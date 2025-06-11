use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use ark_core::boarding_output::list_boarding_outpoints;
use ark_core::boarding_output::BoardingOutpoints;
use ark_core::proof_of_funds;
use ark_core::redeem;
use ark_core::redeem::build_redeem_transaction;
use ark_core::redeem::sign_redeem_transaction;
use ark_core::round;
use ark_core::round::create_and_sign_forfeit_txs;
use ark_core::round::generate_nonce_tree;
use ark_core::round::sign_round_psbt;
use ark_core::round::sign_vtxo_tree;
use ark_core::server;
use ark_core::server::RoundStreamEvent;
use ark_core::server::VtxoOutPoint;
use ark_core::vtxo::list_virtual_tx_outpoints;
use ark_core::vtxo::VirtualTxOutpoints;
use ark_core::ArkAddress;
use ark_core::BoardingOutput;
use ark_core::ExplorerUtxo;
use ark_core::Vtxo;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;
use bitcoin::opcodes::all::OP_CLTV;
use bitcoin::opcodes::all::OP_DROP;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use esplora_client::FromHex;
use futures::StreamExt;
use rand::thread_rng;
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;
use tokio::task::block_in_place;
use zkp::musig::new_musig_nonce_pair;
use zkp::musig::MusigAggNonce;
use zkp::musig::MusigKeyAggCache;
use zkp::musig::MusigSession;
use zkp::musig::MusigSessionId;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // We instantiate an oracle that attests to coin flips.
    let mut oracle = Oracle::new();

    let secp = Secp256k1::new();
    let zkp = zkp::Secp256k1::new();
    let mut rng = thread_rng();

    let mut grpc_client = ark_grpc::Client::new("http://localhost:7070".to_string());

    grpc_client.connect().await?;
    let server_info = grpc_client.get_info().await?;
    let server_pk = server_info.pk.x_only_public_key().0;

    let esplora_client = EsploraClient::new("http://localhost:30000")?;

    let alice_kp = Keypair::new(&secp, &mut rng);
    let alice_pk = alice_kp.public_key();
    let alice_xonly_pk = alice_pk.x_only_public_key().0;

    let bob_kp = Keypair::new(&secp, &mut rng);
    let bob_pk = bob_kp.public_key();
    let bob_xonly_pk = bob_pk.x_only_public_key().0;

    // Alice and Bob need liquidity to fund the DLC.
    //
    // We need VTXOs as inputs to the DLC, because we must be able to presign several transactions
    // on top of the DLC. That is, we can't build the DLC protocol on top of a boarding output!

    let alice_fund_amount = Amount::from_sat(100_000_000);
    let alice_virtual_tx_input = fund_vtxo(
        &esplora_client,
        &grpc_client,
        &server_info,
        &alice_kp,
        alice_fund_amount,
    )
    .await?;

    let bob_fund_amount = Amount::from_sat(100_000_000);
    let bob_virtual_tx_input = fund_vtxo(
        &esplora_client,
        &grpc_client,
        &server_info,
        &bob_kp,
        bob_fund_amount,
    )
    .await?;

    // Using Musig2, the server is not even aware that this is a shared VTXO.
    let musig_key_agg_cache =
        MusigKeyAggCache::new(&zkp, &[to_zkp_pk(alice_pk), to_zkp_pk(bob_pk)]);
    let shared_pk = musig_key_agg_cache.agg_pk();
    let shared_pk = from_zkp_xonly(shared_pk);

    // A path that lets Alice and Bob reclaim (with the server's help) their funds, some time after
    // the oracle attests to the outcome of a relevant event, but _before_ the round ends. Thus,
    // choosing the timelock correctly is very important.
    //
    // We don't use this path in this example, but including it in the Tapscript demonstrates that
    // the server accepts it.
    let refund_locktime = bitcoin::absolute::LockTime::from_height(1_000)?;
    let dlc_refund_script = ScriptBuf::builder()
        .push_int(refund_locktime.to_consensus_u32() as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&shared_pk)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&server_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let dlc_vtxo = Vtxo::new(
        &secp,
        server_info.pk.x_only_public_key().0,
        shared_pk,
        vec![dlc_refund_script],
        server_info.unilateral_exit_delay,
        server_info.network,
    )?;

    // We build the DLC funding transaction, but we don't "broadcast" it yet. We use it as a
    // reference point to build the rest of the DLC.
    let mut dlc_funding_redeem_psbt = build_redeem_transaction(
        &[(
            &dlc_vtxo.to_ark_address(),
            alice_fund_amount + bob_fund_amount,
        )],
        None,
        &[alice_virtual_tx_input.clone(), bob_virtual_tx_input.clone()],
    )
    .context("building DLC TX")?;

    let dlc_output = dlc_funding_redeem_psbt.unsigned_tx.output[0].clone();
    let dlc_outpoint = OutPoint {
        txid: dlc_funding_redeem_psbt.unsigned_tx.compute_txid(),
        vout: 0,
    };

    // Generate payout addresses for Alice and Bob.

    let alice_payout_vtxo = Vtxo::new_default(
        &secp,
        server_info.pk.x_only_public_key().0,
        alice_xonly_pk,
        server_info.unilateral_exit_delay,
        server_info.network,
    )?;

    let bob_payout_vtxo = Vtxo::new_default(
        &secp,
        server_info.pk.x_only_public_key().0,
        bob_xonly_pk,
        server_info.unilateral_exit_delay,
        server_info.network,
    )?;

    let dlc_vtxo_input = redeem::VtxoInput::new(dlc_vtxo, dlc_output.value, dlc_outpoint);

    // We build a refund transaction spending from the DLC VTXO.
    let alice_refund_payout = alice_fund_amount;
    let bob_refund_payout = bob_fund_amount;
    let refund_redeem_psbt = build_redeem_transaction(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_refund_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_refund_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
    )
    .context("building refund TX")?;

    // We build CETs spending from the DLC VTXO.
    let alice_heads_payout = Amount::from_sat(70_000_000);
    let bob_heads_payout = dlc_output.value - alice_heads_payout;
    let heads_cet_redeem_psbt = build_redeem_transaction(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_heads_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_heads_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
    )
    .context("building heads CET")?;

    let alice_tails_payout = Amount::from_sat(25_000_000);
    let bob_tails_payout = dlc_output.value - alice_tails_payout;
    let tails_cet_redeem_psbt = build_redeem_transaction(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_tails_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_tails_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
    )
    .context("building tails CET")?;

    // First, Alice and Bob sign the refund TX.

    let refund_redeem_psbt = sign_refund_redeem_tx(
        refund_redeem_psbt.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        &dlc_vtxo_input,
    )
    .context("signing heads CET")?;

    // Then, Alice and Bob sign the coin flip CETs.

    // The oracle announces the next coin flip.
    let (event, nonce_pk) = oracle.announce();

    // Alice and Bob can construct adaptor PKs based on the oracle's announcement and the
    // oracle's public key.
    let (heads_adaptor_pk, tails_adaptor_pk) = {
        let oracle_pk = oracle.public_key();

        let heads_adaptor_pk = nonce_pk.mul_tweak(&zkp, &heads())?.combine(&oracle_pk)?;
        let tails_adaptor_pk = nonce_pk.mul_tweak(&zkp, &tails())?.combine(&oracle_pk)?;

        (heads_adaptor_pk, tails_adaptor_pk)
    };

    // Both parties end up with a copy of every CET (one per outcome). The transactions cannot yet
    // be published because the adaptor signatures need to be completed with the oracle's adaptor.

    let (heads_cet_redeem_psbt, heads_musig_nonce_parity) = sign_cet_redeem_tx(
        heads_cet_redeem_psbt.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        heads_adaptor_pk,
        &dlc_vtxo_input,
    )
    .context("signing heads CET")?;

    let (tails_cet_redeem_psbt, tails_musig_nonce_parity) = sign_cet_redeem_tx(
        tails_cet_redeem_psbt.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        tails_adaptor_pk,
        &dlc_vtxo_input,
    )
    .context("signing tails CET")?;

    // Finally, Alice and Bob sign the DLC funding transaction.

    sign_redeem_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &alice_kp);

            Ok((sig, alice_xonly_pk))
        },
        &mut dlc_funding_redeem_psbt,
        &[alice_virtual_tx_input.clone(), bob_virtual_tx_input.clone()],
        0,
    )
    .context("Alice signing funding TX")?;

    sign_redeem_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &bob_kp);

            Ok((sig, bob_xonly_pk))
        },
        &mut dlc_funding_redeem_psbt,
        &[alice_virtual_tx_input, bob_virtual_tx_input],
        1,
    )
    .context("Bob signing funding TX")?;

    // Submit DLC funding transaction.
    grpc_client
        .submit_redeem_transaction(dlc_funding_redeem_psbt)
        .await
        .context("submitting funding TX")?;

    if true {
        grpc_client
            .submit_redeem_transaction(refund_redeem_psbt)
            .await
            .context("submitting refund TX")?;

        return Ok(());
    }

    // Wait until the oracle attests to the outcome of the relevant event.

    let is_heads = flip_coin();
    let attestation = oracle.attest(event, is_heads)?;

    // Only one of the CETs is "unlocked".
    let (mut unlocked_cet_redeem_psbt, musig_nonce_parity) = if is_heads {
        (heads_cet_redeem_psbt, heads_musig_nonce_parity)
    } else {
        (tails_cet_redeem_psbt, tails_musig_nonce_parity)
    };

    let mut input = unlocked_cet_redeem_psbt.inputs[0]
        .tap_script_sigs
        .first_entry()
        .context("one sig")?;
    let input_sig = input.get_mut();

    let adaptor_sig =
        zkp::schnorr::Signature::from_slice(input_sig.signature.as_ref()).expect("valid sig");

    let adaptor = zkp::Tweak::from_slice(attestation.as_ref()).expect("valid tweak");

    // Complete the adaptor signature, producing a valid signature for this CET.

    let sig = zkp::musig::adapt(adaptor_sig, adaptor, musig_nonce_parity);
    let sig = schnorr::Signature::from_slice(sig.as_ref()).expect("valid sig");

    input_sig.signature = sig;

    // Publish the CET.
    grpc_client
        .submit_redeem_transaction(unlocked_cet_redeem_psbt)
        .await
        .context("submitting CET")?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify that Alice and Bob receive the expected payouts.

    {
        let spendable_vtxos = spendable_vtxos(&grpc_client, &[alice_payout_vtxo]).await?;
        let virtual_tx_outpoints = list_virtual_tx_outpoints(
            |address: &bitcoin::Address| -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
                find_outpoints(tokio::runtime::Handle::current(), &esplora_client, address)
            },
            spendable_vtxos,
        )?;

        if is_heads {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(69_999_897)
            );
        } else {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(24_999_897)
            );
        }
    };

    {
        let spendable_vtxos = spendable_vtxos(&grpc_client, &[bob_payout_vtxo]).await?;
        let virtual_tx_outpoints = list_virtual_tx_outpoints(
            |address: &bitcoin::Address| -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
                find_outpoints(tokio::runtime::Handle::current(), &esplora_client, address)
            },
            spendable_vtxos,
        )?;

        if is_heads {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(129_999_617)
            );
        } else {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(174_999_617)
            );
        }
    };

    Ok(())
}

fn find_outpoints(
    runtime: tokio::runtime::Handle,
    esplora_client: &EsploraClient,
    address: &bitcoin::Address,
) -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
    block_in_place(|| {
        runtime.block_on(async {
            let outpoints = esplora_client
                .find_outpoints(address)
                .await
                .map_err(ark_core::Error::ad_hoc)?;

            Ok(outpoints)
        })
    })
}

async fn fund_vtxo(
    esplora_client: &EsploraClient,
    grpc_client: &ark_grpc::Client,
    server_info: &server::Info,
    kp: &Keypair,
    amount: Amount,
) -> Result<redeem::VtxoInput> {
    let secp = Secp256k1::new();

    let pk = kp.public_key().x_only_public_key().0;

    let boarding_output = BoardingOutput::new(
        &secp,
        server_info.pk.x_only_public_key().0,
        pk,
        server_info.boarding_exit_delay,
        server_info.network,
    )?;

    faucet_fund(boarding_output.address(), amount).await?;

    let boarding_outpoints = list_boarding_outpoints(
        |address: &bitcoin::Address| -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
            find_outpoints(tokio::runtime::Handle::current(), esplora_client, address)
        },
        &[boarding_output],
    )?;
    assert_eq!(boarding_outpoints.spendable_balance(), amount);

    let vtxo = Vtxo::new_default(
        &secp,
        server_info.pk.x_only_public_key().0,
        pk,
        server_info.unilateral_exit_delay,
        server_info.network,
    )?;

    let round_txid = settle(
        grpc_client,
        server_info,
        kp.secret_key(),
        VirtualTxOutpoints::default(),
        boarding_outpoints,
        vtxo.to_ark_address(),
    )
    .await?
    .ok_or(anyhow!("did not join round"))?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let vtxo_list = grpc_client.list_vtxos(&vtxo.to_ark_address()).await?;
    let virtual_tx_outpoint = vtxo_list
        .spendable
        .iter()
        .find(|v| v.round_txid == round_txid)
        .ok_or(anyhow!("could not find input in round"))?;
    let vtxo_input = redeem::VtxoInput::new(
        vtxo,
        virtual_tx_outpoint.amount,
        virtual_tx_outpoint.outpoint,
    );

    Ok(vtxo_input)
}

/// Sign a refund redeem transaction.
///
/// This function represents a session between the two signing parties. It would normally be
/// performed over the internet.
fn sign_refund_redeem_tx(
    mut refund_redeem_psbt: Psbt,
    alice_kp: &Keypair,
    bob_kp: &Keypair,
    musig_key_agg_cache: &MusigKeyAggCache,
    dlc_vtxo_input: &redeem::VtxoInput,
) -> Result<Psbt> {
    let zkp = zkp::Secp256k1::new();
    let mut rng = thread_rng();

    let shared_pk = from_zkp_xonly(musig_key_agg_cache.agg_pk());

    let alice_pk = alice_kp.public_key();

    let (alice_musig_nonce, alice_musig_pub_nonce) = {
        let session_id = MusigSessionId::new(&mut rng);
        let extra_rand = rng.gen();
        new_musig_nonce_pair(
            &zkp,
            session_id,
            None,
            None,
            to_zkp_pk(alice_pk),
            None,
            Some(extra_rand),
        )?
    };

    let bob_pk = bob_kp.public_key();

    let (bob_musig_nonce, bob_musig_pub_nonce) = {
        let session_id = MusigSessionId::new(&mut rng);
        let extra_rand = rng.gen();
        new_musig_nonce_pair(
            &zkp,
            session_id,
            None,
            None,
            to_zkp_pk(bob_pk),
            None,
            Some(extra_rand),
        )?
    };

    let sign_refund_fn =
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let musig_agg_nonce =
                MusigAggNonce::new(&zkp, &[alice_musig_pub_nonce, bob_musig_pub_nonce]);
            let msg =
                zkp::Message::from_digest_slice(msg.as_ref()).map_err(ark_core::Error::ad_hoc)?;

            let musig_session = MusigSession::new(&zkp, musig_key_agg_cache, musig_agg_nonce, msg);

            let alice_kp = zkp::Keypair::from_seckey_slice(&zkp, &alice_kp.secret_bytes())
                .expect("valid keypair");

            let alice_sig = musig_session
                .partial_sign(&zkp, alice_musig_nonce, &alice_kp, musig_key_agg_cache)
                .map_err(ark_core::Error::ad_hoc)?;

            let bob_kp = zkp::Keypair::from_seckey_slice(&zkp, &bob_kp.secret_bytes())
                .expect("valid keypair");

            let bob_sig = musig_session
                .partial_sign(&zkp, bob_musig_nonce, &bob_kp, musig_key_agg_cache)
                .map_err(ark_core::Error::ad_hoc)?;

            let sig = musig_session.partial_sig_agg(&[alice_sig, bob_sig]);
            let sig =
                schnorr::Signature::from_slice(sig.as_ref()).map_err(ark_core::Error::ad_hoc)?;

            Ok((sig, shared_pk))
        };

    sign_redeem_transaction(
        sign_refund_fn,
        &mut refund_redeem_psbt,
        &[dlc_vtxo_input.clone()],
        0,
    )
    .context("signing refund TX")?;

    Ok(refund_redeem_psbt)
}

/// Sign a CET redeem transaction.
///
/// This function represents a session between the two signing parties. It would normally be
/// performed over the internet.
fn sign_cet_redeem_tx(
    mut cet_redeem_psbt: Psbt,
    alice_kp: &Keypair,
    bob_kp: &Keypair,
    musig_key_agg_cache: &MusigKeyAggCache,
    adaptor_pk: zkp::PublicKey,
    dlc_vtxo_input: &redeem::VtxoInput,
) -> Result<(Psbt, zkp::Parity)> {
    let zkp = zkp::Secp256k1::new();
    let mut rng = thread_rng();

    let shared_pk = from_zkp_xonly(musig_key_agg_cache.agg_pk());

    let alice_pk = alice_kp.public_key();

    let (alice_musig_nonce, alice_musig_pub_nonce) = {
        let session_id = MusigSessionId::new(&mut rng);
        let extra_rand = rng.gen();
        new_musig_nonce_pair(
            &zkp,
            session_id,
            None,
            None,
            to_zkp_pk(alice_pk),
            None,
            Some(extra_rand),
        )?
    };

    let bob_pk = bob_kp.public_key();

    let (bob_musig_nonce, bob_musig_pub_nonce) = {
        let session_id = MusigSessionId::new(&mut rng);
        let extra_rand = rng.gen();
        new_musig_nonce_pair(
            &zkp,
            session_id,
            None,
            None,
            to_zkp_pk(bob_pk),
            None,
            Some(extra_rand),
        )?
    };

    let mut musig_nonce_parity = None;
    let sign_cet_fn =
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let musig_agg_nonce =
                MusigAggNonce::new(&zkp, &[alice_musig_pub_nonce, bob_musig_pub_nonce]);
            let msg =
                zkp::Message::from_digest_slice(msg.as_ref()).map_err(ark_core::Error::ad_hoc)?;

            let musig_session = MusigSession::with_adaptor(
                &zkp,
                musig_key_agg_cache,
                musig_agg_nonce,
                msg,
                adaptor_pk,
            );

            musig_nonce_parity = Some(musig_session.nonce_parity());

            let alice_kp = zkp::Keypair::from_seckey_slice(&zkp, &alice_kp.secret_bytes())
                .expect("valid keypair");

            let alice_sig = musig_session
                .partial_sign(&zkp, alice_musig_nonce, &alice_kp, musig_key_agg_cache)
                .map_err(ark_core::Error::ad_hoc)?;

            let bob_kp = zkp::Keypair::from_seckey_slice(&zkp, &bob_kp.secret_bytes())
                .expect("valid keypair");

            let bob_sig = musig_session
                .partial_sign(&zkp, bob_musig_nonce, &bob_kp, musig_key_agg_cache)
                .map_err(ark_core::Error::ad_hoc)?;

            let sig = musig_session.partial_sig_agg(&[alice_sig, bob_sig]);
            let sig =
                schnorr::Signature::from_slice(sig.as_ref()).map_err(ark_core::Error::ad_hoc)?;

            Ok((sig, shared_pk))
        };

    sign_redeem_transaction(
        sign_cet_fn,
        &mut cet_redeem_psbt,
        &[dlc_vtxo_input.clone()],
        0,
    )
    .context("signing CET")?;

    let musig_nonce_parity = musig_nonce_parity.context("to be set")?;

    Ok((cet_redeem_psbt, musig_nonce_parity))
}

/// Simulation of a DLC oracle.
///
/// This oracle attests to the outcome of flipping a coin: either heads (1) or tails (2).
struct Oracle {
    kp: zkp::Keypair,
    nonces: Vec<zkp::SecretKey>,
}

impl Oracle {
    fn new() -> Self {
        let zkp = zkp::Secp256k1::new();
        let mut rng = thread_rng();

        let kp = zkp::Keypair::new(&zkp, &mut rng);

        Self {
            kp,
            nonces: Vec::new(),
        }
    }

    /// The oracle's public key.
    fn public_key(&self) -> zkp::PublicKey {
        self.kp.public_key()
    }

    /// Announce the public nonce that will be used to attest to the outcome of a future event.
    fn announce(&mut self) -> (usize, zkp::PublicKey) {
        let zkp = zkp::Secp256k1::new();
        let mut rng = thread_rng();

        let sk = zkp::SecretKey::new(&mut rng);
        let pk = zkp::PublicKey::from_secret_key(&zkp, &sk);

        self.nonces.push(sk);

        (self.nonces.len() - 1, pk)
    }

    /// The oracle attests to the outcome of a coin flip.
    fn attest(&self, event: usize, is_heads: bool) -> Result<zkp::SecretKey> {
        let nonce = self.nonces.get(event).context("missing event")?;

        let outcome = if is_heads { heads() } else { tails() };

        let sk = zkp::Scalar::from_be_bytes(self.kp.secret_key().secret_bytes())?;

        let attestation = nonce.mul_tweak(&outcome)?.add_tweak(&sk)?;

        Ok(attestation)
    }
}

const fn heads() -> zkp::Scalar {
    zkp::Scalar::ONE
}

fn tails() -> zkp::Scalar {
    zkp::Scalar::from_be_bytes([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ])
    .expect("valid scalar")
}

/// Flip a fair coin.
///
/// # Returns
///
/// - Heads => `true`.
/// - Tails => `false`.
fn flip_coin() -> bool {
    let mut rng = thread_rng();

    let is_heads = rng.gen_bool(0.5);

    if is_heads {
        tracing::info!("Flipped a coin: got heads!");
    } else {
        tracing::info!("Flipped a coin: got tails!");
    }

    is_heads
}

async fn settle(
    grpc_client: &ark_grpc::Client,
    server_info: &server::Info,
    sk: SecretKey,
    virtual_tx_outpoints: VirtualTxOutpoints,
    boarding_outpoints: BoardingOutpoints,
    to_address: ArkAddress,
) -> Result<Option<Txid>> {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    if virtual_tx_outpoints.spendable.is_empty() && boarding_outpoints.spendable.is_empty() {
        return Ok(None);
    }

    let cosigner_kp = Keypair::new(&secp, &mut rng);

    let round_inputs = {
        let boarding_inputs = boarding_outpoints.spendable.clone().into_iter().map(
            |(outpoint, amount, boarding_output)| {
                proof_of_funds::Input::new(
                    outpoint,
                    boarding_output.exit_delay(),
                    TxOut {
                        value: amount,
                        script_pubkey: boarding_output.script_pubkey(),
                    },
                    boarding_output.tapscripts(),
                    boarding_output.owner_pk(),
                    boarding_output.exit_spend_info(),
                    true,
                )
            },
        );

        let vtxo_inputs = virtual_tx_outpoints.spendable.clone().into_iter().map(
            |(virtual_tx_outpoint, vtxo)| {
                proof_of_funds::Input::new(
                    virtual_tx_outpoint.outpoint,
                    vtxo.exit_delay(),
                    TxOut {
                        value: virtual_tx_outpoint.amount,
                        script_pubkey: vtxo.script_pubkey(),
                    },
                    vtxo.tapscripts(),
                    vtxo.owner_pk(),
                    vtxo.exit_spend_info(),
                    false,
                )
            },
        );

        boarding_inputs.chain(vtxo_inputs).collect::<Vec<_>>()
    };
    let n_round_inputs = round_inputs.len();

    let spendable_amount =
        boarding_outpoints.spendable_balance() + virtual_tx_outpoints.spendable_balance();
    let round_outputs = vec![proof_of_funds::Output::Offchain(TxOut {
        value: spendable_amount,
        script_pubkey: to_address.to_p2tr_script_pubkey(),
    })];

    let own_cosigner_kps = [cosigner_kp];
    let own_cosigner_pks = own_cosigner_kps
        .iter()
        .map(|k| k.public_key())
        .collect::<Vec<_>>();

    let signing_kp = Keypair::from_secret_key(&secp, &sk);
    let sign_for_onchain_pk_fn = |_: &XOnlyPublicKey,
                                  msg: &secp256k1::Message|
     -> Result<schnorr::Signature, ark_core::Error> {
        Ok(secp.sign_schnorr_no_aux_rand(msg, &signing_kp))
    };

    let signing_kp = Keypair::from_secret_key(&secp, &sk);
    let (bip322_proof, intent_message) = proof_of_funds::make_bip322_signature(
        &signing_kp,
        sign_for_onchain_pk_fn,
        round_inputs,
        round_outputs,
        own_cosigner_pks.clone(),
    )?;

    let request_id = grpc_client
        .register_intent(&intent_message, &bip322_proof)
        .await?;

    tracing::info!(request_id, "Registered intent");

    grpc_client.ping(request_id).await?;

    let mut event_stream = grpc_client.get_event_stream().await?;

    let round_signing_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundSigning(e))) => e,
        other => bail!("Did not get round signing event: {other:?}"),
    };

    let round_id = round_signing_event.id;

    tracing::info!(round_id, "Round signing started");

    let unsigned_vtxo_tree = round_signing_event
        .unsigned_vtxo_tree
        .expect("to have an unsigned VTXO tree");

    let nonce_tree = generate_nonce_tree(
        &mut rng,
        &unsigned_vtxo_tree,
        cosigner_kp.public_key(),
        &round_signing_event.unsigned_round_tx,
    )?;

    grpc_client
        .submit_tree_nonces(
            &round_id,
            cosigner_kp.public_key(),
            nonce_tree.to_pub_nonce_tree().into_inner(),
        )
        .await?;

    let round_signing_nonces_generated_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundSigningNoncesGenerated(e))) => e,
        other => bail!("Did not get round signing nonces generated event: {other:?}"),
    };

    let round_id = round_signing_nonces_generated_event.id;

    let agg_pub_nonce_tree = round_signing_nonces_generated_event.tree_nonces;

    tracing::info!(round_id, "Round combined nonces generated");

    let partial_sig_tree = sign_vtxo_tree(
        server_info.vtxo_tree_expiry,
        server_info.pk.x_only_public_key().0,
        &cosigner_kp,
        &unsigned_vtxo_tree,
        &round_signing_event.unsigned_round_tx,
        nonce_tree,
        &agg_pub_nonce_tree.into(),
    )?;

    grpc_client
        .submit_tree_signatures(
            &round_id,
            cosigner_kp.public_key(),
            partial_sig_tree.into_inner(),
        )
        .await?;

    let round_finalization_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundFinalization(e))) => e,
        other => bail!("Did not get round finalization event: {other:?}"),
    };

    let round_id = round_finalization_event.id;

    tracing::info!(round_id, "Round finalization started");

    let keypair = Keypair::from_secret_key(&secp, &sk);

    let vtxo_inputs = virtual_tx_outpoints
        .spendable
        .into_iter()
        .map(|(outpoint, vtxo)| round::VtxoInput::new(vtxo, outpoint.amount, outpoint.outpoint))
        .collect::<Vec<_>>();

    let signed_forfeit_psbts = create_and_sign_forfeit_txs(
        &keypair,
        vtxo_inputs.as_slice(),
        round_finalization_event.connector_tree,
        &round_finalization_event.connectors_index,
        round_finalization_event.min_relay_fee_rate,
        &server_info.forfeit_address,
        server_info.dust,
    )?;

    let onchain_inputs = boarding_outpoints
        .spendable
        .into_iter()
        .map(|(outpoint, amount, boarding_output)| {
            round::OnChainInput::new(boarding_output, amount, outpoint)
        })
        .collect::<Vec<_>>();

    let round_psbt = if n_round_inputs == 0 {
        None
    } else {
        let mut round_psbt = round_finalization_event.round_tx;

        let sign_for_pk_fn = |_: &XOnlyPublicKey,
                              msg: &secp256k1::Message|
         -> Result<schnorr::Signature, ark_core::Error> {
            Ok(secp.sign_schnorr_no_aux_rand(msg, &keypair))
        };

        sign_round_psbt(sign_for_pk_fn, &mut round_psbt, &onchain_inputs)?;

        Some(round_psbt)
    };

    grpc_client
        .submit_signed_forfeit_txs(signed_forfeit_psbts, round_psbt)
        .await?;

    let round_finalized_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundFinalized(e))) => e,
        other => bail!("Did not get round finalized event: {other:?}"),
    };

    let round_id = round_finalized_event.id;

    tracing::info!(round_id, "Round finalized");

    Ok(Some(round_finalized_event.round_txid))
}

async fn spendable_vtxos(
    grpc_client: &ark_grpc::Client,
    vtxos: &[Vtxo],
) -> Result<HashMap<Vtxo, Vec<VtxoOutPoint>>> {
    let mut spendable_vtxos = HashMap::new();
    for vtxo in vtxos.iter() {
        // The VTXOs for the given Ark address that the Ark server tells us about.
        let vtxo_outpoints = grpc_client.list_vtxos(&vtxo.to_ark_address()).await?;

        spendable_vtxos.insert(vtxo.clone(), vtxo_outpoints.spendable);
    }

    Ok(spendable_vtxos)
}

pub struct EsploraClient {
    esplora_client: esplora_client::AsyncClient,
}

#[derive(Clone, Copy, Debug)]
pub struct SpendStatus {
    pub spend_txid: Option<Txid>,
}

impl EsploraClient {
    fn new(url: &str) -> Result<Self> {
        let builder = esplora_client::Builder::new(url);
        let esplora_client = builder.build_async()?;

        Ok(Self { esplora_client })
    }

    async fn find_outpoints(&self, address: &bitcoin::Address) -> Result<Vec<ExplorerUtxo>> {
        let script_pubkey = address.script_pubkey();
        let txs = self
            .esplora_client
            .scripthash_txs(&script_pubkey, None)
            .await?;

        let outputs = txs
            .into_iter()
            .flat_map(|tx| {
                let txid = tx.txid;
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.scriptpubkey == script_pubkey)
                    .map(|(i, v)| ExplorerUtxo {
                        outpoint: OutPoint {
                            txid,
                            vout: i as u32,
                        },
                        amount: Amount::from_sat(v.value),
                        confirmation_blocktime: tx.status.block_time,
                        // Assume the output is unspent until we dig deeper, further down.
                        is_spent: false,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut utxos = Vec::new();
        for output in outputs.iter() {
            let outpoint = output.outpoint;
            let status = self
                .esplora_client
                .get_output_status(&outpoint.txid, outpoint.vout as u64)
                .await?;

            match status {
                Some(esplora_client::OutputStatus { spent: false, .. }) | None => {
                    utxos.push(*output);
                }
                Some(esplora_client::OutputStatus { spent: true, .. }) => {
                    utxos.push(ExplorerUtxo {
                        is_spent: true,
                        ..*output
                    });
                }
            }
        }

        Ok(utxos)
    }

    async fn _get_output_status(&self, txid: &Txid, vout: u32) -> Result<SpendStatus> {
        let status = self
            .esplora_client
            .get_output_status(txid, vout as u64)
            .await?;

        Ok(SpendStatus {
            spend_txid: status.and_then(|s| s.txid),
        })
    }
}

async fn faucet_fund(address: &bitcoin::Address, amount: Amount) -> Result<OutPoint> {
    let res = Command::new("nigiri")
        .args(["faucet", &address.to_string(), &amount.to_btc().to_string()])
        .output()?;

    assert!(res.status.success());

    let text = String::from_utf8(res.stdout)?;
    let re = Regex::new(r"txId: ([0-9a-fA-F]{64})")?;

    let txid = match re.captures(&text) {
        Some(captures) => match captures.get(1) {
            Some(txid) => txid.as_str(),
            _ => panic!("Could not parse TXID"),
        },
        None => {
            panic!("Could not parse TXID");
        }
    };

    let txid: Txid = txid.parse()?;

    let res = Command::new("nigiri")
        .args(["rpc", "getrawtransaction", &txid.to_string()])
        .output()?;

    let tx = String::from_utf8(res.stdout)?;

    let tx = Vec::from_hex(tx.trim())?;
    let tx: Transaction = bitcoin::consensus::deserialize(&tx)?;

    let (vout, _) = tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == address.script_pubkey())
        .context("could not find vout")?;

    // Wait for output to be confirmed.
    tokio::time::sleep(Duration::from_secs(5)).await;

    Ok(OutPoint {
        txid,
        vout: vout as u32,
    })
}

fn to_zkp_pk(pk: secp256k1::PublicKey) -> zkp::PublicKey {
    zkp::PublicKey::from_slice(&pk.serialize()).expect("valid conversion")
}

pub fn from_zkp_xonly(pk: zkp::XOnlyPublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&pk.serialize()).expect("valid conversion")
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            "debug,\
             bdk=info,\
             tower=info,\
             hyper_util=info,\
             hyper=info,\
             reqwest=info,\
             h2=warn",
        )
        .init()
}
