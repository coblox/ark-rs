use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use ark_core::boarding_output::list_boarding_outpoints;
use ark_core::boarding_output::BoardingOutpoints;
use ark_core::proof_of_funds;
use ark_core::redeem;
use ark_core::redeem::build_offchain_transactions;
use ark_core::redeem::sign_checkpoint_transaction;
use ark_core::redeem::sign_offchain_virtual_transaction;
use ark_core::redeem::OffchainTransactions;
use ark_core::round;
use ark_core::round::create_and_sign_forfeit_txs;
use ark_core::round::generate_nonce_tree;
use ark_core::round::sign_round_psbt;
use ark_core::round::sign_vtxo_tree;
use ark_core::server;
use ark_core::server::BatchTreeEventType;
use ark_core::server::RoundStreamEvent;
use ark_core::server::TxTree;
use ark_core::server::VtxoOutPoint;
use ark_core::vtxo::list_virtual_tx_outpoints;
use ark_core::vtxo::VirtualTxOutpoints;
use ark_core::ArkAddress;
use ark_core::BoardingOutput;
use ark_core::ExplorerUtxo;
use ark_core::Vtxo;
use ark_core::VTXO_INPUT_INDEX;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
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

const RUN_REFUND_SCENARIO: bool = false;

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
    let alice_dlc_input = fund_vtxo(
        &esplora_client,
        &grpc_client,
        &server_info,
        &alice_kp,
        alice_fund_amount,
    )
    .await?;

    let bob_fund_amount = Amount::from_sat(100_000_000);
    let bob_dlc_input = fund_vtxo(
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
    let OffchainTransactions {
        virtual_tx: mut dlc_virtual_tx,
        checkpoint_txs: dlc_checkpoint_txs,
    } = build_offchain_transactions(
        &[(
            &dlc_vtxo.to_ark_address(),
            alice_fund_amount + bob_fund_amount,
        )],
        None,
        &[alice_dlc_input.clone(), bob_dlc_input.clone()],
        server_info.dust,
    )
    .context("building DLC TX")?;

    let dlc_output = dlc_virtual_tx.unsigned_tx.output[0].clone();
    let dlc_outpoint = OutPoint {
        txid: dlc_virtual_tx.unsigned_tx.compute_txid(),
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
    let refund_offchain_txs = build_offchain_transactions(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_refund_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_refund_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
        server_info.dust,
    )
    .context("building refund TX")?;

    // We build CETs spending from the DLC VTXO.
    let alice_heads_payout = Amount::from_sat(70_000_000);
    let bob_heads_payout = dlc_output.value - alice_heads_payout;
    let heads_cet_offchain_txs = build_offchain_transactions(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_heads_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_heads_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
        server_info.dust,
    )
    .context("building heads CET")?;

    let alice_tails_payout = Amount::from_sat(25_000_000);
    let bob_tails_payout = dlc_output.value - alice_tails_payout;
    let tails_cet_offchain_txs = build_offchain_transactions(
        &[
            (&alice_payout_vtxo.to_ark_address(), alice_tails_payout),
            (&bob_payout_vtxo.to_ark_address(), bob_tails_payout),
        ],
        None,
        &[dlc_vtxo_input.clone()],
        server_info.dust,
    )
    .context("building tails CET")?;

    // First, Alice and Bob sign the refund TX.

    let SignedRefundOffchainTransactions {
        virtual_tx: refund_virtual_tx,
        checkpoint_tx: mut signed_refund_checkpoint_tx,
    } = sign_refund_offchain_transactions(
        refund_offchain_txs.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        &dlc_vtxo_input,
    )
    .context("signing refund offchain TXs")?;

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

    let SignedCetOffchainTransactions {
        virtual_cet: heads_virtual_cet,
        virtual_cet_parity: heads_virtual_cet_parity,
        checkpoint_tx: heads_signed_checkpoint_tx,
        checkpoint_tx_parity: heads_checkpoint_tx_parity,
    } = sign_cet_offchain_txs(
        heads_cet_offchain_txs.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        heads_adaptor_pk,
        &dlc_vtxo_input,
    )
    .context("signing heads CET offchain TXs")?;

    let SignedCetOffchainTransactions {
        virtual_cet: tails_virtual_cet,
        virtual_cet_parity: tails_virtual_cet_parity,
        checkpoint_tx: tails_signed_checkpoint_tx,
        checkpoint_tx_parity: tails_checkpoint_tx_parity,
    } = sign_cet_offchain_txs(
        tails_cet_offchain_txs.clone(),
        &alice_kp,
        &bob_kp,
        &musig_key_agg_cache,
        tails_adaptor_pk,
        &dlc_vtxo_input,
    )
    .context("signing tails CET offchain TXs")?;

    // Finally, Alice and Bob sign the DLC funding transaction.

    sign_offchain_virtual_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &alice_kp);

            Ok((sig, alice_xonly_pk))
        },
        &mut dlc_virtual_tx,
        &dlc_checkpoint_txs
            .iter()
            .map(|(_, output, outpoint)| (output.clone(), *outpoint))
            .collect::<Vec<_>>(),
        0, // Alice's DLC-funding virtual TX input.
    )
    .context("failed to sign DLC-funding virtual TX as Alice")?;

    sign_offchain_virtual_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &bob_kp);

            Ok((sig, bob_xonly_pk))
        },
        &mut dlc_virtual_tx,
        &dlc_checkpoint_txs
            .iter()
            .map(|(_, output, outpoint)| (output.clone(), *outpoint))
            .collect::<Vec<_>>(),
        1, // Bob's DLC-funding virtual TX input.
    )
    .context("failed to sign DLC-funding virtual TX as Bob")?;

    let dlc_funding_virtual_txid = dlc_virtual_tx.unsigned_tx.compute_txid();

    // Submit DLC funding transaction.
    let res = grpc_client
        .submit_offchain_transaction_request(
            dlc_virtual_tx,
            dlc_checkpoint_txs
                .into_iter()
                .map(|(psbt, _, _)| psbt)
                .collect(),
        )
        .await
        .context("failed to submit offchain TX request to fund DLC")?;

    let mut alice_signed_checkpoint_psbt = res.signed_checkpoint_txs[0].clone();
    sign_checkpoint_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &alice_kp);

            Ok((sig, alice_xonly_pk))
        },
        &mut alice_signed_checkpoint_psbt,
        &alice_dlc_input,
    )
    .context("failed to sign Alice's DLC-funding checkpoint TX")?;

    let mut bob_signed_checkpoint_psbt = res.signed_checkpoint_txs[1].clone();
    sign_checkpoint_transaction(
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &bob_kp);

            Ok((sig, bob_xonly_pk))
        },
        &mut bob_signed_checkpoint_psbt,
        &bob_dlc_input,
    )
    .context("failed to sign Bob's DLC-funding checkpoint TX")?;

    grpc_client
        .finalize_offchain_transaction(
            dlc_funding_virtual_txid,
            vec![alice_signed_checkpoint_psbt, bob_signed_checkpoint_psbt],
        )
        .await
        .context("failed to finalize DLC-funding offchain transaction")?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    if RUN_REFUND_SCENARIO {
        let refund_virtual_txid = refund_virtual_tx.unsigned_tx.compute_txid();

        let res = grpc_client
            .submit_offchain_transaction_request(
                refund_virtual_tx,
                refund_offchain_txs
                    .checkpoint_txs
                    .into_iter()
                    .map(|(psbt, _, _)| psbt)
                    .collect(),
            )
            .await
            .context("failed to submit offchain TX request to refund DLC")?;

        signed_refund_checkpoint_tx
            .combine(res.signed_checkpoint_txs[0].clone())
            .context("failed to combine signed refund TXs")?;

        grpc_client
            .finalize_offchain_transaction(refund_virtual_txid, vec![signed_refund_checkpoint_tx])
            .await
            .context("failed to finalize DLC-refund offchain transaction")?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        {
            let spendable_vtxos = spendable_vtxos(&grpc_client, &[alice_payout_vtxo]).await?;
            let virtual_tx_outpoints = list_virtual_tx_outpoints(
                |address: &bitcoin::Address| -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
                    find_outpoints(tokio::runtime::Handle::current(), &esplora_client, address)
                },
                spendable_vtxos,
            )?;

            assert_eq!(virtual_tx_outpoints.spendable_balance(), alice_fund_amount);
        }
        {
            let spendable_vtxos = spendable_vtxos(&grpc_client, &[bob_payout_vtxo]).await?;
            let virtual_tx_outpoints = list_virtual_tx_outpoints(
                |address: &bitcoin::Address| -> Result<Vec<ExplorerUtxo>, ark_core::Error> {
                    find_outpoints(tokio::runtime::Handle::current(), &esplora_client, address)
                },
                spendable_vtxos,
            )?;

            assert_eq!(virtual_tx_outpoints.spendable_balance(), bob_fund_amount);
        }

        return Ok(());
    }

    // Wait until the oracle attests to the outcome of the relevant event.

    let is_heads = flip_coin();
    let attestation = oracle.attest(event, is_heads)?;

    // Only one of the CETs is "unlocked".
    let (
        mut unlocked_virtual_cet_psbt,
        unlocked_virtual_cet_parity,
        mut unlocked_signed_checkpoint_psbt,
        unlocked_checkpoint_psbt,
        unlocked_checkpoint_parity,
    ) = if is_heads {
        (
            heads_virtual_cet,
            heads_virtual_cet_parity,
            heads_signed_checkpoint_tx,
            heads_cet_offchain_txs.checkpoint_txs[0].0.clone(),
            heads_checkpoint_tx_parity,
        )
    } else {
        (
            tails_virtual_cet,
            tails_virtual_cet_parity,
            tails_signed_checkpoint_tx,
            tails_cet_offchain_txs.checkpoint_txs[0].0.clone(),
            tails_checkpoint_tx_parity,
        )
    };

    let mut input = unlocked_virtual_cet_psbt.inputs[0]
        .tap_script_sigs
        .first_entry()
        .context("one sig")?;
    let input_sig = input.get_mut();

    let adaptor_sig =
        zkp::schnorr::Signature::from_slice(input_sig.signature.as_ref()).expect("valid sig");

    let adaptor = zkp::Tweak::from_slice(attestation.as_ref()).expect("valid tweak");

    // Complete the adaptor signature, producing a valid signature for this CET.

    let sig = zkp::musig::adapt(adaptor_sig, adaptor, unlocked_virtual_cet_parity);
    let sig = schnorr::Signature::from_slice(sig.as_ref()).expect("valid sig");

    input_sig.signature = sig;

    // Publish the CET.

    let unlocked_virtual_cet_txid = unlocked_virtual_cet_psbt.unsigned_tx.compute_txid();

    let res = grpc_client
        .submit_offchain_transaction_request(
            unlocked_virtual_cet_psbt,
            vec![unlocked_checkpoint_psbt],
        )
        .await
        .context("failed to submit offchain TX request for CET")?;

    let mut input = unlocked_signed_checkpoint_psbt.inputs[0]
        .tap_script_sigs
        .first_entry()
        .context("one sig")?;
    let input_sig = input.get_mut();

    let adaptor_sig =
        zkp::schnorr::Signature::from_slice(input_sig.signature.as_ref()).expect("valid sig");

    let adaptor = zkp::Tweak::from_slice(attestation.as_ref()).expect("valid tweak");

    // Complete the adaptor signature, producing a valid signature for this checkpoint transaction.

    let sig = zkp::musig::adapt(adaptor_sig, adaptor, unlocked_checkpoint_parity);
    let sig = schnorr::Signature::from_slice(sig.as_ref()).expect("valid sig");

    input_sig.signature = sig;

    unlocked_signed_checkpoint_psbt
        .combine(res.signed_checkpoint_txs[0].clone())
        .context("failed to combine signed CETs")?;

    grpc_client
        .finalize_offchain_transaction(
            unlocked_virtual_cet_txid,
            vec![unlocked_signed_checkpoint_psbt],
        )
        .await
        .context("failed to finalize CET offchain transaction")?;

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
                Amount::from_sat(70_000_000)
            );
        } else {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(25_000_000)
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
                Amount::from_sat(130_000_000)
            );
        } else {
            assert_eq!(
                virtual_tx_outpoints.spendable_balance(),
                Amount::from_sat(175_000_000)
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
        .spendable()
        .iter()
        .find(|v| v.commitment_txid == round_txid)
        .ok_or(anyhow!("could not find input in round"))?;
    let vtxo_input = redeem::VtxoInput::new(
        vtxo,
        virtual_tx_outpoint.amount,
        virtual_tx_outpoint.outpoint,
    );

    Ok(vtxo_input)
}

/// The result of signing DLC refund transactions between Alice and Bob.
///
/// These do not include the server signature yet.
struct SignedRefundOffchainTransactions {
    virtual_tx: Psbt,
    checkpoint_tx: Psbt,
}

/// Sign the [`OffchainTransactions`] for the refund path.
///
/// This function represents a session between the two signing parties. It would normally be
/// performed over the internet.
fn sign_refund_offchain_transactions(
    offchain_txs: OffchainTransactions,
    alice_kp: &Keypair,
    bob_kp: &Keypair,
    musig_key_agg_cache: &MusigKeyAggCache,
    dlc_vtxo_input: &redeem::VtxoInput,
) -> Result<SignedRefundOffchainTransactions> {
    let zkp = zkp::Secp256k1::new();
    let mut rng = thread_rng();

    let OffchainTransactions {
        virtual_tx: mut refund_virtual_tx,
        checkpoint_txs: refund_checkpoint_txs,
    } = offchain_txs;

    // For a transaction spending a DLC output, there can only be one input.
    let (mut refund_checkpoint_psbt, refund_checkpoint_output, refund_checkpoint_outpoint) =
        refund_checkpoint_txs[0].clone();

    // Signing the virtual TX.
    {
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

        let sign_fn =
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

        sign_offchain_virtual_transaction(
            sign_fn,
            &mut refund_virtual_tx,
            &[(refund_checkpoint_output, refund_checkpoint_outpoint)],
            0,
        )
        .context("signing refund virtual TX")?;
    }

    // Signing the checkpoint TX. Some unnecessary duplication here.
    {
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

        let sign_fn =
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

        // Normally we would sign this one after communicating with the server, but since this
        // output is owned by two parties we need to do this ahead of time.
        sign_checkpoint_transaction(sign_fn, &mut refund_checkpoint_psbt, dlc_vtxo_input)
            .context("signing refund checkpoint TX")?;
    }

    Ok(SignedRefundOffchainTransactions {
        virtual_tx: refund_virtual_tx,
        checkpoint_tx: refund_checkpoint_psbt,
    })
}

/// The result of signing CET transactions between Alice and Bob.
///
/// These do not include the server signature yet.
///
/// TODO: Do we really need to have adaptor signatures for both the virtual TX and the checkpoint
/// TX. It seems like only the checkpoint TX needs an adaptor signature, but it feels weird.
struct SignedCetOffchainTransactions {
    virtual_cet: Psbt,
    virtual_cet_parity: zkp::Parity,
    checkpoint_tx: Psbt,
    checkpoint_tx_parity: zkp::Parity,
}

/// Sign the [`OffchainTransactions`] for the CET path.
///
/// This function represents a session between the two signing parties. It would normally be
/// performed over the internet.
fn sign_cet_offchain_txs(
    offchain_txs: OffchainTransactions,
    alice_kp: &Keypair,
    bob_kp: &Keypair,
    musig_key_agg_cache: &MusigKeyAggCache,
    adaptor_pk: zkp::PublicKey,
    dlc_vtxo_input: &redeem::VtxoInput,
) -> Result<SignedCetOffchainTransactions> {
    let zkp = zkp::Secp256k1::new();
    let mut rng = thread_rng();

    let OffchainTransactions {
        virtual_tx: mut virtual_cet,
        checkpoint_txs: cet_checkpoint_txs,
    } = offchain_txs;

    // For a transaction spending a DLC output, there can only be one input.
    let (mut cet_checkpoint_psbt, cet_checkpoint_output, cet_checkpoint_outpoint) =
        cet_checkpoint_txs[0].clone();

    // Signing the virtual CET.
    let virtual_cet_parity = {
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
        let sign_fn =
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

        sign_offchain_virtual_transaction(
            sign_fn,
            &mut virtual_cet,
            &[(cet_checkpoint_output, cet_checkpoint_outpoint)],
            0,
        )
        .context("signing virtual CET")?;

        musig_nonce_parity.context("to be set")?
    };

    // Signing the checkpoint TX. Some unnecessary duplication here.
    let checkpoint_tx_parity = {
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
        let sign_fn =
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

        // Normally we would sign this one after communicating with the server, but since this
        // output is owned by two parties we need to do this ahead of time.
        sign_checkpoint_transaction(sign_fn, &mut cet_checkpoint_psbt, dlc_vtxo_input)
            .context("signing CET checkpoint TX")?;

        musig_nonce_parity.context("to be set")?
    };

    Ok(SignedCetOffchainTransactions {
        virtual_cet,
        virtual_cet_parity,
        checkpoint_tx: cet_checkpoint_psbt,
        checkpoint_tx_parity,
    })
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

    let intent_id = grpc_client
        .register_intent(&intent_message, &bip322_proof)
        .await?;

    tracing::info!(intent_id, "Registered intent");

    let mut event_stream = grpc_client.get_event_stream().await?;
    let mut vtxo_tree = TxTree::new();

    let batch_started_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::BatchStarted(e))) => e,
        other => bail!("Did not get round signing event: {other:?}"),
    };

    let hash = sha256::Hash::hash(intent_id.as_bytes());
    let hash = hash.as_byte_array().to_vec().to_lower_hex_string();

    if batch_started_event
        .intent_id_hashes
        .iter()
        .any(|h| h == &hash)
    {
        grpc_client.confirm_registration(intent_id.clone()).await?;
    } else {
        bail!(
            "Did not find intent ID {} in round: {}",
            intent_id,
            batch_started_event.id
        )
    }

    let round_signing_event;
    loop {
        match event_stream.next().await {
            Some(Ok(RoundStreamEvent::TreeTx(e))) => {
                if let Some(tree_node) = e.tree_tx {
                    let level = tree_node.level as usize;
                    let level_index = tree_node.level_index as usize;
                    match e.batch_tree_event_type {
                        BatchTreeEventType::Vtxo => {
                            vtxo_tree.insert(tree_node, level, level_index);
                        }
                        BatchTreeEventType::Connector => {
                            bail!("Unexpected connector batch tree event");
                        }
                    }
                }
            }
            Some(Ok(RoundStreamEvent::TreeSigningStarted(e))) => {
                round_signing_event = e;
                break;
            }
            other => bail!("Unexpected event while waiting for round signing: {other:?}"),
        }
    }

    let round_id = round_signing_event.id;
    tracing::info!(round_id, "Round signing started");

    let nonce_tree = generate_nonce_tree(
        &mut rng,
        &vtxo_tree,
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
        Some(Ok(RoundStreamEvent::TreeNoncesAggregated(e))) => e,
        other => bail!("Did not get round signing nonces generated event: {other:?}"),
    };

    tracing::info!(round_id, "Round combined nonces generated");

    let round_id = round_signing_nonces_generated_event.id;

    let agg_pub_nonce_tree = round_signing_nonces_generated_event.tree_nonces;

    let partial_sig_tree = sign_vtxo_tree(
        server_info.vtxo_tree_expiry,
        server_info.pk.x_only_public_key().0,
        &cosigner_kp,
        &vtxo_tree,
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

    let mut connector_tree = TxTree::new();

    let round_finalization_event;
    loop {
        match event_stream.next().await {
            Some(Ok(RoundStreamEvent::TreeTx(e))) => {
                if let Some(tree_node) = e.tree_tx {
                    let level = tree_node.level as usize;
                    let level_index = tree_node.level_index as usize;
                    match e.batch_tree_event_type {
                        BatchTreeEventType::Vtxo => {
                            bail!("Unexpected VTXO batch tree event");
                        }
                        BatchTreeEventType::Connector => {
                            connector_tree.insert(tree_node, level, level_index);
                        }
                    }
                }
            }
            Some(Ok(RoundStreamEvent::TreeSignature(e))) => {
                let level = e.level as usize;
                let level_index = e.level_index as usize;
                match e.batch_tree_event_type {
                    BatchTreeEventType::Vtxo => {
                        let node = vtxo_tree.get_mut(level, level_index)?;

                        node.tx.inputs[VTXO_INPUT_INDEX].tap_key_sig = Some(e.signature);
                    }
                    BatchTreeEventType::Connector => {
                        bail!("received batch tree signature for connectors tree");
                    }
                }
            }
            Some(Ok(RoundStreamEvent::BatchFinalization(e))) => {
                round_finalization_event = e;
                break;
            }
            other => bail!("Unexpected event while waiting for round finalization: {other:?}"),
        }
    }

    let round_id = round_finalization_event.id;

    tracing::info!(round_id, "Round finalization started");

    let keypair = Keypair::from_secret_key(&secp, &sk);

    let vtxo_inputs = virtual_tx_outpoints
        .spendable
        .into_iter()
        .map(|(outpoint, vtxo)| {
            round::VtxoInput::new(
                vtxo,
                outpoint.amount,
                outpoint.outpoint,
                outpoint.is_recoverable(),
            )
        })
        .collect::<Vec<_>>();

    let signed_forfeit_psbts = create_and_sign_forfeit_txs(
        &keypair,
        vtxo_inputs.as_slice(),
        &connector_tree,
        &round_finalization_event.connectors_index,
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
        let mut round_psbt = round_finalization_event.commitment_tx;

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
        Some(Ok(RoundStreamEvent::BatchFinalized(e))) => e,
        other => bail!("Did not get round finalized event: {other:?}"),
    };

    let round_id = round_finalized_event.id;

    tracing::info!(round_id, "Round finalized");

    Ok(Some(round_finalized_event.commitment_txid))
}

async fn spendable_vtxos(
    grpc_client: &ark_grpc::Client,
    vtxos: &[Vtxo],
) -> Result<HashMap<Vtxo, Vec<VtxoOutPoint>>> {
    let mut spendable_vtxos = HashMap::new();
    for vtxo in vtxos.iter() {
        // The VTXOs for the given Ark address that the Ark server tells us about.
        let vtxo_outpoints = grpc_client.list_vtxos(&vtxo.to_ark_address()).await?;

        spendable_vtxos.insert(vtxo.clone(), vtxo_outpoints.spendable().to_vec());
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
