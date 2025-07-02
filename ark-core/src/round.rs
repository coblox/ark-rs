use crate::anchor_output;
use crate::conversions::from_musig_xonly;
use crate::conversions::to_musig_pk;
use crate::internal_node::VtxoTreeInternalNodeScript;
use crate::server::NoncePks;
use crate::server::PartialSigTree;
use crate::server::TxGraph;
use crate::BoardingOutput;
use crate::Error;
use crate::ErrorContext;
use crate::Vtxo;
use crate::VTXO_INPUT_INDEX;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::PublicKey;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot;
use bitcoin::transaction;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use musig::musig;
use rand::CryptoRng;
use rand::Rng;
use std::collections::BTreeMap;
use std::collections::HashMap;

/// The cosigner PKs that sign a VTXO TX input are included in the `unknown` key-value map field of
/// that input in the VTXO PSBT. Since the `unknown` field can be used for any purpose, we know that
/// a value is a cosigner PK if the corresponding key starts with this prefix.
///
/// The byte value corresponds to the string "cosigner".
const COSIGNER_PSBT_KEY_PREFIX: [u8; 8] = [111, 115, 105, 103, 110, 101, 114, 0];

/// A UTXO that is primed to become a VTXO. Alternatively, the owner of this UTXO may decide to
/// spend it into a vanilla UTXO.
///
/// Only UTXOs with a particular script (involving an Ark server) can become VTXOs.
#[derive(Debug, Clone)]
pub struct OnChainInput {
    /// The information needed to spend the UTXO.
    boarding_output: BoardingOutput,
    /// The amount of coins locked in the UTXO.
    amount: Amount,
    /// The location of this UTXO in the blockchain.
    outpoint: OutPoint,
}

impl OnChainInput {
    pub fn new(boarding_output: BoardingOutput, amount: Amount, outpoint: OutPoint) -> Self {
        Self {
            boarding_output,
            amount,
            outpoint,
        }
    }

    pub fn boarding_output(&self) -> &BoardingOutput {
        &self.boarding_output
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }
}

/// Either a confirmed VTXO that needs to be refreshed, or an unconfirmed VTXO that needs
/// confirmation.
///
/// Alternatively, the owner of this VTXO may decide to spend it into a vanilla UTXO.
#[derive(Debug, Clone)]
pub struct VtxoInput {
    /// The information needed to spend the VTXO, besides the amount.
    vtxo: Vtxo,
    /// The amount of coins locked in the VTXO.
    amount: Amount,
    /// Where the VTXO would end up on the blockchain if it were to become a UTXO.
    outpoint: OutPoint,
    is_recoverable: bool,
}

impl VtxoInput {
    pub fn new(vtxo: Vtxo, amount: Amount, outpoint: OutPoint, is_recoverable: bool) -> Self {
        Self {
            vtxo,
            amount,
            outpoint,
            is_recoverable,
        }
    }

    pub fn vtxo(&self) -> &Vtxo {
        &self.vtxo
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }
}

/// A nonce key pair per shared internal (non-leaf) node in the VTXO tree.
///
/// The [`MusigSecNonce`] element of the tuple is an [`Option`] because it cannot be cloned or
/// copied. We use the [`Option`] to move it into the [`NonceTree`] during nonce generation, and out
/// of the [`NonceTree`] when signing the VTXO tree.
#[allow(clippy::type_complexity)]
pub struct NonceKps(HashMap<Txid, (Option<musig::SecretNonce>, musig::PublicNonce)>);

impl NonceKps {
    /// Take ownership of the [`MusigSecNonce`] for the transaction identified by `txid`.
    ///
    /// The caller must take ownership because the [`MusigSecNonce`] ensures that it can only be
    /// used once, to avoid nonce reuse.
    pub fn take_sk(&mut self, txid: &Txid) -> Option<musig::SecretNonce> {
        self.0.get_mut(txid).and_then(|(sec, _)| sec.take())
    }

    /// Convert into [`NoncePks`].
    pub fn to_nonce_pks(&self) -> NoncePks {
        let nonce_pks = self
            .0
            .iter()
            .map(|(txid, (_, pub_nonce))| (*txid, *pub_nonce))
            .collect::<HashMap<_, _>>();

        NoncePks::new(nonce_pks)
    }
}

/// Generate a nonce pair for each internal (non-leaf) node in the VTXO tree.
pub fn generate_nonce_tree<R>(
    rng: &mut R,
    unsigned_vtxo_graph: &TxGraph,
    own_cosigner_pk: PublicKey,
    round_tx: &Psbt,
) -> Result<NonceKps, Error>
where
    R: Rng + CryptoRng,
{
    let secp_musig = ::musig::Secp256k1::new();

    let tx_map = unsigned_vtxo_graph.as_map();

    let nonce_tree = tx_map
        .iter()
        .map(|(txid, node_tx)| {
            let cosigner_pks = extract_cosigner_pks_from_vtxo_psbt(node_tx)?;

            if !cosigner_pks.contains(&own_cosigner_pk) {
                return Err(Error::crypto(format!(
                    "cosigner PKs does not contain {own_cosigner_pk} for TX {txid}"
                )));
            }

            // TODO: We would like to use our own RNG here, but this library is using a
            // different version of `rand`. I think it's not worth the hassle at this stage,
            // particularly because this duplicated dependency will go away anyway.
            let session_id = musig::SessionSecretRand::new();
            let extra_rand = rng.gen();

            let msg = virtual_tx_sighash(node_tx, &tx_map, round_tx)?;

            let key_agg_cache = {
                let cosigner_pks = cosigner_pks
                    .iter()
                    .map(|pk| to_musig_pk(*pk))
                    .collect::<Vec<_>>();
                musig::KeyAggCache::new(&secp_musig, &cosigner_pks.iter().collect::<Vec<_>>())
            };

            let (nonce, pub_nonce) = key_agg_cache.nonce_gen(
                &secp_musig,
                session_id,
                to_musig_pk(own_cosigner_pk),
                msg,
                extra_rand,
            );

            Ok((*txid, (Some(nonce), pub_nonce)))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    Ok(NonceKps(nonce_tree))
}

fn virtual_tx_sighash(
    // The virtual transaction to be signed.
    node_tx: &Psbt,
    // The entire virtual TX set for this batch, so that the parent output can be found, if needed.
    tx_map: &HashMap<Txid, &Psbt>,
    // The round transaction, in case it is the parent VTXO.
    round_tx: &Psbt,
) -> Result<::musig::Message, Error> {
    let tx = &node_tx.unsigned_tx;

    // We expect a single input to a VTXO.
    let previous_output = tx.input[VTXO_INPUT_INDEX].previous_output;

    let parent_tx = tx_map
        .get(&previous_output.txid)
        .or_else(|| {
            (previous_output.txid == round_tx.unsigned_tx.compute_txid()).then_some(&round_tx)
        })
        .ok_or_else(|| {
            Error::crypto(format!(
                "parent transaction {} not found for virtual TX {}",
                previous_output.txid,
                node_tx.unsigned_tx.compute_txid()
            ))
        })?;
    let previous_output = parent_tx
        .unsigned_tx
        .output
        .get(previous_output.vout as usize)
        .ok_or_else(|| {
            Error::crypto(format!(
                "previous output {} not found for virtual TX {}",
                previous_output,
                node_tx.unsigned_tx.compute_txid()
            ))
        })?;

    let prevouts = [previous_output];
    let prevouts = Prevouts::All(&prevouts);

    // Here we are generating a key spend sighash, because the VTXO tree outputs are signed
    // by all parties with a VTXO in this new round, so we use a musig key spend to
    // efficiently coordinate all the parties.
    let tap_sighash = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(VTXO_INPUT_INDEX, &prevouts, TapSighashType::Default)
        .map_err(Error::crypto)?;
    let msg = ::musig::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

    Ok(msg)
}

/// Sign each shared internal (non-leaf) node of the VTXO tree with `own_cosigner_kp` and using
/// `our_nonce_tree` to provide our share of each aggregate nonce.
#[allow(clippy::too_many_arguments)]
pub fn sign_vtxo_tree(
    vtxo_tree_expiry: bitcoin::Sequence,
    server_pk: XOnlyPublicKey,
    own_cosigner_kp: &Keypair,
    vtxo_graph: &TxGraph,
    round_tx: &Psbt,
    mut our_nonce_kps: NonceKps,
    aggregate_nonce_pks: &NoncePks,
) -> Result<PartialSigTree, Error> {
    let own_cosigner_pk = own_cosigner_kp.public_key();

    let internal_node_script = VtxoTreeInternalNodeScript::new(vtxo_tree_expiry, server_pk);

    let secp = Secp256k1::new();
    let secp_musig = ::musig::Secp256k1::new();

    let own_cosigner_kp =
        ::musig::Keypair::from_seckey_slice(&secp_musig, &own_cosigner_kp.secret_bytes())
            .expect("valid keypair");

    let tx_map = vtxo_graph.as_map();

    let mut partial_sig_tree = HashMap::new();
    for (node_txid, node_tx) in tx_map.iter() {
        let mut cosigner_pks = extract_cosigner_pks_from_vtxo_psbt(node_tx)?;
        cosigner_pks.sort_by_key(|k| k.serialize());

        if !cosigner_pks.contains(&own_cosigner_pk) {
            continue;
        }

        tracing::debug!(%node_txid, "Generating partial signature");

        let mut key_agg_cache = {
            let cosigner_pks = cosigner_pks
                .iter()
                .map(|pk| to_musig_pk(*pk))
                .collect::<Vec<_>>();
            musig::KeyAggCache::new(&secp_musig, &cosigner_pks.iter().collect::<Vec<_>>())
        };

        let sweep_tap_tree =
            internal_node_script.sweep_spend_leaf(&secp, from_musig_xonly(key_agg_cache.agg_pk()));

        let tweak = ::musig::Scalar::from(
            ::musig::SecretKey::from_slice(sweep_tap_tree.tap_tweak().as_byte_array())
                .expect("valid conversion"),
        );

        key_agg_cache
            .pubkey_xonly_tweak_add(&secp_musig, &tweak)
            .map_err(Error::crypto)?;

        let agg_pub_nonce = aggregate_nonce_pks.get(node_txid).ok_or_else(|| {
            Error::crypto(format!("missing pub nonce for virtual TX {node_txid}"))
        })?;

        // Equivalent to parsing the individual `MusigAggNonce` from a slice.
        let agg_nonce = musig::AggregatedNonce::new(&secp_musig, &[&agg_pub_nonce]);

        let msg = virtual_tx_sighash(node_tx, &tx_map, round_tx)?;

        let nonce_sk = our_nonce_kps
            .take_sk(node_txid)
            .ok_or(Error::crypto("missing nonce for virtual TX {node_txid}"))?;

        let sig = musig::Session::new(&secp_musig, &key_agg_cache, agg_nonce, msg).partial_sign(
            &secp_musig,
            nonce_sk,
            &own_cosigner_kp,
            &key_agg_cache,
        );

        partial_sig_tree.insert(*node_txid, sig);
    }

    Ok(PartialSigTree(partial_sig_tree))
}

/// Build and sign a forfeit transaction per [`VtxoInput`] to be used in an upcoming round
/// transaction.
pub fn create_and_sign_forfeit_txs(
    // For now we only support a single keypair. Eventually we may need to provide something like a
    // `Sign` trait, so that the caller can find the secret key for the given `VtxoInput`.
    kp: &Keypair,
    vtxo_inputs: &[VtxoInput],
    connectors_graph: &TxGraph,
    connector_index: &HashMap<OutPoint, OutPoint>,
    server_forfeit_address: &Address,
    // As defined by the server.
    dust: Amount,
) -> Result<Vec<Psbt>, Error> {
    const FORFEIT_TX_CONNECTOR_INDEX: usize = 0;
    const FORFEIT_TX_VTXO_INDEX: usize = 1;

    let secp = Secp256k1::new();

    let connector_amount = dust;

    let mut signed_forfeit_psbts = Vec::new();
    for VtxoInput {
        vtxo,
        amount: vtxo_amount,
        outpoint: vtxo_outpoint,
        is_recoverable,
    } in vtxo_inputs.iter()
    {
        if *is_recoverable {
            // Recoverable VTXOs don't need to be forfeited.
            continue;
        }

        let connector_outpoint = connector_index.get(vtxo_outpoint).ok_or_else(|| {
            Error::ad_hoc(format!(
                "connector outpoint missing for VTXO outpoint {vtxo_outpoint}"
            ))
        })?;

        let connector_node = connectors_graph
            .find(&connector_outpoint.txid)
            .ok_or_else(|| {
                Error::ad_hoc(format!(
                    "connector PSBT missing for VTXO outpoint {vtxo_outpoint}"
                ))
            })?;

        let connector_output = connector_node
            .root()
            .unsigned_tx
            .output
            .get(connector_outpoint.vout as usize)
            .ok_or_else(|| {
                Error::ad_hoc(format!(
                    "connector output missing for VTXO outpoint {vtxo_outpoint}"
                ))
            })?;

        let forfeit_output = TxOut {
            value: *vtxo_amount + connector_amount,
            script_pubkey: server_forfeit_address.script_pubkey(),
        };

        let mut forfeit_psbt = Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: *connector_outpoint,
                    ..Default::default()
                },
                TxIn {
                    previous_output: *vtxo_outpoint,
                    ..Default::default()
                },
            ],
            output: vec![forfeit_output.clone(), anchor_output()],
        })
        .map_err(Error::transaction)?;

        forfeit_psbt.inputs[FORFEIT_TX_CONNECTOR_INDEX].witness_utxo =
            Some(connector_output.clone());

        forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].witness_utxo = Some(TxOut {
            value: *vtxo_amount,
            script_pubkey: vtxo.script_pubkey(),
        });

        forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].sighash_type =
            Some(TapSighashType::Default.into());

        let (forfeit_script, forfeit_control_block) = vtxo.forfeit_spend_info();

        let leaf_version = forfeit_control_block.leaf_version;
        forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].tap_scripts = BTreeMap::from_iter([(
            forfeit_control_block,
            (forfeit_script.clone(), leaf_version),
        )]);

        let prevouts = forfeit_psbt
            .inputs
            .iter()
            .filter_map(|i| i.witness_utxo.clone())
            .collect::<Vec<_>>();
        let prevouts = Prevouts::All(&prevouts);

        let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

        let tap_sighash = SighashCache::new(&forfeit_psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                FORFEIT_TX_VTXO_INDEX,
                &prevouts,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(Error::crypto)?;

        let msg = secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

        let sig = secp.sign_schnorr_no_aux_rand(&msg, kp);
        let pk = kp.x_only_public_key().0;

        secp.verify_schnorr(&sig, &msg, &pk)
            .map_err(Error::crypto)
            .context("failed to verify own forfeit signature")?;

        let sig = taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };

        forfeit_psbt.inputs[FORFEIT_TX_VTXO_INDEX].tap_script_sigs =
            BTreeMap::from_iter([((pk, leaf_hash), sig)]);

        signed_forfeit_psbts.push(forfeit_psbt.clone());
    }

    Ok(signed_forfeit_psbts)
}

/// Sign every input of the `round_psbt` which is in the provided `onchain_inputs` list.
pub fn sign_round_psbt<F>(
    sign_for_pk_fn: F,
    round_psbt: &mut Psbt,
    onchain_inputs: &[OnChainInput],
) -> Result<(), Error>
where
    F: Fn(&XOnlyPublicKey, &secp256k1::Message) -> Result<schnorr::Signature, Error>,
{
    let secp = Secp256k1::new();

    let prevouts = round_psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.clone())
        .collect::<Vec<_>>();

    // Sign round transaction inputs that belong to us. For every output we
    // are boarding, we look through the round transaction inputs to find a
    // matching input.
    for OnChainInput {
        boarding_output,
        outpoint: boarding_outpoint,
        ..
    } in onchain_inputs.iter()
    {
        let (forfeit_script, forfeit_control_block) = boarding_output.forfeit_spend_info();

        for (i, input) in round_psbt.inputs.iter_mut().enumerate() {
            let previous_outpoint = round_psbt.unsigned_tx.input[i].previous_output;

            if previous_outpoint == *boarding_outpoint {
                // In the case of a boarding output, we are actually using a
                // script spend path.

                let leaf_version = forfeit_control_block.leaf_version;
                input.tap_scripts = BTreeMap::from_iter([(
                    forfeit_control_block.clone(),
                    (forfeit_script.clone(), leaf_version),
                )]);

                let prevouts = Prevouts::All(&prevouts);

                let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

                let tap_sighash = SighashCache::new(&round_psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        i,
                        &prevouts,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .map_err(Error::crypto)?;

                let msg =
                    secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());
                let pk = boarding_output.owner_pk();

                let sig = sign_for_pk_fn(&pk, &msg)?;

                secp.verify_schnorr(&sig, &msg, &pk)
                    .map_err(Error::crypto)
                    .context("failed to verify own round TX signature")?;

                let sig = taproot::Signature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                };

                input.tap_script_sigs = BTreeMap::from_iter([((pk, leaf_hash), sig)]);
            }
        }
    }

    Ok(())
}

fn extract_cosigner_pks_from_vtxo_psbt(psbt: &Psbt) -> Result<Vec<PublicKey>, Error> {
    let vtxo_input = &psbt.inputs[VTXO_INPUT_INDEX];

    let mut cosigner_pks = Vec::new();
    for (key, pk) in vtxo_input.unknown.iter() {
        if key.key.starts_with(&COSIGNER_PSBT_KEY_PREFIX) {
            cosigner_pks.push(
                bitcoin::PublicKey::from_slice(pk)
                    .map_err(Error::crypto)
                    .context("invalid PK")?
                    .inner,
            );
        }
    }
    Ok(cosigner_pks)
}
