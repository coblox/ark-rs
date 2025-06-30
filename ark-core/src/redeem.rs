use crate::anchor_output;
use crate::script::csv_sig_script;
use crate::script::multisig_script;
use crate::script::tr_script_pubkey;
use crate::vtxo::Vtxo;
use crate::ArkAddress;
use crate::Error;
use crate::ErrorContext;
use crate::UNSPENDABLE_KEY;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::PublicKey;
use bitcoin::key::Secp256k1;
use bitcoin::psbt;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::ScriptBuf;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use std::collections::BTreeMap;
use std::io;
use std::io::Write;

/// The byte value corresponds to the string "taptree".
const VTXO_TAPROOT_KEY: [u8; 7] = [116, 97, 112, 116, 114, 101, 101];

/// A VTXO to be spent into an unconfirmed VTXO.
#[derive(Debug, Clone)]
pub struct VtxoInput {
    /// The information needed to spend the VTXO, besides the amount.
    vtxo: Vtxo,
    /// The amount of coins locked in the VTXO.
    amount: Amount,
    /// Where the VTXO would end up on the blockchain if it were to become a UTXO.
    outpoint: OutPoint,
}

impl VtxoInput {
    pub fn new(vtxo: Vtxo, amount: Amount, outpoint: OutPoint) -> Self {
        Self {
            vtxo,
            amount,
            outpoint,
        }
    }

    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }
}

#[derive(Debug, Clone)]
pub struct OffchainTransactions {
    pub virtual_tx: Psbt,
    pub checkpoint_txs: Vec<(Psbt, CheckpointOutput, CheckpointOutPoint)>,
}

/// Build a transaction to send VTXOs to another [`ArkAddress`].
pub fn build_offchain_transactions(
    outputs: &[(&ArkAddress, Amount)],
    change_address: Option<&ArkAddress>,
    vtxo_inputs: &[VtxoInput],
) -> Result<OffchainTransactions, Error> {
    if vtxo_inputs.is_empty() {
        return Err(Error::transaction(
            "cannot build redeem transaction without inputs",
        ));
    }

    let mut checkpoint_txs = Vec::new();
    for vtxo_input in vtxo_inputs.iter() {
        let checkpoint_tx = build_checkpoint_psbt(vtxo_input).with_context(|| {
            format!(
                "failed to build checkpoint psbt for input {:?}",
                vtxo_input.outpoint
            )
        })?;

        checkpoint_txs.push(checkpoint_tx);
    }

    let mut outputs = outputs
        .iter()
        .map(|(address, amount)| TxOut {
            value: *amount,
            script_pubkey: address.to_p2tr_script_pubkey(),
        })
        .collect::<Vec<_>>();

    let total_input_amount: Amount = vtxo_inputs.iter().map(|v| v.amount).sum();
    let total_output_amount: Amount = outputs.iter().map(|v| v.value).sum();

    let change_amount = total_input_amount.checked_sub(total_output_amount).ok_or_else(|| {
        Error::transaction(format!(
            "cannot cover total output amount ({total_output_amount}) with total input amount ({total_input_amount})"
        ))
    })?;

    if change_amount > Amount::ZERO {
        if let Some(change_address) = change_address {
            outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_address.to_p2tr_script_pubkey(),
            });
        }
    }

    outputs.push(anchor_output());

    // TODO: Use a different locktime if we have CLTV multisig script.
    let lock_time = LockTime::ZERO;

    let unsigned_virtual_tx = Transaction {
        version: transaction::Version::non_standard(3),
        lock_time,
        input: checkpoint_txs
            .iter()
            .map(|(_, _, CheckpointOutPoint { outpoint, .. })| TxIn {
                previous_output: *outpoint,
                script_sig: Default::default(),
                // TODO: Use a different sequence number if we have a CLTV multisig script.
                sequence: bitcoin::Sequence::MAX,
                witness: Default::default(),
            })
            .collect(),
        output: outputs,
    };

    let mut unsigned_virtual_psbt =
        Psbt::from_unsigned_tx(unsigned_virtual_tx).map_err(Error::transaction)?;

    for (i, (_, checkpoint_output, _)) in checkpoint_txs.iter().enumerate() {
        let mut bytes = Vec::new();

        let script = &checkpoint_output.forfeit_script;
        write_compact_size_uint(&mut bytes, script.len() as u64).map_err(Error::transaction)?;

        // Write the depth (always 1). TODO: Support more depth.
        bytes.push(1);

        // TODO: Support future leaf versions.
        bytes.push(LeafVersion::TapScript.to_consensus());

        let mut script_bytes = script.to_bytes();

        write_compact_size_uint(&mut bytes, script_bytes.len() as u64)
            .map_err(Error::transaction)?;

        bytes.append(&mut script_bytes);

        unsigned_virtual_psbt.inputs[i].unknown.insert(
            psbt::raw::Key {
                type_value: u8::MAX,
                key: VTXO_TAPROOT_KEY.to_vec(),
            },
            bytes,
        );
    }

    Ok(OffchainTransactions {
        virtual_tx: unsigned_virtual_psbt,
        checkpoint_txs,
    })
}

#[derive(Debug, Clone)]
pub struct CheckpointOutput {
    forfeit_script: ScriptBuf,
    spend_info: TaprootSpendInfo,
}

#[derive(Debug, Clone, Copy)]
pub struct CheckpointOutPoint {
    outpoint: OutPoint,
    amount: Amount,
}

impl CheckpointOutput {
    fn new(server: XOnlyPublicKey, owner: XOnlyPublicKey, exit_delay: bitcoin::Sequence) -> Self {
        let secp = Secp256k1::new();

        let unspendable_key: PublicKey = UNSPENDABLE_KEY.parse().expect("valid key");
        let (unspendable_key, _) = unspendable_key.inner.x_only_public_key();

        let forfeit_script = multisig_script(server, owner);
        let redeem_script = csv_sig_script(exit_delay, server);

        let spend_info = TaprootBuilder::new()
            .add_leaf(1, forfeit_script.clone())
            .expect("valid forfeit leaf")
            .add_leaf(1, redeem_script)
            .expect("valid redeem leaf")
            .finalize(&secp, unspendable_key)
            .expect("can be finalized");

        Self {
            forfeit_script,
            spend_info,
        }
    }

    fn script_pubkey(&self) -> ScriptBuf {
        tr_script_pubkey(&self.spend_info)
    }
}

fn build_checkpoint_psbt(
    vtxo_input: &VtxoInput,
) -> Result<(Psbt, CheckpointOutput, CheckpointOutPoint), Error> {
    let inputs = vec![TxIn {
        previous_output: vtxo_input.outpoint,
        script_sig: Default::default(),
        sequence: bitcoin::Sequence::MAX,
        witness: Default::default(),
    }];

    let checkpoint_output = CheckpointOutput::new(
        vtxo_input.vtxo.server_pk(),
        vtxo_input.vtxo.owner_pk(),
        vtxo_input.vtxo.exit_delay(),
    );

    let outputs = vec![
        TxOut {
            value: vtxo_input.amount,
            script_pubkey: checkpoint_output.script_pubkey(),
        },
        anchor_output(),
    ];

    let lock_time = LockTime::ZERO;

    let unsigned_tx = Transaction {
        version: transaction::Version::non_standard(3),
        lock_time,
        input: inputs,
        output: outputs,
    };

    let mut unsigned_checkpoint_psbt =
        Psbt::from_unsigned_tx(unsigned_tx).map_err(Error::transaction)?;

    let mut bytes = Vec::new();

    write_compact_size_uint(&mut bytes, vtxo_input.vtxo.tapscripts().len() as u64)
        .map_err(Error::transaction)?;

    for script in vtxo_input.vtxo.tapscripts().iter() {
        // Write the depth (always 1). TODO: Support more depth.
        bytes.push(1);

        // TODO: Support future leaf versions.
        bytes.push(LeafVersion::TapScript.to_consensus());

        let mut script_bytes = script.to_bytes();

        write_compact_size_uint(&mut bytes, script_bytes.len() as u64)
            .map_err(Error::transaction)?;

        bytes.append(&mut script_bytes);
    }

    unsigned_checkpoint_psbt.inputs[0].witness_utxo = Some(TxOut {
        value: vtxo_input.amount,
        script_pubkey: vtxo_input.vtxo.script_pubkey(),
    });

    // In the case of input VTXOs, we are actually using a script spend path.
    let (forfeit_script, forfeit_control_block) = vtxo_input.vtxo.forfeit_spend_info();

    let leaf_version = forfeit_control_block.leaf_version;
    unsigned_checkpoint_psbt.inputs[0].tap_scripts = BTreeMap::from_iter([(
        forfeit_control_block,
        (forfeit_script.clone(), leaf_version),
    )]);

    unsigned_checkpoint_psbt.inputs[0].unknown.insert(
        psbt::raw::Key {
            type_value: u8::MAX,
            key: VTXO_TAPROOT_KEY.to_vec(),
        },
        bytes,
    );

    let checkpoint_outpoint = CheckpointOutPoint {
        outpoint: OutPoint {
            txid: unsigned_checkpoint_psbt.unsigned_tx.compute_txid(),
            vout: 0,
        },
        amount: vtxo_input.amount,
    };

    Ok((
        unsigned_checkpoint_psbt,
        checkpoint_output,
        checkpoint_outpoint,
    ))
}

fn write_compact_size_uint<W: Write>(w: &mut W, val: u64) -> io::Result<()> {
    if val < 253 {
        w.write_all(&[val as u8])?;
    } else if val < 0x10000 {
        w.write_all(&[253])?;
        w.write_all(&(val as u16).to_le_bytes())?;
    } else if val < 0x100000000 {
        w.write_all(&[254])?;
        w.write_all(&(val as u32).to_le_bytes())?;
    } else {
        w.write_all(&[255])?;
        w.write_all(&val.to_le_bytes())?;
    }
    Ok(())
}

pub fn sign_checkpoint_transaction<S>(
    sign_fn: S,
    psbt: &mut Psbt,
    vtxo_input: &VtxoInput,
) -> Result<(), Error>
where
    S: FnOnce(secp256k1::Message) -> Result<(schnorr::Signature, XOnlyPublicKey), Error>,
{
    let VtxoInput {
        vtxo,
        amount,
        outpoint,
    } = vtxo_input;

    tracing::debug!(
        ?outpoint,
        %amount,
        ?vtxo,
        "Attempting to sign selected VTXO for checkpoint transaction"
    );

    let (input_index, _) = psbt
        .unsigned_tx
        .input
        .iter()
        .enumerate()
        .find(|(_, input)| input.previous_output == *outpoint)
        .ok_or_else(|| Error::transaction(format!("missing input for outpoint {outpoint}")))?;

    tracing::debug!(
        ?outpoint,
        ?vtxo,
        index = input_index,
        "Signing selected VTXO for checkpoint transaction"
    );

    let psbt_input = psbt.inputs.get_mut(input_index).expect("input at index");

    // In the case of input VTXOs, we are actually using a script spend path.
    let (forfeit_script, forfeit_control_block) = vtxo.forfeit_spend_info();

    let leaf_version = forfeit_control_block.leaf_version;

    let prevouts = [TxOut {
        value: *amount,
        script_pubkey: vtxo.script_pubkey(),
    }];
    let prevouts = Prevouts::All(&prevouts);

    let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

    let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &prevouts,
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(Error::crypto)
        .context("failed to generate sighash")?;

    let msg = secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

    let (sig, pk) = sign_fn(msg)?;

    let sig = taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };

    psbt_input.tap_script_sigs = BTreeMap::from_iter([((pk, leaf_hash), sig)]);

    Ok(())
}

pub fn sign_offchain_virtual_transaction<S>(
    sign_fn: S,
    psbt: &mut Psbt,
    checkpoint_inputs: &[(CheckpointOutput, CheckpointOutPoint)],
    input_index: usize,
) -> Result<(), Error>
where
    S: FnOnce(secp256k1::Message) -> Result<(schnorr::Signature, XOnlyPublicKey), Error>,
{
    let (checkpoint_output, CheckpointOutPoint { outpoint, amount }) = checkpoint_inputs
        .get(input_index)
        .ok_or_else(|| Error::ad_hoc(format!("no input to sign at index {input_index}")))?;

    tracing::debug!(
        ?outpoint,
        %amount,
        "Attempting to sign selected checkpoint output for offchain virtual transaction"
    );

    let prevout = TxOut {
        value: *amount,
        script_pubkey: checkpoint_output.script_pubkey(),
    };

    psbt.unsigned_tx
        .input
        .iter()
        .enumerate()
        .find(|(_, input)| input.previous_output == *outpoint)
        .ok_or_else(|| Error::transaction(format!("missing input for outpoint {outpoint}")))?;

    tracing::debug!(
        ?outpoint,
        index = input_index,
        "Signing checkpoint output for offchian virtual transaction"
    );

    let psbt_input = psbt.inputs.get_mut(input_index).expect("input at index");

    psbt_input.witness_utxo = Some(prevout.clone());

    // In the case of input checkpoint outputs, we are using a script spend path.

    let forfeit_script = &checkpoint_output.forfeit_script;
    let leaf_version = LeafVersion::TapScript;

    let forfeit_control_block = checkpoint_output
        .spend_info
        .control_block(&(forfeit_script.clone(), leaf_version))
        .ok_or_else(|| {
            Error::transaction(format!(
                "failed to construct control block for input {outpoint:?}"
            ))
        })?;

    psbt_input.tap_scripts = BTreeMap::from_iter([(
        forfeit_control_block,
        (forfeit_script.clone(), leaf_version),
    )]);

    let prevouts = checkpoint_inputs
        .iter()
        .map(|(output, outpoint)| TxOut {
            value: outpoint.amount,
            script_pubkey: output.script_pubkey(),
        })
        .collect::<Vec<_>>();
    let prevouts = Prevouts::All(&prevouts);

    let leaf_hash = TapLeafHash::from_script(forfeit_script, leaf_version);

    let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &prevouts,
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(Error::crypto)
        .context("failed to generate sighash")?;

    let msg = secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

    let (sig, pk) = sign_fn(msg)?;

    let sig = taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };

    psbt_input.tap_script_sigs = BTreeMap::from_iter([((pk, leaf_hash), sig)]);

    Ok(())
}
