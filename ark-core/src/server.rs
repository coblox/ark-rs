//! Messages exchanged between the client and the Ark server.

use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Transaction;
use bitcoin::Txid;
use musig::musig;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TxTree {
    pub levels: Vec<TxTreeLevel>,
}

impl TxTree {
    pub fn txs(&self) -> impl Iterator<Item = &Transaction> {
        self.levels
            .iter()
            .flat_map(|level| level.nodes.iter().map(|node| &node.tx.unsigned_tx))
    }
}

#[derive(Debug, Clone)]
pub struct TxTreeLevel {
    pub nodes: Vec<TxTreeNode>,
}

#[derive(Debug, Clone)]
pub struct TxTreeNode {
    pub txid: Txid,
    pub tx: Psbt,
    pub parent_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct Round {
    pub id: String,
    pub start: i64,
    pub end: i64,
    pub round_tx: Option<Transaction>,
    pub vtxo_tree: Option<TxTree>,
    pub forfeit_txs: Vec<Psbt>,
    pub connector_tree: Option<TxTree>,
    pub stage: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VtxoOutPoint {
    pub outpoint: OutPoint,
    pub spent: bool,
    pub round_txid: Txid,
    pub spent_by: Option<Txid>,
    pub expire_at: i64,
    pub swept: bool,
    pub is_pending: bool,
    /// The redeem transaction which has this [`VtxoOutPoint`] as an output. The TXID matches the
    /// TXID of the `outpoint` field.
    pub redeem_tx: Option<Psbt>,
    pub amount: Amount,
    pub pubkey: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct Info {
    pub pk: PublicKey,
    pub vtxo_tree_expiry: bitcoin::Sequence,
    pub unilateral_exit_delay: bitcoin::Sequence,
    pub boarding_exit_delay: bitcoin::Sequence,
    pub round_interval: i64,
    pub network: Network,
    pub dust: Amount,
    pub forfeit_address: bitcoin::Address,
    pub version: String,
    pub utxo_min_amount: Option<Amount>,
    pub utxo_max_amount: Option<Amount>,
    pub vtxo_min_amount: Option<Amount>,
    pub vtxo_max_amount: Option<Amount>,
}

#[derive(Clone, Debug)]
pub struct ListVtxo {
    pub spent: Vec<VtxoOutPoint>,
    pub spendable: Vec<VtxoOutPoint>,
}

#[derive(Debug, Clone)]
pub struct BatchStartedEvent {
    pub id: String,
    pub intent_id_hashes: Vec<String>,
    // TODO: Perhaps needs to be `bitcoin::Sequence`.
    pub batch_expiry: i64,
    pub forfeit_address: bitcoin::Address<NetworkUnchecked>,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizationEvent {
    pub id: String,
    pub round_tx: Psbt,
    pub vtxo_tree: TxTree,
    pub connector_tree: TxTree,
    /// The key is the VTXO outpoint; the value is the corresponding connector outpoint.
    pub connectors_index: HashMap<OutPoint, OutPoint>,
}

#[derive(Debug, Clone)]
pub struct RoundFinalizedEvent {
    pub id: String,
    pub round_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct RoundFailedEvent {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RoundSigningEvent {
    pub id: String,
    pub cosigners_pubkeys: Vec<PublicKey>,
    pub unsigned_vtxo_tree: Option<TxTree>,
    pub unsigned_round_tx: Psbt,
}

#[derive(Debug, Clone)]
pub struct RoundSigningNoncesGeneratedEvent {
    pub id: String,
    pub tree_nonces: Vec<Vec<Option<musig::PublicNonce>>>,
}

#[derive(Debug, Clone)]
pub enum RoundStreamEvent {
    BatchStarted(BatchStartedEvent),
    RoundFinalization(RoundFinalizationEvent),
    RoundFinalized(RoundFinalizedEvent),
    RoundFailed(RoundFailedEvent),
    RoundSigning(RoundSigningEvent),
    RoundSigningNoncesGenerated(RoundSigningNoncesGeneratedEvent),
}

pub enum TransactionEvent {
    Round(RoundTransaction),
    Redeem(RedeemTransaction),
}

pub struct RedeemTransaction {
    pub txid: Txid,
    pub spent_vtxos: Vec<VtxoOutPoint>,
    pub spendable_vtxos: Vec<VtxoOutPoint>,
}

pub struct RoundTransaction {
    pub txid: Txid,
    pub spent_vtxos: Vec<VtxoOutPoint>,
    pub spendable_vtxos: Vec<VtxoOutPoint>,
    pub claimed_boarding_utxos: Vec<OutPoint>,
}

pub struct VtxoChains {
    pub inner: Vec<VtxoChain>,
    pub root_commitment_txid: Txid,
}

pub struct VtxoChain {
    pub txid: Txid,
    pub spends: Vec<ChainedTx>,
    pub expires_at: i64,
}

pub struct ChainedTx {
    pub txid: Txid,
    pub tx_type: ChainedTxType,
}

pub enum ChainedTxType {
    Commitment,
    Virtual,
    Unspecified,
}

pub struct SubmitOffchainTxResponse {
    pub signed_virtual_tx: Psbt,
    pub signed_checkpoint_txs: Vec<Psbt>,
}

#[derive(Debug, Clone)]
pub struct FinalizeOffchainTxResponse {}
