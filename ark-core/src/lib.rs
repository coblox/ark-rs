use bitcoin::Amount;
use bitcoin::OutPoint;

pub mod boarding_output;
pub mod coin_select;
pub mod conversions;
pub mod proof_of_funds;
pub mod redeem;
pub mod round;
pub mod server;
pub mod unilateral_exit;
pub mod vtxo;

mod ark_address;
mod error;
mod history;
mod internal_node;
mod script;

pub use ark_address::ArkAddress;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
pub use boarding_output::BoardingOutput;
pub use error::Error;
pub use error::ErrorContext;
pub use history::generate_incoming_vtxo_transaction_history;
pub use history::generate_outgoing_vtxo_transaction_history;
pub use history::ArkTransaction;
pub use script::extract_sequence_from_csv_sig_script;
pub use unilateral_exit::build_anchor_tx;
pub use unilateral_exit::build_unilateral_exit_tree_txids;
pub use unilateral_exit::SelectedUtxo;
pub use unilateral_exit::UtxoCoinSelection;
pub use vtxo::Vtxo;

pub const UNSPENDABLE_KEY: &str =
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub const VTXO_INPUT_INDEX: usize = 0;

const ANCHOR_SCRIPT_PUBKEY: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

/// Information a UTXO that may be extracted from an on-chain explorer.
#[derive(Clone, Copy, Debug)]
pub struct ExplorerUtxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub confirmation_blocktime: Option<u64>,
    pub is_spent: bool,
}

pub fn anchor_output() -> TxOut {
    let script_pubkey = ScriptBuf::from_bytes(ANCHOR_SCRIPT_PUBKEY.to_vec());

    TxOut {
        value: Amount::ZERO,
        script_pubkey,
    }
}
