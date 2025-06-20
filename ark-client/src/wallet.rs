use crate::error::Error;
use ark_core::BoardingOutput;
use ark_core::UtxoCoinSelection;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::Psbt;
use bitcoin::XOnlyPublicKey;

pub trait BoardingWallet {
    fn new_boarding_output(
        &self,
        server_pubkey: XOnlyPublicKey,
        exit_delay: bitcoin::Sequence,
        network: Network,
    ) -> Result<BoardingOutput, Error>;

    fn get_boarding_outputs(&self) -> Result<Vec<BoardingOutput>, Error>;

    fn sign_for_pk(&self, pk: &XOnlyPublicKey, msg: &Message) -> Result<Signature, Error>;
}

pub trait OnchainWallet {
    fn get_onchain_address(&self) -> Result<Address, Error>;

    fn sync(&self) -> impl std::future::Future<Output = Result<(), Error>>;

    fn balance(&self) -> Result<Balance, Error>;

    fn prepare_send_to_address(
        &self,
        address: Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Psbt, Error>;

    fn sign(&self, psbt: &mut Psbt) -> Result<bool, Error>;

    fn select_coins(&self, target_amount: Amount) -> Result<UtxoCoinSelection, Error>;
}

pub trait Persistence {
    fn save_boarding_output(
        &self,
        sk: SecretKey,
        boarding_output: BoardingOutput,
    ) -> Result<(), Error>;

    fn load_boarding_outputs(&self) -> Result<Vec<BoardingOutput>, Error>;

    fn sk_for_pk(&self, pk: &XOnlyPublicKey) -> Result<SecretKey, Error>;
}

#[derive(Debug, Clone, Copy)]
pub struct Balance {
    /// All coinbase outputs not yet matured
    pub immature: Amount,
    /// Unconfirmed UTXOs generated by a wallet tx
    pub trusted_pending: Amount,
    /// Unconfirmed UTXOs received from an external wallet
    pub untrusted_pending: Amount,
    /// Confirmed and immediately spendable balance
    pub confirmed: Amount,
}
