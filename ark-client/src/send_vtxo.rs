use crate::error::ErrorContext;
use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use crate::Blockchain;
use crate::Client;
use crate::Error;
use ark_core::coin_select::select_vtxos;
use ark_core::redeem;
use ark_core::redeem::build_offchain_transactions;
use ark_core::redeem::sign_checkpoint_transaction;
use ark_core::redeem::sign_offchain_virtual_transaction;
use ark_core::redeem::OffchainTransactions;
use ark_core::ArkAddress;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::Amount;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;

impl<B, W> Client<B, W>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    pub async fn send_vtxo(&self, address: ArkAddress, amount: Amount) -> Result<Txid, Error> {
        // Recoverable VTXOs cannot be sent.
        let select_recoverable_vtxos = false;

        let spendable_vtxos = self
            .spendable_vtxos(select_recoverable_vtxos)
            .await
            .context("failed to get spendable VTXOs")?;

        // Run coin selection algorithm on candidate spendable VTXOs.
        let spendable_vtxo_outpoints = spendable_vtxos
            .iter()
            .flat_map(|(vtxos, _)| vtxos.clone())
            .map(|vtxo| ark_core::coin_select::VtxoOutPoint {
                outpoint: vtxo.outpoint,
                expire_at: vtxo.expire_at,
                amount: vtxo.amount,
            })
            .collect::<Vec<_>>();

        let selected_coins = select_vtxos(
            spendable_vtxo_outpoints,
            amount,
            self.server_info.dust,
            true,
        )
        .map_err(Error::from)
        .context("failed to select coins")?;

        let vtxo_inputs = selected_coins
            .into_iter()
            .map(|vtxo_outpoint| {
                let vtxo = spendable_vtxos
                    .clone()
                    .into_iter()
                    .find_map(|(vtxo_outpoints, vtxo)| {
                        vtxo_outpoints
                            .iter()
                            .any(|v| v.outpoint == vtxo_outpoint.outpoint)
                            .then_some(vtxo)
                    })
                    .expect("to find matching default VTXO");

                redeem::VtxoInput::new(vtxo, vtxo_outpoint.amount, vtxo_outpoint.outpoint)
            })
            .collect::<Vec<_>>();

        let (change_address, _) = self.get_offchain_address()?;

        let OffchainTransactions {
            mut virtual_tx,
            checkpoint_txs,
        } = build_offchain_transactions(
            &[(&address, amount)],
            Some(&change_address),
            &vtxo_inputs,
            self.server_info.dust,
        )
        .map_err(Error::from)?;

        let sign_fn =
        |msg: secp256k1::Message| -> Result<(schnorr::Signature, XOnlyPublicKey), ark_core::Error> {
            let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, self.kp());
            let pk = self.kp().x_only_public_key().0;

            Ok((sig, pk))
        };

        for i in 0..checkpoint_txs.len() {
            sign_offchain_virtual_transaction(
                sign_fn,
                &mut virtual_tx,
                &checkpoint_txs
                    .iter()
                    .map(|(_, output, outpoint)| (output.clone(), *outpoint))
                    .collect::<Vec<_>>(),
                i,
            )?;
        }

        let virtual_txid = virtual_tx.unsigned_tx.compute_txid();

        let mut res = self
            .network_client()
            .submit_offchain_transaction_request(
                virtual_tx,
                checkpoint_txs
                    .into_iter()
                    .map(|(psbt, _, _)| psbt)
                    .collect(),
            )
            .await
            .map_err(Error::ark_server)
            .context("failed to submit offchain transaction request")?;

        for checkpoint_psbt in res.signed_checkpoint_txs.iter_mut() {
            let vtxo_input = vtxo_inputs
                .iter()
                .find(|input| {
                    checkpoint_psbt.unsigned_tx.input[0].previous_output == input.outpoint()
                })
                .ok_or_else(|| {
                    Error::ad_hoc(format!(
                        "could not find VTXO input for checkpoint transaction {}",
                        checkpoint_psbt.unsigned_tx.compute_txid(),
                    ))
                })?;

            sign_checkpoint_transaction(sign_fn, checkpoint_psbt, vtxo_input)?;
        }

        self.network_client()
            .finalize_offchain_transaction(virtual_txid, res.signed_checkpoint_txs)
            .await
            .map_err(Error::ark_server)
            .context("failed to finalize offchain transaction")?;

        Ok(virtual_txid)
    }
}
