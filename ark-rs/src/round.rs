use crate::asp::RoundStreamEvent;
use crate::error::ErrorContext;
use crate::utils::sleep;
use crate::utils::spawn;
use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use crate::Blockchain;
use crate::Client;
use crate::Error;
use crate::ExplorerUtxo;
use ark_core::asp::RoundInput;
use ark_core::asp::RoundOutput;
use ark_core::asp::Tree;
use ark_core::round;
use ark_core::round::create_and_sign_forfeit_txs;
use ark_core::round::generate_nonce_tree;
use ark_core::round::sign_round_psbt;
use ark_core::round::sign_vtxo_tree;
use ark_core::round::NonceTree;
use ark_core::ArkAddress;
use backon::ExponentialBuilder;
use backon::Retryable;
use bitcoin::key::Keypair;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Psbt;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use futures::FutureExt;
use futures::StreamExt;
use rand::CryptoRng;
use rand::Rng;
use std::time::Duration;

impl<B, W> Client<B, W>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    /// Lift all pending VTXOs and boarding outputs into the Ark, converting them into new,
    /// confirmed VTXOs. We do this by "joining the next round".
    pub async fn board<R>(&self, rng: &mut R) -> Result<(), Error>
    where
        R: Rng + CryptoRng + Clone,
    {
        // Get off-chain address and send all funds to this address, no change output 🦄
        let (to_address, _) = self.get_offchain_address();

        let (boarding_inputs, vtxo_inputs, total_amount) =
            self.fetch_round_transaction_inputs().await?;

        tracing::info!(
            offchain_adress = %to_address.encode(),
            ?boarding_inputs,
            "Attempting to board the ark"
        );

        let join_next_ark_round = || async {
            self.join_next_ark_round(
                &mut rng.clone(),
                boarding_inputs.clone(),
                vtxo_inputs.clone(),
                RoundOutputType::Board {
                    to_address,
                    to_amount: total_amount,
                },
            )
            .await
        };

        // Joining a round can fail depending on the timing, so we try a few times.
        let txid = join_next_ark_round
            .retry(ExponentialBuilder::default().with_max_times(5))
            .sleep(sleep)
            // TODO: Use `when` to only retry certain errors.
            .notify(|err: &Error, dur: Duration| {
                tracing::warn!(
                    "Retrying joining next Ark round after {:?}. Error: {:?}",
                    dur,
                    err,
                );
            })
            .await
            .context("Failed to join round")?;

        tracing::info!(%txid, "Boarding success");

        Ok(())
    }

    // In go client: CollaborativeRedeem.
    pub async fn off_board<R>(
        &self,
        rng: &mut R,
        to_address: Address,
        to_amount: Amount,
    ) -> Result<Txid, Error>
    where
        R: Rng + CryptoRng + Clone,
    {
        let (change_address, _) = self.get_offchain_address();

        let (boarding_inputs, vtxo_inputs, total_amount) =
            self.fetch_round_transaction_inputs().await?;

        let change_amount = total_amount.checked_sub(to_amount).ok_or_else(|| {
            Error::coin_select("cannot afford to send {to_amount}, only have {total_amount}")
        })?;

        tracing::info!(
            %to_address,
            %to_amount,
            change_address = %change_address.encode(),
            %change_amount,
            ?boarding_inputs,
            "Attempting to off-board the ark"
        );

        let join_next_ark_round = || async {
            self.join_next_ark_round(
                &mut rng.clone(),
                boarding_inputs.clone(),
                vtxo_inputs.clone(),
                RoundOutputType::OffBoard {
                    to_address: to_address.clone(),
                    to_amount,
                    change_address,
                    change_amount,
                },
            )
            .await
        };

        // Joining a round can fail depending on the timing, so we try a few times.
        let txid = join_next_ark_round
            .retry(ExponentialBuilder::default().with_max_times(5))
            .sleep(sleep)
            // TODO: Use `when` to only retry certain errors.
            .notify(|err: &Error, dur: Duration| {
                tracing::warn!(
                    "Retrying joining next Ark round after {:?}. Error: {:?}",
                    dur,
                    err,
                );
            })
            .await
            .context("Failed to join round")?;

        tracing::info!(%txid, "Off-boarding success");

        Ok(txid)
    }

    /// Get all the [`round::OnChainInput`]s and [`round::VtxoInput`]s that can be used to join an
    /// upcoming round.
    async fn fetch_round_transaction_inputs(
        &self,
    ) -> Result<(Vec<round::OnChainInput>, Vec<round::VtxoInput>, Amount), Error> {
        // Get all known boarding outputs.
        let boarding_outputs = self.inner.wallet.get_boarding_outputs()?;

        let mut boarding_inputs: Vec<round::OnChainInput> = Vec::new();
        let mut total_amount = Amount::ZERO;

        let now = std::time::UNIX_EPOCH.elapsed().map_err(Error::ad_hoc)?;

        // Find outpoints for each boarding output.
        for boarding_output in boarding_outputs {
            let outpoints = self
                .blockchain()
                .find_outpoints(boarding_output.address())
                .await?;

            for o in outpoints.iter() {
                if let ExplorerUtxo {
                    outpoint,
                    amount,
                    confirmation_blocktime: Some(confirmation_blocktime),
                } = o
                {
                    // Only include confirmed boarding outputs with an _inactive_ exit path.
                    if !boarding_output.can_be_claimed_unilaterally_by_owner(
                        now,
                        Duration::from_secs(*confirmation_blocktime),
                    ) {
                        boarding_inputs
                            .push(round::OnChainInput::new(boarding_output.clone(), *outpoint));
                        total_amount += *amount;
                    }
                }
            }
        }

        let spendable_vtxos = self.spendable_vtxos().await?;

        for (vtxo_outpoints, _) in spendable_vtxos.iter() {
            total_amount += vtxo_outpoints
                .iter()
                .fold(Amount::ZERO, |acc, vtxo| acc + vtxo.amount)
        }

        let vtxo_inputs = spendable_vtxos
            .into_iter()
            .flat_map(|(vtxo_outpoints, vtxo)| {
                vtxo_outpoints
                    .into_iter()
                    .map(|vtxo_outpoint| {
                        round::VtxoInput::new(
                            vtxo.clone(),
                            vtxo_outpoint.amount,
                            vtxo_outpoint.outpoint.expect("outpoint"),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok((boarding_inputs, vtxo_inputs, total_amount))
    }

    async fn join_next_ark_round<R>(
        &self,
        rng: &mut R,
        onchain_inputs: Vec<round::OnChainInput>,
        vtxo_inputs: Vec<round::VtxoInput>,
        output_type: RoundOutputType,
    ) -> Result<Txid, Error>
    where
        R: Rng + CryptoRng,
    {
        if onchain_inputs.is_empty() && vtxo_inputs.is_empty() {
            return Err(Error::ad_hoc("cannot join round without inputs"));
        }

        let asp_info = &self.asp_info;

        // Generate an ephemeral key.
        let ephemeral_kp = Keypair::new(self.secp(), rng);

        let inputs = {
            let boarding_inputs = onchain_inputs
                .clone()
                .into_iter()
                .map(|o| RoundInput::new(Some(o.outpoint()), o.boarding_output().tapscripts()));

            let vtxo_inputs = vtxo_inputs
                .clone()
                .into_iter()
                .map(|v| RoundInput::new(Some(v.outpoint()), v.vtxo().tapscripts()));

            boarding_inputs.chain(vtxo_inputs).collect()
        };

        let payment_id = self
            .asp_client()
            .register_inputs_for_next_round(ephemeral_kp.public_key(), inputs)
            .await
            .map_err(Error::from)
            .context("failed to register round inputs")?;

        tracing::debug!(payment_id, "Registered for round");

        let mut outputs = vec![];

        match output_type {
            RoundOutputType::Board {
                to_address,
                to_amount,
            } => outputs.push(RoundOutput::new_virtual(to_address, to_amount)),
            RoundOutputType::OffBoard {
                to_address,
                to_amount,
                change_address,
                change_amount,
            } => {
                outputs.push(RoundOutput::new_on_chain(to_address, to_amount));
                outputs.push(RoundOutput::new_virtual(change_address, change_amount));
            }
        }

        self.asp_client()
            .register_outputs_for_next_round(payment_id.clone(), outputs)
            .await?;

        let asp_client = self.asp_client();

        // The protocol expects us to ping the ASP every 5 seconds to let the server know that we
        // are still interested in joining the round.
        //
        // We generate a `RemoteHandle` so that the ping task is cancelled when the parent function
        // ends.
        let (ping_task, _ping_handle) = {
            let asp_client = asp_client.clone();
            async move {
                loop {
                    if let Err(e) = asp_client.ping(payment_id.clone()).await {
                        tracing::warn!("Error via ping: {e:?}");
                    }

                    sleep(Duration::from_millis(5000)).await
                }
            }
        }
        .remote_handle();

        spawn(ping_task);

        let mut stream = asp_client.get_event_stream().await?;

        let mut step = RoundStep::Start;

        let (asp_pk, _) = asp_info.pk.inner.x_only_public_key();

        let mut round_id: Option<String> = None;
        let mut unsigned_round_tx: Option<Psbt> = None;
        let mut vtxo_tree: Option<Tree> = None;
        let mut cosigner_pks: Option<Vec<PublicKey>> = None;

        let mut our_nonce_tree: Option<NonceTree> = None;
        loop {
            match stream.next().await {
                Some(Ok(event)) => match event {
                    RoundStreamEvent::RoundSigning(e) => {
                        if step != RoundStep::Start {
                            continue;
                        }

                        tracing::info!(round_id = e.id, "Round signing started");

                        round_id = Some(e.id.clone());

                        let unsigned_vtxo_tree =
                            e.unsigned_vtxo_tree.expect("to have an unsigned vtxo tree");

                        let nonce_tree = generate_nonce_tree(
                            rng,
                            &unsigned_vtxo_tree,
                            ephemeral_kp.public_key(),
                        )
                        .map_err(Error::from)?;

                        asp_client
                            .submit_tree_nonces(
                                e.id,
                                ephemeral_kp.public_key(),
                                nonce_tree.to_pub_nonce_tree().into_inner(),
                            )
                            .await?;

                        our_nonce_tree = Some(nonce_tree);

                        vtxo_tree = Some(unsigned_vtxo_tree);

                        let cosigner_public_keys =
                            e.cosigners_pubkeys.into_iter().collect::<Vec<_>>();

                        cosigner_pks = Some(cosigner_public_keys);

                        unsigned_round_tx = Some(e.unsigned_round_tx);

                        step = step.next();
                        continue;
                    }
                    RoundStreamEvent::RoundSigningNoncesGenerated(e) => {
                        if step != RoundStep::RoundSigningStarted {
                            continue;
                        }

                        let agg_pub_nonce_tree = e.tree_nonces;

                        tracing::debug!(
                            round_id = e.id,
                            ?agg_pub_nonce_tree,
                            "Round combined nonces generated"
                        );

                        let unsigned_round_tx = unsigned_round_tx
                            .as_ref()
                            .ok_or(Error::asp("missing round TX during round protocol"))?;

                        let vtxo_tree = vtxo_tree
                            .as_ref()
                            .ok_or(Error::asp("missing vtxo tree during round protocol"))?;
                        let cosigner_pks = cosigner_pks
                            .clone()
                            .ok_or(Error::asp("missing cosigner PKs during round protocol"))?;
                        let our_nonce_tree = our_nonce_tree
                            .take()
                            .ok_or(Error::asp("missing nonce tree during round protocol"))?;

                        let partial_sig_tree = sign_vtxo_tree(
                            asp_info.round_lifetime,
                            asp_pk,
                            &ephemeral_kp,
                            vtxo_tree,
                            unsigned_round_tx,
                            cosigner_pks,
                            our_nonce_tree,
                            agg_pub_nonce_tree.into(),
                        )
                        .map_err(Error::from)?;

                        asp_client
                            .submit_tree_signatures(
                                e.id,
                                ephemeral_kp.public_key(),
                                partial_sig_tree.into_inner(),
                            )
                            .await?;

                        step = step.next();
                    }
                    RoundStreamEvent::RoundFinalization(e) => {
                        if step != RoundStep::RoundSigningNoncesGenerated {
                            continue;
                        }
                        tracing::debug!(?e, "Round finalization started");

                        let signed_forfeit_psbts = create_and_sign_forfeit_txs(
                            self.kp(),
                            vtxo_inputs.as_slice(),
                            e.connectors,
                            e.min_relay_fee_rate,
                            &asp_info.forfeit_address,
                            asp_info.dust,
                        )
                        .map_err(Error::from)?;

                        let mut round_psbt = e.round_tx;

                        let sign_for_pk_fn = |pk: &XOnlyPublicKey,
                                              msg: &secp256k1::Message|
                         -> Result<
                            schnorr::Signature,
                            ark_core::Error,
                        > {
                            self.inner
                                .wallet
                                .sign_for_pk(pk, msg)
                                .map_err(|e| ark_core::Error::ad_hoc(e.to_string()))
                        };

                        sign_round_psbt(sign_for_pk_fn, &mut round_psbt, &onchain_inputs)
                            .map_err(Error::from)?;

                        asp_client
                            .submit_signed_forfeit_txs(signed_forfeit_psbts, round_psbt)
                            .await?;

                        step = step.next();
                    }
                    RoundStreamEvent::RoundFinalized(e) => {
                        if step != RoundStep::RoundFinalization {
                            continue;
                        }

                        let round_txid = e.round_txid;

                        tracing::info!(round_id = e.id, %round_txid, "Round finalized");

                        return Ok(round_txid);
                    }
                    RoundStreamEvent::RoundFailed(e) => {
                        if Some(&e.id) == round_id.as_ref() {
                            return Err(Error::asp(format!(
                                "failed registering in round {}: {}",
                                e.id, e.reason
                            )));
                        }

                        tracing::debug!("Unrelated round failed: {e:?}");

                        continue;
                    }
                },
                Some(Err(e)) => {
                    return Err(Error::asp(e));
                }
                None => {
                    return Err(Error::asp("dropped round event stream"));
                }
            }
        }

        #[derive(Debug, PartialEq, Eq)]
        enum RoundStep {
            Start,
            RoundSigningStarted,
            RoundSigningNoncesGenerated,
            RoundFinalization,
            Finalized,
        }

        impl RoundStep {
            fn next(&self) -> RoundStep {
                match self {
                    RoundStep::Start => RoundStep::RoundSigningStarted,
                    RoundStep::RoundSigningStarted => RoundStep::RoundSigningNoncesGenerated,
                    RoundStep::RoundSigningNoncesGenerated => RoundStep::RoundFinalization,
                    RoundStep::RoundFinalization => RoundStep::Finalized,
                    RoundStep::Finalized => RoundStep::Finalized, // we can't go further
                }
            }
        }
    }
}

enum RoundOutputType {
    Board {
        to_address: ArkAddress,
        to_amount: Amount,
    },
    OffBoard {
        to_address: Address,
        to_amount: Amount,
        change_address: ArkAddress,
        change_amount: Amount,
    },
}
