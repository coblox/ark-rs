use crate::generated;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::indexer_service_client::IndexerServiceClient;
use crate::generated::ark::v1::Bip322Signature;
use crate::generated::ark::v1::ConfirmRegistrationRequest;
use crate::generated::ark::v1::GetEventStreamRequest;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::GetTransactionsStreamRequest;
use crate::generated::ark::v1::GetVtxosRequest;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::RegisterIntentRequest;
use crate::generated::ark::v1::SubmitSignedForfeitTxsRequest;
use crate::generated::ark::v1::SubmitTreeNoncesRequest;
use crate::generated::ark::v1::SubmitTreeSignaturesRequest;
use crate::tree;
use crate::Error;
use ark_core::proof_of_funds;
use ark_core::server::BatchFailed;
use ark_core::server::BatchFinalizationEvent;
use ark_core::server::BatchFinalizedEvent;
use ark_core::server::BatchStartedEvent;
use ark_core::server::BatchTreeEventType;
use ark_core::server::ChainedTx;
use ark_core::server::ChainedTxType;
use ark_core::server::CommitmentTransaction;
use ark_core::server::FinalizeOffchainTxResponse;
use ark_core::server::Info;
use ark_core::server::ListVtxo;
use ark_core::server::RedeemTransaction;
use ark_core::server::RoundStreamEvent;
use ark_core::server::SubmitOffchainTxResponse;
use ark_core::server::TransactionEvent;
use ark_core::server::TreeNoncesAggregatedEvent;
use ark_core::server::TreeSignatureEvent;
use ark_core::server::TreeSigningStartedEvent;
use ark_core::server::TreeTxEvent;
use ark_core::server::TxTree;
use ark_core::server::TxTreeNode;
use ark_core::server::VtxoChain;
use ark_core::server::VtxoChains;
use ark_core::server::VtxoOutPoint;
use ark_core::ArkAddress;
use async_stream::stream;
use base64::Engine;
use bitcoin::hex::DisplayHex;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::Signature;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Txid;
use futures::Stream;
use futures::StreamExt;
use futures::TryStreamExt;
use musig::musig;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Client {
    url: String,
    ark_client: Option<ArkServiceClient<tonic::transport::Channel>>,
    indexer_client: Option<IndexerServiceClient<tonic::transport::Channel>>,
}

impl Client {
    pub fn new(url: String) -> Self {
        Self {
            url,
            ark_client: None,
            indexer_client: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        let ark_service_client = ArkServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;
        let indexer_client = IndexerServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;

        self.ark_client = Some(ark_service_client);
        self.indexer_client = Some(indexer_client);
        Ok(())
    }

    pub async fn get_info(&mut self) -> Result<Info, Error> {
        let mut client = self.inner_ark_client()?;

        let response = client
            .get_info(GetInfoRequest {})
            .await
            .map_err(Error::request)?;

        response.into_inner().try_into()
    }

    pub async fn list_vtxos(&self, address: &ArkAddress) -> Result<ListVtxo, Error> {
        let address = address.encode();

        let mut client = self.inner_indexer_client()?;

        // TODO: implement pagination
        // TODO: we probably want to expose all fields as arguments to this function
        let response = client
            .get_vtxos(GetVtxosRequest {
                addresses: vec![address],
                outpoints: vec![],
                spendable_only: false,
                spent_only: false,
                page: None,
            })
            .await
            .map_err(Error::request)?;

        let mut spent = response
            .get_ref()
            .vtxos
            .iter()
            .filter_map(|vtxo| {
                if vtxo.is_redeemed || vtxo.is_spent || vtxo.is_swept {
                    Some(VtxoOutPoint::try_from(vtxo))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut spendable = response
            .get_ref()
            .vtxos
            .iter()
            .filter_map(|vtxo| {
                if !vtxo.is_redeemed && !vtxo.is_spent && !vtxo.is_swept {
                    Some(VtxoOutPoint::try_from(vtxo))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut spent_by_redeem = Vec::new();
        for spendable_vtxo in spendable.clone() {
            let was_spent_by_redeem = spendable.iter().any(|v| v.is_redeemed);

            if was_spent_by_redeem {
                spent_by_redeem.push(spendable_vtxo);
            }
        }

        // Remove "spendable" VTXOs that were actually already spent by a redeem transaction
        // from the list of spendable VTXOs.
        spendable.retain(|i| !spent_by_redeem.contains(i));

        // Add them to the list of spent VTXOs.
        spent.append(&mut spent_by_redeem);

        Ok(ListVtxo::new(spent, spendable))
    }

    pub async fn register_intent(
        &self,
        intent_message: &proof_of_funds::IntentMessage,
        proof: &proof_of_funds::Bip322Proof,
    ) -> Result<String, Error> {
        let mut client = self.inner_ark_client()?;

        let request = RegisterIntentRequest {
            intent: Some(Bip322Signature {
                signature: proof.serialize(),
                message: intent_message.encode().map_err(Error::conversion)?,
            }),
        };

        let response = client
            .register_intent(request)
            .await
            .map_err(Error::request)?;

        let intent_id = response.into_inner().intent_id;

        Ok(intent_id)
    }

    pub async fn submit_offchain_transaction_request(
        &self,
        virtual_tx: Psbt,
        checkpoint_txs: Vec<Psbt>,
    ) -> Result<SubmitOffchainTxResponse, Error> {
        let mut client = self.inner_ark_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let virtual_tx = base64.encode(virtual_tx.serialize());

        let checkpoint_txs = checkpoint_txs
            .into_iter()
            .map(|tx| base64.encode(tx.serialize()))
            .collect();

        let res = client
            .submit_tx(generated::ark::v1::SubmitTxRequest {
                signed_ark_tx: virtual_tx,
                checkpoint_txs,
            })
            .await
            .map_err(Error::request)?;

        let res = res.into_inner();

        let signed_virtual_tx = res.final_ark_tx;
        let signed_virtual_tx = base64
            .decode(signed_virtual_tx)
            .map_err(Error::conversion)?;
        let signed_virtual_tx = Psbt::deserialize(&signed_virtual_tx).map_err(Error::conversion)?;

        let signed_checkpoint_txs = res
            .signed_checkpoint_txs
            .into_iter()
            .map(|tx| {
                let tx = base64.decode(tx).map_err(Error::conversion)?;
                let tx = Psbt::deserialize(&tx).map_err(Error::conversion)?;

                Ok(tx)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(SubmitOffchainTxResponse {
            signed_virtual_tx,
            signed_checkpoint_txs,
        })
    }

    pub async fn finalize_offchain_transaction(
        &self,
        txid: Txid,
        checkpoint_txs: Vec<Psbt>,
    ) -> Result<FinalizeOffchainTxResponse, Error> {
        let mut client = self.inner_ark_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let checkpoint_txs = checkpoint_txs
            .into_iter()
            .map(|tx| base64.encode(tx.serialize()))
            .collect();

        client
            .finalize_tx(generated::ark::v1::FinalizeTxRequest {
                ark_txid: txid.to_string(),
                final_checkpoint_txs: checkpoint_txs,
            })
            .await
            .map_err(Error::request)?;

        Ok(FinalizeOffchainTxResponse {})
    }

    pub async fn confirm_registration(&self, intent_id: String) -> Result<String, Error> {
        let mut client = self.inner_ark_client()?;

        let res = client
            .confirm_registration(ConfirmRegistrationRequest { intent_id })
            .await
            .map_err(Error::request)?;

        Ok(res.into_inner().blinded_creds)
    }

    pub async fn submit_tree_nonces(
        &self,
        batch_id: &str,
        cosigner_pubkey: PublicKey,
        pub_nonce_tree: Vec<Vec<Option<musig::PublicNonce>>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let pub_nonce_tree = tree::encode_tree(pub_nonce_tree).map_err(Error::conversion)?;

        client
            .submit_tree_nonces(SubmitTreeNoncesRequest {
                batch_id: batch_id.to_string(),
                pubkey: cosigner_pubkey.to_string(),
                tree_nonces: pub_nonce_tree.to_lower_hex_string(),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn submit_tree_signatures(
        &self,
        batch_id: &str,
        cosigner_pk: PublicKey,
        partial_sig_tree: Vec<Vec<Option<musig::PartialSignature>>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let tree_signatures = tree::encode_tree(partial_sig_tree).map_err(Error::conversion)?;

        client
            .submit_tree_signatures(SubmitTreeSignaturesRequest {
                batch_id: batch_id.to_string(),
                pubkey: cosigner_pk.to_string(),
                tree_signatures: tree_signatures.to_lower_hex_string(),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn submit_signed_forfeit_txs(
        &self,
        signed_forfeit_txs: Vec<Psbt>,
        signed_commitment_tx: Option<Psbt>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_commitment_tx = signed_commitment_tx
            .map(|tx| base64.encode(tx.serialize()))
            .unwrap_or_default();

        client
            .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                signed_forfeit_txs: signed_forfeit_txs
                    .iter()
                    .map(|psbt| base64.encode(psbt.serialize()))
                    .collect(),
                signed_commitment_tx,
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn get_event_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<RoundStreamEvent, Error>> + Unpin, Error> {
        let mut client = self.inner_ark_client()?;

        let response = client
            .get_event_stream(GetEventStreamRequest {})
            .await
            .map_err(Error::request)?;
        let mut stream = response.into_inner();

        let stream = stream! {
            loop {
                match stream.try_next().await {
                    Ok(Some(event)) => match event.event {
                        None => {
                            log::debug!("Got empty message");
                        }
                        Some(event) => {
                            yield Ok(RoundStreamEvent::try_from(event)?);
                        }
                    },
                    Ok(None) => {
                        yield Err(Error::event_stream_disconnect());
                    }
                    Err(e) => {
                        yield Err(Error::event_stream(e));
                    }
                }
            }
        };

        Ok(stream.boxed())
    }

    pub async fn get_tx_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<TransactionEvent, Error>> + Unpin, Error> {
        let mut client = self.inner_ark_client()?;

        let response = client
            .get_transactions_stream(GetTransactionsStreamRequest {})
            .await
            .map_err(Error::request)?;

        let mut stream = response.into_inner();

        let stream = stream! {
            loop {
                match stream.try_next().await {
                    Ok(Some(event)) => match event.tx {
                        None => {
                            log::debug!("Got empty message");
                        }
                        Some(event) => {
                            yield Ok(TransactionEvent::try_from(event)?);
                        }
                    },
                    Ok(None) => {
                        yield Err(Error::event_stream_disconnect());
                    }
                    Err(e) => {
                        yield Err(Error::event_stream(e));
                    }
                }
            }
        };

        Ok(stream.boxed())
    }

    pub async fn get_vtxo_chain(
        &self,
        outpoint: Option<OutPoint>,
        size_and_index: Option<(i32, i32)>,
    ) -> Result<VtxoChainResponse, Error> {
        let mut client = self.inner_indexer_client()?;
        let response = client
            .get_vtxo_chain(generated::ark::v1::GetVtxoChainRequest {
                outpoint: outpoint.map(|o| generated::ark::v1::IndexerOutpoint {
                    txid: o.txid.to_string(),
                    vout: o.vout,
                }),
                page: size_and_index
                    .map(|(size, index)| generated::ark::v1::IndexerPageRequest { size, index }),
            })
            .await
            .map_err(Error::request)?;
        let response = response.into_inner();
        let result = response.try_into()?;
        Ok(result)
    }

    pub async fn get_virtual_txs(
        &self,
        txids: Vec<String>,
        size_and_index: Option<(i32, i32)>,
    ) -> Result<VirtualTxsResponse, Error> {
        let mut client = self.inner_indexer_client()?;
        let response = client
            .get_virtual_txs(generated::ark::v1::GetVirtualTxsRequest {
                txids,
                page: size_and_index
                    .map(|(size, index)| generated::ark::v1::IndexerPageRequest { size, index }),
            })
            .await
            .map_err(Error::request)?;
        let response = response.into_inner();
        let result = response.try_into()?;
        Ok(result)
    }

    fn inner_ark_client(&self) -> Result<ArkServiceClient<tonic::transport::Channel>, Error> {
        // Cloning an `ArkServiceClient<Channel>` is cheap.
        self.ark_client.clone().ok_or(Error::not_connected())
    }
    fn inner_indexer_client(
        &self,
    ) -> Result<IndexerServiceClient<tonic::transport::Channel>, Error> {
        self.indexer_client.clone().ok_or(Error::not_connected())
    }
}

impl TryFrom<generated::ark::v1::Tree> for TxTree {
    type Error = Error;

    fn try_from(value: generated::ark::v1::Tree) -> Result<Self, Self::Error> {
        let mut tree = TxTree::new();

        for (level_idx, level) in value.levels.into_iter().enumerate() {
            for (node_idx, node) in level.nodes.into_iter().enumerate() {
                let node = node.try_into()?;
                tree.insert(node, level_idx, node_idx);
            }
        }

        Ok(tree)
    }
}

impl TryFrom<generated::ark::v1::Node> for TxTreeNode {
    type Error = Error;

    fn try_from(value: generated::ark::v1::Node) -> Result<Self, Self::Error> {
        let txid: Txid = value.txid.parse().map_err(Error::conversion)?;

        let tx = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        )
        .decode(&value.tx)
        .map_err(Error::conversion)?;

        let tx = Psbt::deserialize(&tx).map_err(Error::conversion)?;

        let parent_txid: Txid = value.parent_txid.parse().map_err(Error::conversion)?;

        Ok(TxTreeNode {
            txid,
            tx,
            parent_txid,
            level: value.level,
            level_index: value.level_index,
            leaf: value.leaf,
        })
    }
}

impl TryFrom<generated::ark::v1::BatchStartedEvent> for BatchStartedEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::BatchStartedEvent) -> Result<Self, Self::Error> {
        Ok(BatchStartedEvent {
            id: value.id,
            intent_id_hashes: value.intent_id_hashes,
            batch_expiry: value.batch_expiry,
        })
    }
}

impl TryFrom<generated::ark::v1::BatchFinalizationEvent> for BatchFinalizationEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::BatchFinalizationEvent) -> Result<Self, Self::Error> {
        let base64 = &base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let commitment_tx = base64
            .decode(&value.commitment_tx)
            .map_err(Error::conversion)?;
        let commitment_tx = Psbt::deserialize(&commitment_tx).map_err(Error::conversion)?;

        let connectors_index = value
            .connectors_index
            .iter()
            .map(|(key, value)| {
                let key = {
                    let parts = key.split(':').collect::<Vec<_>>();

                    let txid = parts[0].parse().map_err(Error::conversion)?;
                    let vout = parts[1].parse().map_err(Error::conversion)?;

                    OutPoint { txid, vout }
                };

                let value = value.clone().try_into()?;

                Ok((key, value))
            })
            .collect::<Result<HashMap<OutPoint, OutPoint>, Error>>()?;

        Ok(BatchFinalizationEvent {
            id: value.id,
            commitment_tx,
            connectors_index,
        })
    }
}

impl TryFrom<generated::ark::v1::BatchFinalizedEvent> for BatchFinalizedEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::BatchFinalizedEvent) -> Result<Self, Self::Error> {
        let commitment_txid = value.commitment_txid.parse().map_err(Error::conversion)?;

        Ok(BatchFinalizedEvent {
            id: value.id,
            commitment_txid,
        })
    }
}

impl From<generated::ark::v1::BatchFailed> for BatchFailed {
    fn from(value: generated::ark::v1::BatchFailed) -> Self {
        BatchFailed {
            id: value.id,
            reason: value.reason,
        }
    }
}

impl TryFrom<generated::ark::v1::TreeSigningStartedEvent> for TreeSigningStartedEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TreeSigningStartedEvent) -> Result<Self, Self::Error> {
        let unsigned_commitment_tx = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        )
        .decode(&value.unsigned_commitment_tx)
        .map_err(Error::conversion)?;

        let unsigned_round_tx =
            Psbt::deserialize(&unsigned_commitment_tx).map_err(Error::conversion)?;

        Ok(TreeSigningStartedEvent {
            id: value.id,
            cosigners_pubkeys: value
                .cosigners_pubkeys
                .into_iter()
                .map(|pk| pk.parse().map_err(Error::conversion))
                .collect::<Result<Vec<_>, Error>>()?,
            unsigned_round_tx,
        })
    }
}

impl TryFrom<generated::ark::v1::TreeNoncesAggregatedEvent> for TreeNoncesAggregatedEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TreeNoncesAggregatedEvent) -> Result<Self, Self::Error> {
        let tree_nonces = crate::decode_tree(value.tree_nonces)?;

        Ok(TreeNoncesAggregatedEvent {
            id: value.id,
            tree_nonces,
        })
    }
}

impl TryFrom<generated::ark::v1::TreeTxEvent> for TreeTxEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TreeTxEvent) -> Result<Self, Self::Error> {
        let tree_tx = value.tree_tx.map(|t| t.try_into()).transpose()?;

        let batch_tree_event_type = match value.batch_index {
            0 => BatchTreeEventType::Vtxo,
            1 => BatchTreeEventType::Connector,
            n => return Err(Error::conversion(format!("unsupported batch index: {n}"))),
        };

        Ok(Self {
            id: value.id,
            topic: value.topic,
            batch_tree_event_type,
            tree_tx,
        })
    }
}

impl TryFrom<generated::ark::v1::TreeSignatureEvent> for TreeSignatureEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TreeSignatureEvent) -> Result<Self, Self::Error> {
        let batch_tree_event_type = match value.batch_index {
            0 => BatchTreeEventType::Vtxo,
            1 => BatchTreeEventType::Connector,
            n => return Err(Error::conversion(format!("unsupported batch index: {n}"))),
        };

        let signature = Vec::from_hex(&value.signature).map_err(Error::conversion)?;
        let signature = Signature::from_slice(&signature).map_err(Error::conversion)?;

        Ok(Self {
            id: value.id,
            topic: value.topic,
            batch_tree_event_type,
            level: value.level,
            level_index: value.level_index,
            signature,
        })
    }
}

impl TryFrom<generated::ark::v1::get_event_stream_response::Event> for RoundStreamEvent {
    type Error = Error;

    fn try_from(
        value: generated::ark::v1::get_event_stream_response::Event,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            generated::ark::v1::get_event_stream_response::Event::BatchStarted(e) => {
                RoundStreamEvent::BatchStarted(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::BatchFinalization(e) => {
                RoundStreamEvent::BatchFinalization(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::BatchFinalized(e) => {
                RoundStreamEvent::BatchFinalized(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::BatchFailed(e) => {
                RoundStreamEvent::BatchFailed(e.into())
            }
            generated::ark::v1::get_event_stream_response::Event::TreeSigningStarted(e) => {
                RoundStreamEvent::TreeSigningStarted(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::TreeNoncesAggregated(e) => {
                RoundStreamEvent::TreeNoncesAggregated(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::TreeTx(e) => {
                RoundStreamEvent::TreeTx(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::TreeSignature(e) => {
                RoundStreamEvent::TreeSignature(e.try_into()?)
            }
        })
    }
}

impl TryFrom<generated::ark::v1::get_transactions_stream_response::Tx> for TransactionEvent {
    type Error = Error;

    fn try_from(
        value: generated::ark::v1::get_transactions_stream_response::Tx,
    ) -> Result<Self, Self::Error> {
        match value {
            generated::ark::v1::get_transactions_stream_response::Tx::CommitmentTx(
                commitment_tx,
            ) => Ok(TransactionEvent::Round(CommitmentTransaction::try_from(
                commitment_tx,
            )?)),
            generated::ark::v1::get_transactions_stream_response::Tx::ArkTx(redeem) => Ok(
                TransactionEvent::Redeem(RedeemTransaction::try_from(redeem)?),
            ),
        }
    }
}

impl TryFrom<generated::ark::v1::TxNotification> for CommitmentTransaction {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TxNotification) -> Result<Self, Self::Error> {
        let spent_vtxos = value
            .spent_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let spendable_vtxos = value
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CommitmentTransaction {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            spent_vtxos,
            spendable_vtxos,
        })
    }
}

impl TryFrom<generated::ark::v1::TxNotification> for RedeemTransaction {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TxNotification) -> Result<Self, Self::Error> {
        let spent_vtxos = value
            .spent_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let spendable_vtxos = value
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RedeemTransaction {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            spent_vtxos,
            spendable_vtxos,
        })
    }
}

impl TryFrom<Outpoint> for OutPoint {
    type Error = Error;

    fn try_from(value: Outpoint) -> Result<Self, Self::Error> {
        let point = OutPoint {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            vout: value.vout,
        };
        Ok(point)
    }
}

pub struct VtxoChainResponse {
    pub chains: VtxoChains,
    pub depth: i32,
    pub page: Option<IndexerPage>,
}

pub struct VirtualTxsResponse {
    pub txs: Vec<Psbt>,
    pub page: Option<IndexerPage>,
}

pub struct IndexerPage {
    pub current: i32,
    pub next: i32,
    pub total: i32,
}

impl TryFrom<generated::ark::v1::GetVtxoChainResponse> for VtxoChainResponse {
    type Error = Error;

    fn try_from(value: generated::ark::v1::GetVtxoChainResponse) -> Result<Self, Self::Error> {
        let chains = value
            .chain
            .iter()
            .map(VtxoChain::try_from)
            .collect::<Result<Vec<_>, Error>>()?;

        let root_commitment_txid =
            Txid::from_str(value.root_commitment_txid.as_str()).map_err(Error::conversion)?;

        Ok(VtxoChainResponse {
            chains: VtxoChains {
                inner: chains,
                root_commitment_txid,
            },
            depth: value.depth,
            page: value
                .page
                .map(IndexerPage::try_from)
                .transpose()
                .map_err(Error::conversion)?,
        })
    }
}

impl TryFrom<generated::ark::v1::GetVirtualTxsResponse> for VirtualTxsResponse {
    type Error = Error;

    fn try_from(value: generated::ark::v1::GetVirtualTxsResponse) -> Result<Self, Self::Error> {
        let base64 = &base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let txs = value
            .txs
            .into_iter()
            // .map(|tx| bitcoin::consensus::encode::deserialize_hex(&tx).
            // map_err(Error::conversion))
            .map(|tx| {
                let bytes = base64.decode(&tx).map_err(Error::conversion)?;
                let psbt = Psbt::deserialize(&bytes).map_err(Error::conversion)?;

                Ok(psbt)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(VirtualTxsResponse {
            txs,
            page: value
                .page
                .map(IndexerPage::try_from)
                .transpose()
                .map_err(Error::conversion)?,
        })
    }
}

impl TryFrom<&generated::ark::v1::IndexerChain> for VtxoChain {
    type Error = Error;

    fn try_from(value: &generated::ark::v1::IndexerChain) -> Result<Self, Self::Error> {
        let spends = value
            .spends
            .iter()
            .map(ChainedTx::try_from)
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(VtxoChain {
            txid: value.txid.parse().map_err(Error::conversion)?,
            spends,
            expires_at: value.expires_at,
        })
    }
}

impl From<generated::ark::v1::IndexerPageResponse> for IndexerPage {
    fn from(value: generated::ark::v1::IndexerPageResponse) -> Self {
        IndexerPage {
            current: value.current,
            next: value.next,
            total: value.total,
        }
    }
}

impl TryFrom<&generated::ark::v1::IndexerChainedTx> for ChainedTx {
    type Error = Error;

    fn try_from(value: &generated::ark::v1::IndexerChainedTx) -> Result<Self, Self::Error> {
        let tx_type = match value.r#type {
            0 => ChainedTxType::Unspecified,
            1 => ChainedTxType::Virtual,
            2 => ChainedTxType::Commitment,
            n => {
                return Err(Error::conversion(format!(
                    "unsupported chained TX type: {n}"
                )))
            }
        };

        Ok(ChainedTx {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            tx_type,
        })
    }
}
