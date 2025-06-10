use crate::generated;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::explorer_service_client::ExplorerServiceClient;
use crate::generated::ark::v1::indexer_service_client::IndexerServiceClient;
use crate::generated::ark::v1::Bip322Signature;
use crate::generated::ark::v1::GetEventStreamRequest;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::GetRoundRequest;
use crate::generated::ark::v1::GetTransactionsStreamRequest;
use crate::generated::ark::v1::ListVtxosRequest;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::PingRequest;
use crate::generated::ark::v1::RegisterIntentRequest;
use crate::generated::ark::v1::SubmitRedeemTxRequest;
use crate::generated::ark::v1::SubmitSignedForfeitTxsRequest;
use crate::generated::ark::v1::SubmitTreeNoncesRequest;
use crate::generated::ark::v1::SubmitTreeSignaturesRequest;
use crate::tree;
use crate::Error;
use ark_core::proof_of_funds;
use ark_core::server::Info;
use ark_core::server::ListVtxo;
use ark_core::server::RedeemTransaction;
use ark_core::server::Round;
use ark_core::server::RoundFailedEvent;
use ark_core::server::RoundFinalizationEvent;
use ark_core::server::RoundFinalizedEvent;
use ark_core::server::RoundSigningEvent;
use ark_core::server::RoundSigningNoncesGeneratedEvent;
use ark_core::server::RoundStreamEvent;
use ark_core::server::RoundTransaction;
use ark_core::server::TransactionEvent;
use ark_core::server::TxTree;
use ark_core::server::TxTreeLevel;
use ark_core::server::TxTreeNode;
use ark_core::server::VtxoOutPoint;
use ark_core::ArkAddress;
use async_stream::stream;
use base64::Engine;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
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
    explorer_client: Option<ExplorerServiceClient<tonic::transport::Channel>>,
    indexer_client: Option<IndexerServiceClient<tonic::transport::Channel>>,
}

impl Client {
    pub fn new(url: String) -> Self {
        Self {
            url,
            ark_client: None,
            explorer_client: None,
            indexer_client: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        let ark_service_client = ArkServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;
        let explorer_client = ExplorerServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;
        let indexer_client = IndexerServiceClient::connect(self.url.clone())
            .await
            .map_err(Error::connect)?;

        self.ark_client = Some(ark_service_client);
        self.explorer_client = Some(explorer_client);
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

        let mut client = self.inner_explorer_client()?;

        let response = client
            .list_vtxos(ListVtxosRequest { address })
            .await
            .map_err(Error::request)?;

        let mut spent = response
            .get_ref()
            .spent_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut spendable = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut spent_by_redeem = Vec::new();
        for spendable_vtxo in spendable.clone() {
            let was_spent_by_redeem = spendable.iter().any(|v| {
                v.redeem_tx
                    .as_ref()
                    .map(|r| {
                        r.unsigned_tx
                            .input
                            .iter()
                            .any(|i| i.previous_output == spendable_vtxo.outpoint)
                    })
                    .unwrap_or_default()
            });

            if was_spent_by_redeem {
                spent_by_redeem.push(spendable_vtxo);
            }
        }

        // Remove "spendable" VTXOs that were actually already spent by a redeem transaction
        // from the list of spendable VTXOs.
        spendable.retain(|i| !spent_by_redeem.contains(i));

        // Add them to the list of spent VTXOs.
        spent.append(&mut spent_by_redeem);

        Ok(ListVtxo { spent, spendable })
    }

    pub async fn register_intent(
        &self,
        intent_message: &proof_of_funds::IntentMessage,
        proof: &proof_of_funds::Bip322Proof,
    ) -> Result<String, Error> {
        let mut client = self.inner_ark_client()?;

        let request = RegisterIntentRequest {
            bip322_signature: Some(Bip322Signature {
                signature: proof.serialize(),
                message: intent_message.encode().map_err(Error::conversion)?,
            }),
        };

        let response = client
            .register_intent(request)
            .await
            .map_err(Error::request)?;

        let request_id = response.into_inner().request_id;

        Ok(request_id)
    }

    pub async fn submit_redeem_transaction(&self, redeem_psbt: Psbt) -> Result<Psbt, Error> {
        let mut client = self.inner_ark_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let redeem_tx = base64.encode(redeem_psbt.serialize());

        let res = client
            .submit_redeem_tx(SubmitRedeemTxRequest { redeem_tx })
            .await
            .map_err(Error::request)?;

        let psbt = base64
            .decode(res.into_inner().signed_redeem_tx)
            .map_err(Error::conversion)?;
        let psbt = Psbt::deserialize(&psbt).map_err(Error::conversion)?;

        Ok(psbt)
    }

    pub async fn ping(&self, request_id: String) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        client
            .ping(PingRequest { request_id })
            .await
            .map_err(|e| Error::ping(e.message().to_string()))?;

        Ok(())
    }

    pub async fn submit_tree_nonces(
        &self,
        round_id: &str,
        cosigner_pubkey: PublicKey,
        pub_nonce_tree: Vec<Vec<Option<musig::PublicNonce>>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let pub_nonce_tree = tree::encode_tree(pub_nonce_tree).map_err(Error::conversion)?;

        client
            .submit_tree_nonces(SubmitTreeNoncesRequest {
                round_id: round_id.to_string(),
                pubkey: cosigner_pubkey.to_string(),
                tree_nonces: pub_nonce_tree.to_lower_hex_string(),
            })
            .await
            .map_err(Error::request)?;

        Ok(())
    }

    pub async fn submit_tree_signatures(
        &self,
        round_id: &str,
        cosigner_pk: PublicKey,
        partial_sig_tree: Vec<Vec<Option<musig::PartialSignature>>>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let tree_signatures = tree::encode_tree(partial_sig_tree).map_err(Error::conversion)?;

        client
            .submit_tree_signatures(SubmitTreeSignaturesRequest {
                round_id: round_id.to_string(),
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
        signed_round_psbt: Option<Psbt>,
    ) -> Result<(), Error> {
        let mut client = self.inner_ark_client()?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        client
            .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                signed_forfeit_txs: signed_forfeit_txs
                    .iter()
                    .map(|psbt| base64.encode(psbt.serialize()))
                    .collect(),
                signed_round_tx: signed_round_psbt.map(|p| base64.encode(p.serialize())),
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

    pub async fn get_round(&self, round_txid: String) -> Result<Option<Round>, Error> {
        let mut client = self.inner_explorer_client()?;

        let response = client
            .get_round(GetRoundRequest { txid: round_txid })
            .await
            .map_err(Error::request)?;

        let response = response.into_inner();

        let round = response.round.map(Round::try_from).transpose()?;

        Ok(round)
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

    fn inner_ark_client(&self) -> Result<ArkServiceClient<tonic::transport::Channel>, Error> {
        // Cloning an `ArkServiceClient<Channel>` is cheap.
        self.ark_client.clone().ok_or(Error::not_connected())
    }
    fn inner_explorer_client(
        &self,
    ) -> Result<ExplorerServiceClient<tonic::transport::Channel>, Error> {
        self.explorer_client.clone().ok_or(Error::not_connected())
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
        let levels = value
            .levels
            .into_iter()
            .map(|level| level.try_into())
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(TxTree { levels })
    }
}

impl TryFrom<generated::ark::v1::TreeLevel> for TxTreeLevel {
    type Error = Error;

    fn try_from(value: generated::ark::v1::TreeLevel) -> Result<Self, Self::Error> {
        let nodes = value
            .nodes
            .into_iter()
            .map(|node| node.try_into())
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(TxTreeLevel { nodes })
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
        })
    }
}

impl TryFrom<generated::ark::v1::RoundFinalizationEvent> for RoundFinalizationEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::RoundFinalizationEvent) -> Result<Self, Self::Error> {
        let base64 = &base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let vtxo_tree = value.vtxo_tree.unwrap_or_default().try_into()?;

        let round_tx = base64.decode(&value.round_tx).map_err(Error::conversion)?;

        let round_tx = Psbt::deserialize(&round_tx).map_err(Error::conversion)?;

        let connector_tree = TxTree::try_from(value.connectors.unwrap_or_default())?;

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

        Ok(RoundFinalizationEvent {
            id: value.id,
            round_tx,
            vtxo_tree,
            connector_tree,
            min_relay_fee_rate: value.min_relay_fee_rate,
            connectors_index,
        })
    }
}

impl TryFrom<generated::ark::v1::RoundFinalizedEvent> for RoundFinalizedEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::RoundFinalizedEvent) -> Result<Self, Self::Error> {
        let round_txid = value.round_txid.parse().map_err(Error::conversion)?;

        Ok(RoundFinalizedEvent {
            id: value.id,
            round_txid,
        })
    }
}

impl From<generated::ark::v1::RoundFailed> for RoundFailedEvent {
    fn from(value: generated::ark::v1::RoundFailed) -> Self {
        RoundFailedEvent {
            id: value.id,
            reason: value.reason,
        }
    }
}

impl TryFrom<generated::ark::v1::RoundSigningEvent> for RoundSigningEvent {
    type Error = Error;

    fn try_from(value: generated::ark::v1::RoundSigningEvent) -> Result<Self, Self::Error> {
        let unsigned_round_tx = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        )
        .decode(&value.unsigned_round_tx)
        .map_err(Error::conversion)?;

        let unsigned_vtxo_tree = value
            .unsigned_vtxo_tree
            .map(|tree| tree.try_into())
            .transpose()?;

        let unsigned_round_tx = Psbt::deserialize(&unsigned_round_tx).map_err(Error::conversion)?;

        Ok(RoundSigningEvent {
            id: value.id,
            cosigners_pubkeys: value
                .cosigners_pubkeys
                .into_iter()
                .map(|pk| pk.parse().map_err(Error::conversion))
                .collect::<Result<Vec<_>, Error>>()?,
            unsigned_vtxo_tree,
            unsigned_round_tx,
        })
    }
}

impl TryFrom<generated::ark::v1::RoundSigningNoncesGeneratedEvent>
    for RoundSigningNoncesGeneratedEvent
{
    type Error = Error;

    fn try_from(
        value: generated::ark::v1::RoundSigningNoncesGeneratedEvent,
    ) -> Result<Self, Self::Error> {
        let tree_nonces = crate::decode_tree(value.tree_nonces)?;

        Ok(RoundSigningNoncesGeneratedEvent {
            id: value.id,
            tree_nonces,
        })
    }
}

impl TryFrom<generated::ark::v1::get_event_stream_response::Event> for RoundStreamEvent {
    type Error = Error;

    fn try_from(
        value: generated::ark::v1::get_event_stream_response::Event,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            generated::ark::v1::get_event_stream_response::Event::RoundFinalization(e) => {
                RoundStreamEvent::RoundFinalization(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::RoundFinalized(e) => {
                RoundStreamEvent::RoundFinalized(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::RoundFailed(e) => {
                RoundStreamEvent::RoundFailed(e.into())
            }
            generated::ark::v1::get_event_stream_response::Event::RoundSigning(e) => {
                RoundStreamEvent::RoundSigning(e.try_into()?)
            }
            generated::ark::v1::get_event_stream_response::Event::RoundSigningNoncesGenerated(
                e,
            ) => RoundStreamEvent::RoundSigningNoncesGenerated(e.try_into()?),
        })
    }
}

impl TryFrom<generated::ark::v1::Round> for Round {
    type Error = Error;

    fn try_from(value: generated::ark::v1::Round) -> Result<Self, Self::Error> {
        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let round_tx = match value.round_tx.is_empty() {
            true => None,
            false => {
                let psbt = base64.decode(&value.round_tx).map_err(Error::conversion)?;
                Some(Psbt::deserialize(&psbt).map_err(Error::conversion)?)
            }
        };

        let vtxo_tree = value
            .vtxo_tree
            .map(TxTree::try_from)
            .transpose()
            .map_err(Error::conversion)?;

        let forfeit_txs = value
            .forfeit_txs
            .into_iter()
            .map(|t| {
                let psbt = base64.decode(&t).map_err(Error::conversion)?;
                let psbt = Psbt::deserialize(&psbt).map_err(Error::conversion)?;
                Ok(psbt)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let connector_tree = value
            .connectors
            .map(TxTree::try_from)
            .transpose()
            .map_err(Error::conversion)?;

        Ok(Round {
            id: value.id,
            start: value.start,
            end: value.end,
            round_tx,
            vtxo_tree,
            forfeit_txs,
            connector_tree,
            stage: value.stage,
        })
    }
}

impl TryFrom<generated::ark::v1::get_transactions_stream_response::Tx> for TransactionEvent {
    type Error = Error;

    fn try_from(
        value: generated::ark::v1::get_transactions_stream_response::Tx,
    ) -> Result<Self, Self::Error> {
        match value {
            generated::ark::v1::get_transactions_stream_response::Tx::Round(round) => {
                Ok(TransactionEvent::Round(RoundTransaction::try_from(round)?))
            }
            generated::ark::v1::get_transactions_stream_response::Tx::Redeem(redeem) => Ok(
                TransactionEvent::Redeem(RedeemTransaction::try_from(redeem)?),
            ),
        }
    }
}

impl TryFrom<generated::ark::v1::RoundTransaction> for RoundTransaction {
    type Error = Error;

    fn try_from(value: generated::ark::v1::RoundTransaction) -> Result<Self, Self::Error> {
        let spent_vtxos = value
            .spent_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let claimed_boarding_utxos = value
            .claimed_boarding_utxos
            .into_iter()
            .map(OutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let spendable_vtxos = value
            .spendable_vtxos
            .iter()
            .map(VtxoOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RoundTransaction {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            spent_vtxos,
            spendable_vtxos,
            claimed_boarding_utxos,
        })
    }
}

impl TryFrom<generated::ark::v1::RedeemTransaction> for RedeemTransaction {
    type Error = Error;

    fn try_from(value: generated::ark::v1::RedeemTransaction) -> Result<Self, Self::Error> {
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
    pub chain: Vec<VtxoChain>,
    pub depth: i32,
    pub root_commitment_txid: Txid,
    pub page: Option<IndexerPage>,
}

pub struct VtxoChain {
    pub txid: Txid,
    pub spends: Vec<ChainedTx>,
    pub expires_at: i64,
}

pub struct ChainedTx {
    pub txid: Txid,
    pub tx_type: i32,
}

pub struct IndexerPage {
    pub current: i32,
    pub next: i32,
    pub total: i32,
}

impl TryFrom<generated::ark::v1::GetVtxoChainResponse> for VtxoChainResponse {
    type Error = Error;

    fn try_from(value: generated::ark::v1::GetVtxoChainResponse) -> Result<Self, Self::Error> {
        let chain = value
            .chain
            .iter()
            .map(VtxoChain::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(VtxoChainResponse {
            chain,
            depth: value.depth,
            root_commitment_txid: Txid::from_str(value.root_commitment_txid.as_str())
                .map_err(Error::conversion)?,
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
        Ok(ChainedTx {
            txid: Txid::from_str(value.txid.as_str()).map_err(Error::conversion)?,
            tx_type: value.r#type,
        })
    }
}
