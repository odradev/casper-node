//! A network message type used for communication between nodes

use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
};

use derive_more::From;
use fmt::Debug;
use futures::{future::BoxFuture, FutureExt};
use hex_fmt::HexFmt;
use serde::{Deserialize, Serialize};

use crate::{
    components::{
        consensus,
        fetcher::{FetchItem, FetchResponse, Tag},
        gossiper,
        network::{EstimatorWeights, FromIncoming, GossipedAddress, MessageKind, Payload},
    },
    effect::{
        incoming::{
            ConsensusDemand, ConsensusMessageIncoming, FinalitySignatureIncoming, GossiperIncoming,
            NetRequest, NetRequestIncoming, NetResponse, NetResponseIncoming, TrieDemand,
            TrieRequest, TrieRequestIncoming, TrieResponse, TrieResponseIncoming,
        },
        AutoClosingResponder, EffectBuilder,
    },
    types::{Block, Deploy, FinalitySignature, NodeId},
};

/// Reactor message.
#[derive(Clone, From, Serialize, Deserialize)]
pub(crate) enum Message {
    /// Consensus component message.
    #[from]
    Consensus(consensus::ConsensusMessage),
    /// Consensus component demand.
    #[from]
    ConsensusRequest(consensus::ConsensusRequestMessage),
    /// Block gossiper component message.
    #[from]
    BlockGossiper(gossiper::Message<Block>),
    /// Deploy gossiper component message.
    #[from]
    DeployGossiper(gossiper::Message<Deploy>),
    #[from]
    FinalitySignatureGossiper(gossiper::Message<FinalitySignature>),
    /// Address gossiper component message.
    #[from]
    AddressGossiper(gossiper::Message<GossipedAddress>),
    /// Request to get an item from a peer.
    GetRequest {
        /// The type tag of the requested item.
        tag: Tag,
        /// The serialized ID of the requested item.
        serialized_id: Vec<u8>,
    },
    /// Response to a `GetRequest`.
    GetResponse {
        /// The type tag of the contained item.
        tag: Tag,
        /// The serialized item.
        serialized_item: Arc<[u8]>,
    },
    /// Finality signature.
    #[from]
    FinalitySignature(Box<FinalitySignature>),
}

impl Payload for Message {
    #[inline]
    fn message_kind(&self) -> MessageKind {
        match self {
            Message::Consensus(_) => MessageKind::Consensus,
            Message::ConsensusRequest(_) => MessageKind::Consensus,
            Message::BlockGossiper(_) => MessageKind::BlockGossip,
            Message::DeployGossiper(_) => MessageKind::DeployGossip,
            Message::AddressGossiper(_) => MessageKind::AddressGossip,
            Message::GetRequest { tag, .. } | Message::GetResponse { tag, .. } => match tag {
                Tag::Deploy | Tag::LegacyDeploy => MessageKind::DeployTransfer,
                Tag::Block => MessageKind::BlockTransfer,
                Tag::BlockHeader => MessageKind::BlockTransfer,
                Tag::TrieOrChunk => MessageKind::TrieTransfer,
                Tag::FinalitySignature => MessageKind::Other,
                Tag::SyncLeap => MessageKind::BlockTransfer,
                Tag::ApprovalsHashes => MessageKind::BlockTransfer,
                Tag::BlockExecutionResults => MessageKind::BlockTransfer,
            },
            Message::FinalitySignature(_) => MessageKind::Consensus,
            Message::FinalitySignatureGossiper(_) => MessageKind::FinalitySignatureGossip,
        }
    }

    fn is_low_priority(&self) -> bool {
        // We only deprioritize requested trie nodes, as they are the most commonly requested item
        // during fast sync.
        match self {
            Message::Consensus(_) => false,
            Message::ConsensusRequest(_) => false,
            Message::DeployGossiper(_) => false,
            Message::BlockGossiper(_) => false,
            Message::FinalitySignatureGossiper(_) => false,
            Message::AddressGossiper(_) => false,
            Message::GetRequest { tag, .. } if *tag == Tag::TrieOrChunk => true,
            Message::GetRequest { .. } => false,
            Message::GetResponse { .. } => false,
            Message::FinalitySignature(_) => false,
        }
    }

    #[inline]
    fn incoming_resource_estimate(&self, weights: &EstimatorWeights) -> u32 {
        match self {
            Message::Consensus(_) => weights.consensus,
            Message::ConsensusRequest(_) => weights.consensus,
            Message::BlockGossiper(_) => weights.gossip,
            Message::DeployGossiper(_) => weights.gossip,
            Message::FinalitySignatureGossiper(_) => weights.gossip,
            Message::AddressGossiper(_) => weights.gossip,
            Message::GetRequest { tag, .. } => match tag {
                Tag::Deploy | Tag::LegacyDeploy => weights.deploy_requests,
                Tag::Block => weights.block_requests,
                Tag::BlockHeader => weights.block_requests,
                Tag::TrieOrChunk => weights.trie_requests,
                Tag::FinalitySignature => weights.gossip,
                Tag::SyncLeap => weights.block_requests,
                Tag::ApprovalsHashes => weights.block_requests,
                Tag::BlockExecutionResults => weights.block_requests,
            },
            Message::GetResponse { tag, .. } => match tag {
                Tag::Deploy | Tag::LegacyDeploy => weights.deploy_responses,
                Tag::Block => weights.block_responses,
                Tag::BlockHeader => weights.block_responses,
                Tag::TrieOrChunk => weights.trie_responses,
                Tag::FinalitySignature => weights.gossip,
                Tag::SyncLeap => weights.block_responses,
                Tag::ApprovalsHashes => weights.block_responses,
                Tag::BlockExecutionResults => weights.block_responses,
            },
            Message::FinalitySignature(_) => weights.finality_signatures,
        }
    }

    fn is_unsafe_for_syncing_peers(&self) -> bool {
        match self {
            Message::Consensus(_) => false,
            Message::ConsensusRequest(_) => false,
            Message::BlockGossiper(_) => false,
            Message::DeployGossiper(_) => false,
            Message::FinalitySignatureGossiper(_) => false,
            Message::AddressGossiper(_) => false,
            // Trie requests can deadlock between syncing nodes.
            Message::GetRequest { tag, .. } if *tag == Tag::TrieOrChunk => true,
            Message::GetRequest { .. } => false,
            Message::GetResponse { .. } => false,
            Message::FinalitySignature(_) => false,
        }
    }
}

impl Message {
    pub(crate) fn new_get_request<T: FetchItem>(id: &T::Id) -> Result<Self, bincode::Error> {
        Ok(Message::GetRequest {
            tag: T::TAG,
            serialized_id: bincode::serialize(id)?,
        })
    }

    pub(crate) fn new_get_response<T: FetchItem>(
        item: &FetchResponse<T, T::Id>,
    ) -> Result<Self, bincode::Error> {
        Ok(Message::GetResponse {
            tag: T::TAG,
            serialized_item: item.to_serialized()?.into(),
        })
    }

    /// Creates a new get response from already serialized data.
    pub(crate) fn new_get_response_from_serialized(tag: Tag, serialized_item: Arc<[u8]>) -> Self {
        Message::GetResponse {
            tag,
            serialized_item,
        }
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Message::Consensus(c) => f.debug_tuple("Consensus").field(&c).finish(),
            Message::ConsensusRequest(c) => f.debug_tuple("ConsensusRequest").field(&c).finish(),
            Message::BlockGossiper(dg) => f.debug_tuple("BlockGossiper").field(&dg).finish(),
            Message::DeployGossiper(dg) => f.debug_tuple("DeployGossiper").field(&dg).finish(),
            Message::FinalitySignatureGossiper(sig) => f
                .debug_tuple("FinalitySignatureGossiper")
                .field(&sig)
                .finish(),
            Message::AddressGossiper(ga) => f.debug_tuple("AddressGossiper").field(&ga).finish(),
            Message::GetRequest { tag, serialized_id } => f
                .debug_struct("GetRequest")
                .field("tag", tag)
                .field("serialized_item", &HexFmt(serialized_id))
                .finish(),
            Message::GetResponse {
                tag,
                serialized_item,
            } => f
                .debug_struct("GetResponse")
                .field("tag", tag)
                .field("serialized_item", &HexFmt(serialized_item))
                .finish(),
            Message::FinalitySignature(fs) => {
                f.debug_tuple("FinalitySignature").field(&fs).finish()
            }
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Message::Consensus(consensus) => write!(f, "Consensus::{}", consensus),
            Message::ConsensusRequest(consensus) => write!(f, "ConsensusRequest({})", consensus),
            Message::BlockGossiper(deploy) => write!(f, "BlockGossiper::{}", deploy),
            Message::DeployGossiper(deploy) => write!(f, "DeployGossiper::{}", deploy),
            Message::FinalitySignatureGossiper(sig) => {
                write!(f, "FinalitySignatureGossiper::{}", sig)
            }
            Message::AddressGossiper(gossiped_address) => {
                write!(f, "AddressGossiper::({})", gossiped_address)
            }
            Message::GetRequest { tag, serialized_id } => {
                write!(f, "GetRequest({}-{:10})", tag, HexFmt(serialized_id))
            }
            Message::GetResponse {
                tag,
                serialized_item,
            } => write!(f, "GetResponse({}-{:10})", tag, HexFmt(serialized_item)),
            Message::FinalitySignature(fs) => {
                write!(f, "FinalitySignature::({})", fs)
            }
        }
    }
}

impl<REv> FromIncoming<Message> for REv
where
    REv: From<ConsensusMessageIncoming>
        + From<ConsensusDemand>
        + From<GossiperIncoming<Block>>
        + From<GossiperIncoming<Deploy>>
        + From<GossiperIncoming<FinalitySignature>>
        + From<GossiperIncoming<GossipedAddress>>
        + From<NetRequestIncoming>
        + From<NetResponseIncoming>
        + From<TrieRequestIncoming>
        + From<TrieDemand>
        + From<TrieResponseIncoming>
        + From<FinalitySignatureIncoming>,
{
    fn from_incoming(sender: NodeId, payload: Message) -> Self {
        match payload {
            Message::Consensus(message) => ConsensusMessageIncoming { sender, message }.into(),
            Message::ConsensusRequest(_message) => {
                // TODO: Remove this once from_incoming and try_demand_from_incoming are unified.
                unreachable!("called from_incoming with a consensus request")
            }
            Message::BlockGossiper(message) => GossiperIncoming { sender, message }.into(),
            Message::DeployGossiper(message) => GossiperIncoming { sender, message }.into(),
            Message::FinalitySignatureGossiper(message) => {
                GossiperIncoming { sender, message }.into()
            }
            Message::AddressGossiper(message) => GossiperIncoming { sender, message }.into(),
            Message::GetRequest { tag, serialized_id } => match tag {
                Tag::Deploy => NetRequestIncoming {
                    sender,
                    message: NetRequest::Deploy(serialized_id),
                }
                .into(),
                Tag::LegacyDeploy => NetRequestIncoming {
                    sender,
                    message: NetRequest::LegacyDeploy(serialized_id),
                }
                .into(),
                Tag::Block => NetRequestIncoming {
                    sender,
                    message: NetRequest::Block(serialized_id),
                }
                .into(),
                Tag::BlockHeader => NetRequestIncoming {
                    sender,
                    message: NetRequest::BlockHeader(serialized_id),
                }
                .into(),
                Tag::TrieOrChunk => TrieRequestIncoming {
                    sender,
                    message: TrieRequest(serialized_id),
                }
                .into(),
                Tag::FinalitySignature => NetRequestIncoming {
                    sender,
                    message: NetRequest::FinalitySignature(serialized_id),
                }
                .into(),
                Tag::SyncLeap => NetRequestIncoming {
                    sender,
                    message: NetRequest::SyncLeap(serialized_id),
                }
                .into(),
                Tag::ApprovalsHashes => NetRequestIncoming {
                    sender,
                    message: NetRequest::ApprovalsHashes(serialized_id),
                }
                .into(),
                Tag::BlockExecutionResults => NetRequestIncoming {
                    sender,
                    message: NetRequest::BlockExecutionResults(serialized_id),
                }
                .into(),
            },
            Message::GetResponse {
                tag,
                serialized_item,
            } => match tag {
                Tag::Deploy => NetResponseIncoming {
                    sender,
                    message: NetResponse::Deploy(serialized_item),
                }
                .into(),
                Tag::LegacyDeploy => NetResponseIncoming {
                    sender,
                    message: NetResponse::LegacyDeploy(serialized_item),
                }
                .into(),
                Tag::Block => NetResponseIncoming {
                    sender,
                    message: NetResponse::Block(serialized_item),
                }
                .into(),
                Tag::BlockHeader => NetResponseIncoming {
                    sender,
                    message: NetResponse::BlockHeader(serialized_item),
                }
                .into(),
                Tag::TrieOrChunk => TrieResponseIncoming {
                    sender,
                    message: TrieResponse(serialized_item.to_vec()),
                }
                .into(),
                Tag::FinalitySignature => NetResponseIncoming {
                    sender,
                    message: NetResponse::FinalitySignature(serialized_item),
                }
                .into(),
                Tag::SyncLeap => NetResponseIncoming {
                    sender,
                    message: NetResponse::SyncLeap(serialized_item),
                }
                .into(),
                Tag::ApprovalsHashes => NetResponseIncoming {
                    sender,
                    message: NetResponse::ApprovalsHashes(serialized_item),
                }
                .into(),
                Tag::BlockExecutionResults => NetResponseIncoming {
                    sender,
                    message: NetResponse::BlockExecutionResults(serialized_item),
                }
                .into(),
            },
            Message::FinalitySignature(message) => {
                FinalitySignatureIncoming { sender, message }.into()
            }
        }
    }

    fn try_demand_from_incoming(
        effect_builder: EffectBuilder<REv>,
        sender: NodeId,
        payload: Message,
    ) -> Result<(Self, BoxFuture<'static, Option<Message>>), Message>
    where
        Self: Sized + Send,
    {
        match payload {
            Message::GetRequest { tag, serialized_id } if tag == Tag::TrieOrChunk => {
                let (ev, fut) = effect_builder.create_request_parts(move |responder| TrieDemand {
                    sender,
                    request_msg: TrieRequest(serialized_id),
                    auto_closing_responder: AutoClosingResponder::from_opt_responder(responder),
                });

                Ok((ev, fut.boxed()))
            }
            Message::ConsensusRequest(request_msg) => {
                let (ev, fut) =
                    effect_builder.create_request_parts(move |responder| ConsensusDemand {
                        sender,
                        request_msg,
                        auto_closing_responder: AutoClosingResponder::from_opt_responder(responder),
                    });

                Ok((ev, fut.boxed()))
            }
            _ => Err(payload),
        }
    }
}
