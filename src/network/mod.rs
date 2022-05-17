// Copyright 2022 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! The [`Mixnet`] struct implements the [`NetworkBehaviour`] trait. When used with a
//! [`libp2p_swarm::Swarm`], it will handle the mixnet protocol.

mod connection;
mod handler;
mod protocol;
mod worker;

pub use crate::network::worker::{WorkerOut, WorkerSink as WorkerSink2};
use crate::{
	core::{self, SurbsPayload},
	network::worker::WorkerIn,
	MixPublicKey, SendOptions,
};
use dyn_clone::DynClone;
use futures::{channel::mpsc::SendError, Sink, SinkExt, Stream, StreamExt};
use handler::Handler;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	dial_opts::{DialOpts, PeerCondition},
	CloseConnection, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
	NotifyHandler, PollParameters,
};
use std::{
	collections::{HashMap, VecDeque},
	task::{Context, Poll},
};
pub use worker::MixnetWorker;

pub type WorkerStream = Box<dyn Stream<Item = WorkerOut> + Unpin + Send>;
pub type WorkerSink = Box<dyn ClonableSink>;
pub type WorkerChannels = (worker::WorkerSink, worker::WorkerStream);

pub trait ClonableSink: Sink<WorkerIn, Error = SendError> + DynClone + Unpin + Send {}

impl<T> ClonableSink for T where T: Sink<WorkerIn, Error = SendError> + DynClone + Unpin + Send {}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	mixnet_worker_sink: WorkerSink,
	// TODO this stream is simply redirecting workers to a sink: TODO use it directly in worker
	mixnet_worker_stream: WorkerStream,
	// only to avoid two connection from same peer.
	connected: HashMap<PeerId, ConnectionId>,
	notify_queue: VecDeque<(PeerId, ConnectionId)>,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration.
	pub fn new(worker_in: WorkerSink, worker_out: WorkerStream) -> Self {
		Self {
			mixnet_worker_sink: worker_in,
			mixnet_worker_stream: worker_out,
			notify_queue: Default::default(),
			connected: Default::default(),
		}
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to the specified recipient.
	pub fn send(
		&mut self,
		to: crate::MixPeerId,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		self.mixnet_worker_sink
			.start_send_unpin(WorkerIn::RegisterMessage(Some(to), message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to a random recipient.
	pub fn send_to_random_recipient(
		&mut self,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		self.mixnet_worker_sink
			.start_send_unpin(WorkerIn::RegisterMessage(None, message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send surb reply.
	pub fn send_surb(
		&mut self,
		message: Vec<u8>,
		surb: SurbsPayload,
	) -> std::result::Result<(), core::Error> {
		self.mixnet_worker_sink
			.start_send_unpin(WorkerIn::RegisterSurbs(message, surb))
			.map_err(|_| core::Error::WorkerChannelFull)
	}
}

/// Event generated by the network behaviour.
#[derive(Debug)]
pub enum NetworkEvent {
	/// A new peer has connected and handshake.
	Connected(PeerId, MixPublicKey),

	/// A message has reached us.
	Message(DecodedMessage),

	/// Handle of a stream was dropped,
	/// this behavior cannot be use properly
	/// anymore.
	CloseStream,
}

/// Variant of message received.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageType {
	/// Message only.
	StandAlone,
	/// Message with a surb for reply.
	WithSurbs(SurbsPayload),
	/// Message from a surb reply (trusted), and initial query
	/// if stored.
	FromSurbs(Option<Vec<u8>>),
}

impl MessageType {
	/// can the message a surb reply.
	pub fn with_surb(&self) -> bool {
		matches!(self, &MessageType::WithSurbs(_))
	}

	/// Extract surb.
	pub fn surb(self) -> Option<SurbsPayload> {
		match self {
			MessageType::WithSurbs(surb) => Some(surb),
			_ => None,
		}
	}
}

/// A full mixnet message that has reached its recipient.
#[derive(Debug)]
pub struct DecodedMessage {
	/// The peer ID of the last hop that we have received the message from. This is not the message
	/// origin.
	pub peer: crate::MixPeerId,
	/// Message data.
	pub message: Vec<u8>,
	/// Message kind.
	pub kind: MessageType,
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = NetworkEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(handler::Config::new(), dyn_clone::clone_box(&*self.mixnet_worker_sink))
	}

	fn inject_event(&mut self, _: PeerId, _: ConnectionId, _: ()) {}

	fn inject_connection_established(
		&mut self,
		peer_id: &PeerId,
		con_id: &ConnectionId,
		_: &ConnectedPoint,
		_: Option<&Vec<Multiaddr>>,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		if !self.connected.contains_key(peer_id) {
			self.notify_queue.push_back((peer_id.clone(), con_id.clone()));
			self.connected.insert(peer_id.clone(), con_id.clone());
		}
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &PeerId,
		con_id: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
		if self.connected.get(peer_id) == Some(con_id) {
			self.connected.remove(peer_id);
		}
	}

	fn addresses_of_peer(&mut self, _peer: &PeerId) -> Vec<Multiaddr> {
		// TODO cache addresses for extend_addresses_through_behaviour
		vec![]
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		params: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		if let Some((id, connection)) = self.notify_queue.pop_front() {
			return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
				peer_id: id,
				handler: NotifyHandler::One(connection),
				event: id,
			})
		}

		match self.mixnet_worker_stream.poll_next_unpin(cx) {
			Poll::Ready(Some(out)) => match out {
				WorkerOut::Disconnected(peer_id) => {
					if let Some(con_id) = self.connected.remove(&peer_id) {
						Poll::Ready(NetworkBehaviourAction::CloseConnection {
							peer_id,
							connection: CloseConnection::One(con_id),
						})
					} else {
						self.poll(cx, params)
					}
				},
				WorkerOut::Connected(peer, public_key) =>
					Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::Connected(
						peer, public_key,
					))),
				WorkerOut::ReceivedMessage(peer, message, kind) =>
					Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::Message(
						DecodedMessage { peer, message, kind },
					))),
				WorkerOut::Dial(peer, addresses, reply) =>
					if !self.connected.contains_key(&peer) {
						let mut handler = self.new_handler();
						handler.set_peer_id(peer.clone());
						if let Some(reply) = reply {
							handler.set_established(reply);
						}
						Poll::Ready(NetworkBehaviourAction::Dial {
							opts: DialOpts::peer_id(peer)
								.condition(PeerCondition::Disconnected)
								.addresses(addresses)
								.extend_addresses_through_behaviour()
								.build(),
							handler,
						})
					} else {
						self.poll(cx, params)
					},
			},
			Poll::Ready(None) =>
				return Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::CloseStream)),
			Poll::Pending => Poll::Pending,
		}
	}
}
