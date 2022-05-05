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

mod handler;
mod protocol;
mod worker;

use crate::{
	core::{self, SurbsPayload},
	network::worker::{WorkerIn, WorkerOut},
	MixPublicKey, SendOptions,
};
use dyn_clone::DynClone;
use futures::{channel::mpsc::SendError, Sink, Stream};
use handler::Handler;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use std::{
	collections::VecDeque,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};
pub use worker::MixnetWorker;

pub const WINDOW_BACKPRESSURE: Duration = Duration::from_secs(5);

pub type WorkerStream = Box<dyn Stream<Item = WorkerOut> + Unpin + Send>;
pub type WorkerSink = Box<dyn ClonableSink>;
pub type WorkerChannels = (worker::WorkerSink, worker::WorkerStream);

pub trait ClonableSink: Sink<WorkerIn, Error = SendError> + DynClone + Unpin + Send {}

impl<T> ClonableSink for T where T: Sink<WorkerIn, Error = SendError> + DynClone + Unpin + Send {}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	mixnet_worker_sink: WorkerSink,
	// TODO this is only redirecting to worker: just create a worker handle struct from it (no need
	// to be in behaviour). 
	pinned_mixnet_worker_sink: Pin<WorkerSink>,
	// TODO this stream is simply redirecting workers to a sink: TODO use it directly in worker
	mixnet_worker_stream: Pin<WorkerStream>,
	notify_queue: VecDeque<(PeerId, ConnectionId)>,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration.
	pub fn new(worker_in: WorkerSink, worker_out: WorkerStream) -> Self {
		Self {
			pinned_mixnet_worker_sink: Pin::new(dyn_clone::clone_box(&*worker_in)),
			mixnet_worker_sink: worker_in,
			mixnet_worker_stream: Pin::new(worker_out),
			notify_queue: Default::default(),
		}
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to the specified recipient.
	pub fn send(
		&mut self,
		to: PeerId,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		self.pinned_mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterMessage(Some(to), message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to a random recipient.
	pub fn send_to_random_recipient(
		&mut self,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		self.pinned_mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterMessage(None, message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send surbs reply.
	pub fn send_surbs(
		&mut self,
		message: Vec<u8>,
		surbs: SurbsPayload,
	) -> std::result::Result<(), core::Error> {
		self.pinned_mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterSurbs(message, surbs))
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
	/// Message with a surbs for reply.
	WithSurbs(SurbsPayload),
	/// Message from a surbs reply (trusted), and initial query
	/// if stored.
	FromSurbs(Option<Vec<u8>>),
}

impl MessageType {
	/// can the message a surbs reply.
	pub fn with_surbs(&self) -> bool {
		matches!(self, &MessageType::WithSurbs(_))
	}

	/// Extract surbs.
	pub fn surbs(self) -> Option<SurbsPayload> {
		match self {
			MessageType::WithSurbs(surbs) => Some(surbs),
			_ => None,
		}
	}
}

/// A full mixnet message that has reached its recipient.
#[derive(Debug)]
pub struct DecodedMessage {
	/// The peer ID of the last hop that we have received the message from. This is not the message
	/// origin.
	pub peer: PeerId,
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
		self.notify_queue.push_back((peer_id.clone(), con_id.clone()));
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &PeerId,
		_conn: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		_: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		if let Some((id, connection)) = self.notify_queue.pop_front() {
			return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
				peer_id: id,
				handler: NotifyHandler::One(connection),
				event: id,
			})
		}

		match self.mixnet_worker_stream.as_mut().poll_next(cx) {
			Poll::Ready(Some(out)) => match out {
				WorkerOut::Connected(peer, public_key) =>
					return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
						NetworkEvent::Connected(peer, public_key),
					)),
				WorkerOut::ReceivedMessage(peer, message, kind) =>
					return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
						NetworkEvent::Message(DecodedMessage { peer, message, kind }),
					)),
			},
			Poll::Ready(None) =>
				return Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::CloseStream)),
			Poll::Pending => Poll::Pending,
		}
	}
}
