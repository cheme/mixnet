// Copyright 2022 Parity Technologies (UK), .. Ltd.
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

//! The [`MixnetBehaviour`] struct implements the [`NetworkBehaviour`] trait. When used with a
//! [`libp2p_swarm::Swarm`], it will handle the mixnet protocol.

mod handler;
mod protocol;

use crate::{
	core::{Config, Mixnet, MixnetEvent, Packet},
	traits::Configuration,
	DecodedMessage, MixPublicKey, NetworkId,
};
use futures::FutureExt;
use futures_timer::Delay;
use handler::{Failure, Handler};
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use std::{
	collections::VecDeque,
	task::{Context, Poll},
	time::Duration,
};

type Result = std::result::Result<Packet, Failure>;

/// Internal information tracked for an established connection.
/// TODO replace by managed connection (remove)
struct Connection {
	id: ConnectionId,
	_address: Option<Multiaddr>,
	read_timeout: Delay,
}

impl Connection {
	fn new(id: ConnectionId, address: Option<Multiaddr>) -> Self {
		Self { id, _address: address, read_timeout: Delay::new(Duration::new(2, 0)) }
	}
}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	mixnet: Mixnet,
	events: VecDeque<MixnetEvent>,
	public_key: MixPublicKey,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration.
	pub fn new(config: Config, topology: Box<dyn Configuration>) -> Self {
		Self {
			public_key: config.public_key.clone(),
			mixnet: Mixnet::new(config, topology),
			events: Default::default(),
		}
	}

	/// access inner mixnet read only.
	pub fn mixnet(&mut self) -> &Mixnet {
		&self.mixnet
	}

	/// access inner mixnet mutable.
	pub fn mixnet_mut(&mut self) -> &mut Mixnet {
		&mut self.mixnet
	}
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = MixnetEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(handler::Config::new())
	}

	fn inject_event(&mut self, peer_id: PeerId, _: ConnectionId, event: Result) {
		match event {
			Ok(packet) => {
				log::trace!(target: "mixnet", "Incoming message from {:?}", peer_id);
				if let Ok(Some(((message, kind), peer))) =
					self.mixnet.import_message(peer_id, packet)
				{
					self.events.push_front(MixnetEvent::Message(DecodedMessage {
						peer,
						message,
						kind,
					}))
				}
			},
			Err(e) => {
				log::trace!(target: "mixnet", "Network error: {}", e);
			},
		}
	}

	fn inject_connection_established(
		&mut self,
		peer_id: &NetworkId,
		con_id: &ConnectionId,
		endpoint: &ConnectedPoint,
		_: Option<&Vec<Multiaddr>>,
		_: usize,
	) {
		if self.mixnet().has_connection(peer_id) {
			log::trace!(target: "mixnet", "Duplicate connection: {}", peer_id);
			return
		}
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		let address = match endpoint {
			ConnectedPoint::Dialer { address, .. } => Some(address.clone()),
			ConnectedPoint::Listener { .. } => None,
		};
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		self.mixnet_mut().insert_connection(*peer_id);
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &NetworkId,
		_: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
		self.mixnet.remove_connected_peer(peer_id);
	}
	/*
		fn inject_disconnected(&mut self, peer_id: &PeerId) {
			log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
			self.handshakes.remove(peer_id);
			self.mixnet.remove_connected_peer(peer_id);
			if self.connected.remove(peer_id).is_some() {
				self.events.push_back(NetworkEvent::Disconnected(peer_id.clone()));
			}
		}
	*/
	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		_: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		// TODO check if this events queue is used
		if let Some(e) = self.events.pop_back() {
			return Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
		}

		match self.mixnet.poll_unpin(cx) {
			Poll::Ready(e) => return Poll::Ready(NetworkBehaviourAction::GenerateEvent(e)),
			Poll::Pending => Poll::Pending,
		}
	}
}
