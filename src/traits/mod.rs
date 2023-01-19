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

//! Mixnet topology interface.

pub mod hash_table;
pub mod set;

use crate::{Error, MixPublicKey, MixnetId, NetworkId, PeerCount, WindowStats};
use ambassador::delegatable_trait;
use dyn_clone::DynClone;
use futures::{channel::mpsc::SendError, Sink};
use std::{
	collections::BTreeSet,
	marker::Unpin,
	task::{Context, Poll},
};

pub use crate::WorkerCommand;
pub use hash_table::TopologyHashTable;

pub trait ClonableSink: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}
impl<T> ClonableSink for T where T: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}

/// Provide Configuration of mixnet.
pub trait Configuration: Topology + Unpin + Sized + Send + 'static {
	/// Do we need stats for each windows.
	fn collect_windows_stats(&self) -> bool;

	/// Callback on windows stats.
	fn window_stats(&self, stats: &WindowStats, connection: &PeerCount);

	/// Callback on connection stats.
	fn peer_stats(&self, stats: &PeerCount);
}

/// Provide network topology information to the mixnet.
#[delegatable_trait]
pub trait Topology: Sized {
	/// Check if a peer is in topology, do not need to be connected.
	fn can_route(&self, id: &MixnetId) -> bool;

	/// first hop nodes that may currently allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixnetId,
		_to: Option<&MixnetId>,
		_num_hop: usize,
	) -> Vec<(MixnetId, MixPublicKey)>;

	/// Allow prioritizing some external messages.
	fn can_add_external_message(
		&self,
		_id: &MixnetId,
		queue_size: usize,
		queue_limit: usize,
	) -> bool {
		queue_size <= queue_limit
	}

	/// Check node links.
	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool;

	/// Random message path.
	/// When recipient is undefined, a random recipient among reachable
	/// routing peers is used.
	///	E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// `recipient_node` is part of the returned path, not `start_node`.
	/// Error when no recipient is reachable.
	fn random_path( // TODO random_paths
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		count: usize,
		num_hops: usize,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error>;

	/// On connection successful handshake.
	/// TODO could pass connectionkind to simplify code
	fn connected(&mut self, id: MixnetId, public_key: MixPublicKey);

	/// On disconnect.
	/// TODO could pass connectionkind to simplify code
	fn disconnected(&mut self, id: &MixnetId);

	/// On topology change, might have existing peer changed, return a list of these peers.
	/// Call to this function return the new peers only once and should
	/// be costless when no change occurs.
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>>;

	/// A new static routing set was globally defined.
	fn handle_new_routing_set(&mut self, set: NewRoutingSet);

	/// Obtain a mixnet id from a network id if in topology.
	fn get_mixnet_id(&self, network_id: &NetworkId) -> Option<MixnetId>;
	// TODO handle new id and key.
}

/// A current routing set of peers.
/// Two variant given other info will be shared.
pub struct NewRoutingSet<'a> {
	pub peers: &'a [(MixnetId, MixPublicKey, NetworkId)],
}

/// No topology try direct connection.
pub struct NoTopology {
	pub connected_peers: std::collections::HashMap<MixnetId, MixPublicKey>,
}

impl Topology for NoTopology {
	fn can_route(&self, _id: &MixnetId) -> bool {
		false
	}

	fn random_path(
		&mut self,
		from: (&MixnetId, Option<&MixPublicKey>),
		recipient: Option<(&MixnetId, Option<&MixPublicKey>)>,
		count: usize,
		_num_hops: usize,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		log::warn!(target: "mixnet", "No topology, direct transmission");

		let recipient = recipient.or_else(|| {
			use rand::prelude::IteratorRandom;
			let mut rng = rand::thread_rng();
			// Select a random connected peer
			self.connected_peers
				.iter()
				.filter(|(k, _v)| k != &from.0)
				.choose(&mut rng)
				.map(|(k, v)| (k, Some(v)))
		});
		let recipient = if let Some(recipient) = recipient {
			recipient
		} else {
			return Err(Error::NoPath(None))
		};

		// No topology is defined. Check if direct connection is possible.
		match self.connected_peers.get(recipient.0) {
			Some(key) => Ok(vec![vec![(*recipient.0, *key)]; count]),
			_ => Err(Error::NoPath(Some(*recipient.0))),
		}
	}

	// first hop that allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixnetId,
		_to: Option<&MixnetId>,
		_num_hop: usize,
	) -> Vec<(MixnetId, MixPublicKey)> {
		Vec::new()
	}

	fn routing_to(&self, _from: &MixnetId, _to: &MixnetId) -> bool {
		true
	}

	fn connected(&mut self, id: MixnetId, key: MixPublicKey) {
		self.connected_peers.insert(id, key);
	}

	fn disconnected(&mut self, id: &MixnetId) {
		self.connected_peers.remove(id);
	}

	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		None
	}

	fn handle_new_routing_set(&mut self, _set: NewRoutingSet) {}

	fn get_mixnet_id(&self, _network_id: &NetworkId) -> Option<MixnetId> {
		None
	}
}

impl Configuration for NoTopology {
	fn collect_windows_stats(&self) -> bool {
		false
	}

	fn window_stats(&self, _: &WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

/// Primitives needed from a network connection.
///
/// TODO consider removing the trait (only here to avoid intermodule
/// dependencies).
pub trait Connection: Unpin {
	/// Is queue empty and connection ready for next message.
	fn can_queue_send(&self) -> bool;

	/// Queue a message, `can_queue_send` must be `true`.
	fn queue_send(&mut self, header: Option<u8>, message: Vec<u8>);

	/// Send and flush, return true when queued message is written and flushed.
	/// Return false if ignored (no queued message).
	/// Return Error if connection broke.
	fn send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>>;

	/// Try receive a packet, size is always `PACKET_SIZE`.
	fn try_recv(&mut self, cx: &mut Context) -> Poll<Result<Option<Vec<u8>>, ()>>;
}
