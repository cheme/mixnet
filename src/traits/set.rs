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

//! Topology of a set of peers all connected to each others.
//! And accepting any external connections.

use crate::{
	traits::{NewRoutingSet, Topology},
	Error, MixPublicKey, MixnetId, NetworkId,
};
use log::debug;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Configuaration for this hash table.
/// Allows to use table from external source.
pub trait Configuration {
	/// Minimal number of node for accepting to add new message.
	const LOW_MIXNET_THRESHOLD: usize;

	/// Percent of additional bandwidth allowed for external
	/// node message reception.
	const EXTERNAL_BANDWIDTH: (usize, usize);
}

/// A topology where connections all peers of a set
/// are considered online and connected with each others.
pub struct TopologySet<C: Configuration> {
	local_id: MixnetId,

	// true when we are in routing set.
	routing: bool,

	// A view over locally connected nodes from
	// the routing set.
	connected_nodes: HashSet<MixnetId>,

	routing_set: Vec<(MixnetId, MixPublicKey)>,

	// node from a past routing set that did exit it.
	changed_routing: BTreeSet<MixnetId>,

	routing_peers_id: BTreeMap<MixnetId, usize>,

	routing_peers_network: BTreeMap<NetworkId, usize>,

	skip_buf: Vec<usize>,

	_ph: std::marker::PhantomData<C>,
}

impl<C: Configuration> Topology for TopologySet<C> {
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		(!self.changed_routing.is_empty()).then(|| std::mem::take(&mut self.changed_routing))
	}

	fn first_hop_nodes_external(
		&self,
		from: &MixnetId,
		to: Option<&MixnetId>,
		_num_hops: usize,
	) -> Vec<(MixnetId, MixPublicKey)> {
		// allow for all
		self.routing_set
			.iter()
			.filter(|id| from != &id.0)
			.filter(|id| to != Some(&id.0))
			.filter(|id| &self.local_id != &id.0)
			.filter(|id| self.connected_nodes.contains(&id.0))
			.map(|id| (id.0, id.1))
			.collect()
	}

	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool {
		self.routing_peers_id.contains_key(from) && self.routing_peers_id.contains_key(to)
	}

	fn random_path(
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		nb_chunk: usize,
		num_hops: usize,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		if !self.has_enough_nodes_to_send() {
			debug!(target: "mixnet", "Not enough routing nodes for path.");
			return Err(Error::NotEnoughRoutingPeers)
		}

		let mut rng = rand::thread_rng();
		let start_ix = if let Some(ix) = self.routing_peers_id.get(start_node.0) {
			*ix
		} else {
			return Err(Error::NoPath(Some(*start_node.0)))
		};
		self.skip_buf.clear();
		self.skip_buf.push(start_ix);
		let recipient_ix = if let Some(recipient) = recipient_node {
			if let Some(ix) = self.routing_peers_id.get(recipient.0) {
				*ix
			} else {
				return Err(Error::NoPath(Some(*recipient.0)))
			}
		} else {
			if let Some(ix) = self.random_peer(&mut rng, &self.skip_buf[..]) {
				ix
			} else {
				return Err(Error::NoPath(None))
			}
		};
		self.skip_buf.push(recipient_ix);
		self.skip_buf.sort();
		let mut result = Vec::with_capacity(nb_chunk);
		while result.len() < nb_chunk {
			let mut path_ids = Vec::with_capacity(num_hops);
			path_ids.push(self.routing_set[start_ix].clone());
			while path_ids.len() < num_hops - 1 {
				if let Some(ix) = self.random_peer(&mut rng, &self.skip_buf[..]) {
					self.skip_buf.push(recipient_ix);
					self.skip_buf.sort();
					path_ids.push(self.routing_set[ix].clone());
				} else {
					return Err(Error::NoPath(None))
				}
			}
			path_ids.push(self.routing_set[recipient_ix].clone());
			result.push(path_ids);
		}
		debug!(target: "mixnet", "Path: {:?}", result);
		Ok(result)
	}

	fn can_route(&self, id: &MixnetId) -> bool {
		if &self.local_id == id {
			self.routing
		} else {
			self.routing_peers_id.contains_key(id)
		}
	}

	fn connected(&mut self, peer_id: MixnetId, _key: MixPublicKey) {
		debug!(target: "mixnet", "Connected from internal");
		self.add_connected_peer(peer_id);
	}

	fn disconnected(&mut self, peer_id: &MixnetId) {
		debug!(target: "mixnet", "Disconnected from internal");
		self.add_disconnected_peer(peer_id);
	}

	fn handle_new_routing_set(&mut self, set: NewRoutingSet) {
		let mut old_set = std::mem::take(&mut self.routing_peers_id);
		*self = Self::new(self.local_id);
		for (mixnet_id, mix_public_key, network_id) in set.peers {
			old_set.remove(mixnet_id);

			if mixnet_id == &self.local_id {
				self.routing = true;
			}
			let ix = self.routing_set.len();

			self.routing_peers_id.insert(*mixnet_id, ix);
			self.routing_peers_network.insert(*network_id, ix);
			self.routing_set.push((*mixnet_id, *mix_public_key));
		}
		for (id, _) in old_set.into_iter() {
			self.changed_routing.insert(id);
		}
	}

	fn get_mixnet_id(&self, network_id: &NetworkId) -> Option<MixnetId> {
		self.routing_peers_network
			.get(network_id)
			.and_then(|ix| self.routing_set.get(*ix).map(|i| i.0))
	}
}

impl<C: Configuration> TopologySet<C> {
	/// Instantiate a new topology.
	pub fn new(local_id: MixnetId) -> Self {
		TopologySet {
			local_id,
			routing: false,
			connected_nodes: HashSet::new(),
			routing_set: Vec::new(),
			changed_routing: BTreeSet::new(),
			routing_peers_id: BTreeMap::new(),
			routing_peers_network: BTreeMap::new(),
			skip_buf: Vec::new(),
			_ph: std::marker::PhantomData,
		}
	}

	fn random_peer(&self, rng: &mut rand::rngs::ThreadRng, sorted_skip: &[usize]) -> Option<usize> {
		use rand::Rng;
		let nb = self.routing_set.len() - sorted_skip.len();
		let ix: usize = match nb {
			l if l <= u8::MAX as usize => rng.gen::<u8>() as usize,
			l if l <= u16::MAX as usize => rng.gen::<u16>() as usize,
			l if l <= u32::MAX as usize => rng.gen::<u32>() as usize,
			_ => rng.gen::<usize>(),
		};
		let mut ix = ix % nb;
		for i in sorted_skip {
			if ix >= *i {
				ix += 1;
			} else {
				break
			}
		}
		if ix >= nb {
			None
		} else {
			Some(ix)
		}
	}

	fn has_enough_nodes_to_send(&self) -> bool {
		// all nodes are seen as live.
		self.routing_set.len() >= C::LOW_MIXNET_THRESHOLD
	}

	/// Is peer able to proxy.
	pub fn has_enough_nodes_to_proxy(&self) -> bool {
		self.routing_set.len() >= C::LOW_MIXNET_THRESHOLD
	}

	pub fn add_connected_peer(&mut self, peer_id: MixnetId) {
		debug!(target: "mixnet", "Connected to mixnet {:?}", peer_id);
		if self.connected_nodes.contains(&peer_id) {
			return
		}
		self.connected_nodes.insert(peer_id);
	}

	fn add_disconnected_peer(&mut self, peer_id: &MixnetId) {
		debug!(target: "mixnet", "Disconnected from mixnet {:?}", peer_id);
		self.connected_nodes.remove(peer_id);
	}

	/// Returns the mixnet peer id of our node.
	pub fn local_id(&self) -> &MixnetId {
		&self.local_id
	}
}
