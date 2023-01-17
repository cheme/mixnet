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

//! Topology where direct peers are resolved
//! by hashing peers id (so randomly distributed).

use crate::{
	traits::{NewRoutingSet, ShouldConnectTo, Topology},
	Error, MixPublicKey, MixnetId, NetworkId, PeerCount,
};
use log::{debug, error, trace};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Configuaration for this hash table.
/// Allows to use table from external source.
pub trait Configuration {
	/// Minimal number of node for accepting to add new message.
	const LOW_MIXNET_THRESHOLD: usize;

	/// Minimal number of paths for sending to recipient.
	const LOW_MIXNET_PATHS: usize;

	/// Number of connection a routing peer should have active (with
	/// constant message bandwidth).
	const NUMBER_CONNECTED_FORWARD: usize;

	/// Split routing set in different layers.
	/// Layers are connected with next layer and last layer is connected
	/// with first.
	/// If no or single layer, just connect peers between themselve in
	/// an single routing set.
	const NUMBER_LAYER: u8;

	/// Minimal size for a layer, this can lower the number of layer when
	/// not enough peers in routing set.
	const MIN_LAYER_SIZE: usize;

	// Since hashing routed, should be same as NUMBER_CONNECTED_BACKWARD,
	// just we allow some lower value for margin.
	const NUMBER_CONNECTED_BACKWARD: usize;

	/// Percent of additional bandwidth allowed for external
	/// node message reception.
	const EXTERNAL_BANDWIDTH: (usize, usize);

	/// Default parameters for the topology.
	const DEFAULT_PARAMETERS: Parameters;
}

/// Configuration parameters for topology.
#[derive(Clone)]
pub struct Parameters {
	// limit to external connection
	pub max_external: Option<usize>,

	// When running as external number of consumer connection
	// with validator to try to maintain.
	pub number_consumer_connection: Option<usize>,
}

pub trait TableVersion: Default + Clone + Eq + PartialEq + Ord + std::fmt::Debug + 'static {
	/// Associated table content did change.
	fn register_change(&mut self);
}

impl TableVersion for () {
	fn register_change(&mut self) {}
}

/// A topology where connections are determined by taking first
/// hashes of a set of mixpeers.
///
/// This assumes all peers are connected (`external_routing_table` defaults to `false`).
/// And routing table are updated on mixpeer set changes.
pub struct TopologyHashTable<C: Configuration> {
	local_id: MixnetId,

	// if routing it is routing node, if consumer, we should only connect to this
	// layer index peers.
	local_layer_ix: u8,

	// true when we are in routing set.
	routing: bool,

	routing_table: RoutingTable,

	// The connected nodes (for first hop use `routing_peers` joined `connected_nodes`).
	connected_nodes: HashSet<MixnetId>,

	routing_set: BTreeSet<MixnetId>,

	changed_routing: BTreeSet<MixnetId>,

	// TODO this do not need to be stored
	layered_routing_set: Vec<BTreeSet<MixnetId>>,

	// TODO this do not need to be stored
	layered_routing_set_ix: HashMap<MixnetId, u8>,

	try_connect: BTreeSet<MixnetId>,

	// This is only routing peers we got info for.
	// Can be redundant with `routing_set`.
	routing_peers: BTreeMap<MixnetId, RoutingTable>,

	routing_peers_network: BTreeMap<NetworkId, MixnetId>,

	params: Parameters,

	// all path of a given size.
	// on every change to routing table this is cleared TODO make change synchronously to
	// avoid full calc every time.
	//
	// This assume topology is balanced, so we can just run random selection at each hop.
	// TODO check topology balancing and balance if needed (keeping only peers with right incoming
	// and outgoing?)
	// TODO find something better
	// TODO could replace HashMap by vec and use indices as ptr
	paths: BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	paths_depth: usize,

	// Ordered theorical connections by priority.
	should_connect_to: Vec<MixnetId>,

	_ph: std::marker::PhantomData<C>,
}

/// Current published view of an routing peer routing table.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RoutingTable {
	pub public_key: MixPublicKey,
	// TODO could replace MixnetId by index in list of allowed routing peers for compactness.
	pub connected_to: BTreeSet<MixnetId>,
	pub receive_from: BTreeSet<MixnetId>,
}

impl<C: Configuration> Topology for TopologyHashTable<C> {
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		(!self.changed_routing.is_empty()).then(|| std::mem::take(&mut self.changed_routing))
	}

	fn try_connect(&mut self) -> Option<BTreeSet<MixnetId>> {
		(!self.try_connect.is_empty()).then(|| std::mem::take(&mut self.try_connect))
	}

	fn first_hop_nodes_external(
		&self,
		from: &MixnetId,
		to: Option<&MixnetId>,
		num_hops: usize,
	) -> Vec<(MixnetId, MixPublicKey)> {
		let routing_set = if self.layered_routing_set.is_empty() {
			&self.routing_set
		} else {
			let dest_ix =
				layer_dest(self.local_layer_ix as usize, self.layered_routing_set.len(), num_hops);
			&self.layered_routing_set[dest_ix]
		};
		// allow for all
		routing_set
			.iter()
			.filter(|id| from != *id)
			.filter(|id| to != Some(*id))
			.filter(|id| &self.local_id != *id)
			.filter(|id| self.connected_nodes.contains(*id))
			.filter_map(|k| self.routing_peers.get(k).map(|table| (*k, table.public_key)))
			.collect()
	}

	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool {
		if &self.local_id == from {
			if self.routing {
				self.routing_table.connected_to.contains(to)
			} else {
				false
			}
		} else {
			self.routing_peers
				.get(from)
				.map(|table| table.connected_to.contains(to))
				.unwrap_or(false)
		}
	}

	fn random_path(
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		nb_chunk: usize,
		mut num_hops: usize,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		if !self.has_enough_nodes_to_send() {
			debug!(target: "mixnet", "Not enough routing nodes for path.");
			return Err(Error::NotEnoughRoutingPeers)
		}

		let start = start_node.0;
		let recipient = self.reachable(start, recipient_node, &mut num_hops)?;
		let recipient = match (recipient_node, recipient.as_ref()) {
			(_, Some(node)) => &node,
			(Some(node), _) => node.0,
			_ => return Err(Error::NoPath(None)),
		};
		let mut result = Vec::with_capacity(nb_chunk);
		while result.len() < nb_chunk {
			let path_ids = if let Some(path) = random_path(&self.paths, start, &recipient, num_hops)
			{
				trace!(target: "mixnet", "Got path: {:?}", &path);
				path
			} else {
				return Err(Error::NoPath(Some(*recipient)))
			};
			let mut path = Vec::with_capacity(num_hops + 1);

			for peer_id in path_ids.into_iter() {
				if let Some(table) = self.routing_peers.get(&peer_id) {
					path.push((peer_id, table.public_key));
				} else {
					error!(target: "mixnet", "node in routing_nodes must also be in connected_nodes");
					unreachable!("node in routing_nodes must also be in connected_nodes");
				}
			}
			if let Some(table) = self.routing_peers.get(recipient) {
				path.push((*recipient, table.public_key));
			} else if &self.local_id == recipient {
				// surb reply
				path.push((self.local_id, self.routing_table.public_key));
			} else {
				error!(target: "mixnet", "Unknown recipient {:?}", recipient);
				return Err(Error::NotEnoughRoutingPeers)
			}

			result.push(path);
		}
		debug!(target: "mixnet", "Path: {:?}", result);
		Ok(result)
	}

	fn can_route(&self, id: &MixnetId) -> bool {
		if &self.local_id == id {
			self.routing
		} else {
			self.routing_set.contains(id)
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

	fn accept_peer(&self, peer_id: &MixnetId, peers: &PeerCount) -> bool {
		if self.routing {
			self.routing_to(peer_id, &self.local_id) ||
				self.routing_to(&self.local_id, peer_id) ||
				(peers.nb_connected_external < self.params.max_external.unwrap_or(usize::MAX))
		} else {
			// Could use a higher limit when not routing, but would be more `when not suceptible
			// to be in the routing set` which we don't know but can configure.
			peers.nb_connected_external < self.params.max_external.unwrap_or(usize::MAX)
		}
	}

	fn should_connect_to(&self) -> ShouldConnectTo {
		let (number, is_static) = if self.routing {
			(C::NUMBER_CONNECTED_FORWARD, true)
		} else {
			(self.params.number_consumer_connection.unwrap_or(usize::MAX), false)
		};
		ShouldConnectTo { peers: self.should_connect_to.as_slice(), number, is_static }
	}

	fn handle_new_routing_set(&mut self, set: NewRoutingSet) {
		self.handle_new_routing_set_start(set.peers.iter().map(|k| &k.0), None);
		self.refresh_static_routing_tables(set.peers);
	}

	fn get_mixnet_id(&self, network_id: &NetworkId) -> Option<MixnetId> {
		self.routing_peers_network.get(network_id).cloned()
	}
}

impl<C: Configuration> TopologyHashTable<C> {
	/// Instantiate a new topology.
	pub fn new(local_id: MixnetId, node_public_key: MixPublicKey, params: Parameters) -> Self {
		let routing_table = RoutingTable {
			public_key: node_public_key,
			connected_to: BTreeSet::new(),
			receive_from: BTreeSet::new(),
		};
		TopologyHashTable {
			local_id,
			local_layer_ix: 0,
			routing_set: BTreeSet::new(),
			routing_peers_network: BTreeMap::new(),
			layered_routing_set: Vec::new(),
			layered_routing_set_ix: HashMap::new(),
			connected_nodes: HashSet::new(),
			changed_routing: BTreeSet::new(),
			try_connect: BTreeSet::new(),
			routing: false,
			routing_peers: BTreeMap::new(),
			routing_table,
			paths: Default::default(),
			paths_depth: 0,
			params,
			should_connect_to: Default::default(),
			_ph: Default::default(),
		}
	}

	/// Change ids.
	/// TODO this should be part of handle_new_routing_set on trait
	pub fn change_local(
		&mut self,
		local_id: Option<MixnetId>,
		node_public_key: Option<MixPublicKey>,
	) {
		if let Some(id) = local_id {
			self.local_id = id;
		}
		if let Some(key) = node_public_key {
			self.routing_table.public_key = key;
		}
	}

	fn has_enough_nodes_to_send(&self) -> bool {
		// all nodes are seen as live.
		self.routing_set.len() >= C::LOW_MIXNET_THRESHOLD
	}

	/// Is peer able to proxy.
	pub fn has_enough_nodes_to_proxy(&self) -> bool {
		self.routing_peers.len() >= C::LOW_MIXNET_THRESHOLD
	}

	fn update_first_hop_layer(&mut self) {
		if !self.routing {
			if !self.layered_routing_set.is_empty() {
				// use layer with most connect.
				let mut count = vec![0usize; self.layered_routing_set.len()];
				for (id, _) in self.routing_peers.iter() {
					if self.connected_nodes.contains(id) {
						if let Some(ix) = self.layered_routing_set_ix.get(id) {
							count[*ix as usize] += 1;
						}
					}
				}
				self.local_layer_ix =
					count.iter().enumerate().max_by_key(|k| k.1).map(|k| k.0).unwrap_or(0) as u8;
			}
		}
	}

	// TODO Note that building this is rather brutal, could just make some
	// random selection already to reduce size (and refresh after x uses).
	fn fill_paths(
		local_id: &MixnetId,
		local_routing: &RoutingTable,
		paths: &mut BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
		paths_depth: &mut usize,
		routing_peers: &BTreeMap<MixnetId, RoutingTable>,
		depth: usize,
	) {
		if &depth <= paths_depth {
			return
		}
		// TODO not strictly needed
		let mut to_from = HashMap::<MixnetId, Vec<MixnetId>>::new();

		for (from, table) in routing_peers.iter().chain(std::iter::once((local_id, local_routing)))
		{
			// TODO change if limiting size of receive_from
			to_from.insert(*from, table.receive_from.iter().cloned().collect());
		}

		fill_paths_inner(to_from, paths, *paths_depth, depth);
		if *paths_depth < depth {
			*paths_depth = depth;
		}
	}

	pub fn add_connected_peer(&mut self, peer_id: MixnetId) {
		debug!(target: "mixnet", "Connected to mixnet {:?}", peer_id);
		if self.connected_nodes.contains(&peer_id) {
			return
		}
		self.connected_nodes.insert(peer_id);

		self.update_first_hop_layer();
	}

	fn add_disconnected_peer(&mut self, peer_id: &MixnetId) {
		debug!(target: "mixnet", "Disconnected from mixnet {:?}", peer_id);
		self.connected_nodes.remove(peer_id);

		self.update_first_hop_layer();
	}

	fn handle_new_routing_set_start<'a>(
		&mut self,
		set: impl Iterator<Item = &'a MixnetId>,
		new_self: Option<(Option<MixnetId>, Option<MixPublicKey>)>,
	) {
		debug!(target: "mixnet", "Handle new routing set.");
		if let Some((id, pub_key)) = new_self {
			if let Some(id) = id {
				self.local_id = id;
			}
			if let Some(pub_key) = pub_key {
				self.routing_table.public_key = pub_key;
			}
		}

		// all previously allowed will see their routing change.
		let mut prev =
			std::mem::replace(&mut self.changed_routing, std::mem::take(&mut self.routing_set));
		self.changed_routing.append(&mut prev);
		self.routing_peers.clear();
		self.routing = false;

		for peer_id in set {
			self.routing_set.insert(*peer_id);
			if &self.local_id == peer_id {
				debug!(target: "mixnet", "In new routing set, routing.");
				self.routing = true;
			}
		}
		self.refresh_overlay();
	}

	fn refresh_overlay(&mut self) {
		if let Some((overlays, overlays_ix, at)) =
			refresh_overlay(&self.local_id, &self.routing_set, C::NUMBER_LAYER, C::MIN_LAYER_SIZE)
		{
			self.layered_routing_set = overlays;
			self.layered_routing_set_ix = overlays_ix;
			self.local_layer_ix = at;
		}
		self.update_first_hop_layer();
	}

	pub fn handle_new_self_key(&mut self) {
		unimplemented!("rotate key");
	}

	fn refresh_static_routing_tables(&mut self, set: &[(MixnetId, MixPublicKey)]) {
		for (id, public_key) in set.iter() {
			if id == &self.local_id {
				let routing_set = if self.layered_routing_set.is_empty() {
					&self.routing_set
				} else {
					&self.layered_routing_set
						[(self.local_layer_ix as usize + 1) % self.layered_routing_set.len()]
				};

				if let Some(table) = Self::refresh_connection_table_to(
					id,
					public_key,
					Some(&self.routing_table),
					routing_set,
					&mut self.should_connect_to,
				) {
					// TODO could also add receive_from.
					for peer_id in table.connected_to.iter() {
						if !self.routing_table.connected_to.contains(peer_id) {
							self.try_connect.insert(*peer_id);
						}
					}
					self.routing_table = table;
					self.paths.clear();
					self.paths_depth = 0;
				}
			} else {
				let past = self.routing_peers.get(id);

				let routing_set = if self.layered_routing_set.is_empty() {
					&self.routing_set
				} else {
					if let Some(ix) = self.layered_routing_set_ix.get(id) {
						&self.layered_routing_set
							[(*ix as usize + 1) % self.layered_routing_set.len()]
					} else {
						// skip
						log::error!(target: "mixnet", "Routing overlay should be define for routing set peer {:?}, ignoring.", id);
						continue
					}
				};

				if let Some(table) = Self::refresh_connection_table_to(
					id,
					public_key,
					past,
					routing_set,
					&mut self.should_connect_to,
				) {
					self.routing_peers.insert(*id, table);
					self.paths.clear();
					self.paths_depth = 0;
				}
			}
		}

		for id in self.routing_set.iter() {
			if id == &self.local_id {
				if let Some(from) = Self::refresh_connection_table_from(
					id,
					&self.routing_table.receive_from,
					self.routing_peers.iter(),
				) {
					self.routing_table.receive_from = from;
				}
			} else if let Some(routing_table) = self.routing_peers.get(id) {
				if let Some(from) = Self::refresh_connection_table_from(
					id,
					&routing_table.receive_from,
					self.routing_peers
						.iter()
						.chain(std::iter::once((&self.local_id, &self.routing_table))),
				) {
					if let Some(routing_table) = self.routing_peers.get_mut(id) {
						routing_table.receive_from = from;
					}
				}
			}
		}
	}

	fn refresh_connection_table_to(
		from: &MixnetId,
		from_key: &MixPublicKey,
		past: Option<&RoutingTable>,
		routing_set: &BTreeSet<MixnetId>,
		should_connect_to_dest: &mut Vec<MixnetId>,
	) -> Option<RoutingTable> {
		*should_connect_to_dest = should_connect_to(from, routing_set, C::NUMBER_CONNECTED_FORWARD);
		let mut routing_table = RoutingTable {
			public_key: *from_key,
			connected_to: Default::default(),
			receive_from: Default::default(),
		};
		for peer in should_connect_to_dest.iter() {
			// consider all connected
			routing_table.connected_to.insert(*peer);
			if routing_table.connected_to.len() == C::NUMBER_CONNECTED_FORWARD {
				break
			}
		}

		(past != Some(&routing_table)).then(|| routing_table)
	}

	fn refresh_connection_table_from<'a>(
		from: &MixnetId,
		past: &BTreeSet<MixnetId>,
		routing_peers: impl Iterator<Item = (&'a MixnetId, &'a RoutingTable)>,
	) -> Option<BTreeSet<MixnetId>> {
		let mut receive_from = BTreeSet::default();
		for (peer_id, table) in routing_peers {
			if table.connected_to.contains(from) {
				receive_from.insert(*peer_id);
			}
		}

		(past != &receive_from).then(|| receive_from)
	}

	/// Returns the mixnet peer id of our node.
	pub fn local_id(&self) -> &MixnetId {
		&self.local_id
	}

	/// Return our routing table.
	pub fn local_routing_table(&self) -> &RoutingTable {
		&self.routing_table
	}

	fn reachable(
		&mut self,
		start: &MixnetId,
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		num_hops: &mut usize,
	) -> Result<Option<MixnetId>, Error> {
		let recipient_id = recipient_node.as_ref().map(|r| r.0);
		let recipient = recipient_id
			.map(|id| {
				if self.can_route(id) {
					Ok(*id)
				} else {
					trace!(target: "mixnet", "Non routing recipient");
					return Err(Error::NoPath(Some(*id)))
				}
			})
			.transpose()?;
		if !self.layered_routing_set.is_empty() {
			let mut is_accessible = false;
			if let Some(start_layer) = self.layered_routing_set_ix.get(start) {
				if let Some(recipient) = recipient.as_ref() {
					if let Some(dest_layer) = self.layered_routing_set_ix.get(recipient) {
						if *dest_layer as usize ==
							layer_dest(
								*start_layer as usize,
								self.layered_routing_set.len(),
								*num_hops,
							) {
							is_accessible = true;
						}
					}
				} else {
					is_accessible = true;
				}
			}
			if !is_accessible {
				return Err(Error::NoPath(recipient_id.cloned()))
			}
		}
		trace!(target: "mixnet", "number hop: {:?}", num_hops);
		Self::fill_paths(
			&self.local_id,
			&self.routing_table,
			&mut self.paths,
			&mut self.paths_depth,
			&self.routing_peers,
			*num_hops,
		);
		let (nb_path, change_recipient) =
			count_paths(&self.paths, start, recipient.as_ref(), *num_hops);
		let recipient = match (change_recipient, recipient) {
			(Some(recipient), _) | (None, Some(recipient)) => recipient,
			_ => return Err(Error::NoPath(None)),
		};
		debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
		debug!(target: "mixnet", "{:?} to {:?}", start, recipient);
		if nb_path < C::LOW_MIXNET_PATHS {
			error!(target: "mixnet", "not enough paths: {:?}", nb_path);
			trace!(target: "mixnet", "not enough paths: {:?}", &self.paths);
			// TODO NotEnoughPath error
			return Err(Error::NoPath(Some(recipient)))
		};
		trace!(target: "mixnet", "enough paths: {:?}", nb_path);
		Ok(change_recipient)
	}
}

fn fill_paths_inner(
	to_from: HashMap<MixnetId, Vec<MixnetId>>,
	paths: &mut BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	paths_depth: usize,
	depth: usize,
) {
	let mut start_depth = std::cmp::max(2, paths_depth);
	while start_depth < depth {
		let depth = start_depth + 1;
		if start_depth == 2 {
			let at = paths.entry(depth).or_default();
			for (to, mid) in to_from.iter() {
				let depth_paths: &mut HashMap<MixnetId, Vec<MixnetId>> = at.entry(*to).or_default();
				for mid in mid {
					if let Some(parents) = to_from.get(mid) {
						for from in parents.iter() {
							// avoid two identical node locally (paths still contains
							// redundant node in some of its paths but being
							// distributed in a balanced way we will just avoid those
							// on each hop random calculation.
							if from == to {
								continue
							}
							depth_paths.entry(*from).or_default().push(*mid);
						}
					}
				}
			}
		} else {
			let at = paths.entry(start_depth).or_default();
			let mut dest_at = HashMap::<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>::new();
			for (to, paths_to) in at.iter() {
				let depth_paths = dest_at.entry(*to).or_default();
				for (mid, _) in paths_to.iter() {
					if let Some(parents) = to_from.get(mid) {
						for from in parents.iter() {
							if from == to {
								continue
							}
							depth_paths.entry(*from).or_default().push(*mid);
						}
					}
				}
			}
			paths.insert(depth, dest_at);
		}
		start_depth += 1;
	}
}

#[cfg(test)]
fn paths_mem_size(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
) -> usize {
	// approximate and slow, just to get idea in test. TODO update when switching paths to use
	// indexes as ptr.
	let mut size = 0;
	for paths in paths.iter() {
		size += 8; // usize
		for paths in paths.1.iter() {
			size += 32;
			for paths in paths.1.iter() {
				size += 32;
				for _ in paths.1.iter() {
					size += 32;
				}
			}
		}
	}
	size
}

fn should_connect_to(
	from: &MixnetId,
	routing_set: &BTreeSet<MixnetId>,
	nb: usize,
) -> Vec<MixnetId> {
	// TODO cache common seed when all got init
	// or/and have something faster
	let mut common_seed = [0u8; 32];
	for id in routing_set.iter() {
		let hash = crate::core::hash(id);
		for i in 0..32 {
			common_seed[i] ^= hash[i];
		}
	}
	let mut hash = crate::core::hash(from);
	for i in 0..32 {
		hash[i] ^= common_seed[i];
	}

	let mut allowed: Vec<_> = routing_set.iter().filter(|a| a != &from).collect();
	let mut nb_allowed = allowed.len();
	let mut result = Vec::with_capacity(std::cmp::min(nb, nb_allowed));
	let mut cursor = 0;
	while result.len() < nb && nb_allowed > 0 {
		// TODO bit arith
		let mut nb_bytes = match nb_allowed {
			nb_allowed if nb_allowed <= u8::MAX as usize => 1,
			nb_allowed if nb_allowed <= u16::MAX as usize => 2,
			nb_allowed if nb_allowed < 1usize << 24 => 3,
			nb_allowed if nb_allowed < u32::MAX as usize => 4,
			_ => unimplemented!(),
		};
		let mut at = 0usize;
		loop {
			if let Some(next) = hash.get(cursor) {
				nb_bytes -= 1;
				at += (*next as usize) * (1usize << (8 * nb_bytes));
				cursor += 1;
				if nb_bytes == 0 {
					break
				}
			} else {
				cursor = 0;
				hash = crate::core::hash(&hash);
			}
		}
		at %= nb_allowed;
		result.push(*allowed.remove(at));
		nb_allowed = allowed.len();
	}
	result
}

fn refresh_overlay(
	local_id: &MixnetId,
	routing_set: &BTreeSet<MixnetId>,
	number_layer: u8,
	min_layer_size: usize,
) -> Option<(Vec<BTreeSet<MixnetId>>, HashMap<MixnetId, u8>, u8)> {
	let nb_peers = routing_set.len();
	let nb_overlay = if number_layer > 0 {
		let max_nb_layer = nb_peers / min_layer_size;
		std::cmp::min(max_nb_layer, number_layer as usize)
	} else {
		1
	};
	if nb_overlay < 2 {
		return None
	}
	let mut layered_routing_set: Vec<BTreeSet<MixnetId>> = vec![Default::default(); nb_overlay];
	let mut layered_routing_set_ix: HashMap<MixnetId, u8> = Default::default();
	// TODO cache common seed when all got init
	// or/and have something faster
	let mut common_seed = [0u8; 32];
	for id in routing_set.iter() {
		let hash = crate::core::hash(id);
		for i in 0..32 {
			common_seed[i] ^= hash[i];
		}
	}
	let mut common_ix = 0u8;
	for i in 0..32 {
		common_ix ^= common_seed[i];
	}
	let mut local_layer_ix = 0u8;
	for peer in routing_set.iter() {
		let hash = crate::core::hash(peer);
		let mut layer_ix = common_ix;
		for i in 0..32 {
			layer_ix ^= hash[i];
		}
		layer_ix = layer_ix % (nb_overlay as u8);
		layered_routing_set[layer_ix as usize].insert(*peer);
		if local_id == peer {
			local_layer_ix = layer_ix;
		}
		layered_routing_set_ix.insert(*peer, layer_ix);
	}
	Some((layered_routing_set, layered_routing_set_ix, local_layer_ix))
}

fn layer_dest(from: usize, nb_layer: usize, nb_hops: usize) -> usize {
	// origin an dest are in nb_hops so -1
	let dest = (from + nb_hops - 1) % nb_layer;
	debug_assert!(layer_ori(dest, nb_layer, nb_hops) == from);
	debug_assert!(layer_distance(from, dest, nb_layer, nb_hops) == nb_hops);
	dest
}

fn layer_ori(dest: usize, nb_layer: usize, nb_hops: usize) -> usize {
	let avoid_underflow = ((nb_hops / nb_layer) + 1) * nb_layer;
	(avoid_underflow + dest + 1 - nb_hops) % nb_layer
}

fn layer_distance(ori: usize, dest: usize, nb_layer: usize, min_distance: usize) -> usize {
	let mut distance = if dest > ori { dest - ori + 1 } else { nb_layer - ori + dest + 1 };
	while distance < min_distance {
		distance += nb_layer;
	}
	distance
}

fn random_path_inner(
	rng: &mut rand::rngs::ThreadRng,
	routes: &Vec<MixnetId>,
	skip: impl Fn(&MixnetId) -> bool,
) -> Option<MixnetId> {
	use rand::Rng;
	// Warning this assume that PeerId is a randomly distributed value.
	let ix: usize = match routes.len() {
		l if l <= u8::MAX as usize => rng.gen::<u8>() as usize,
		l if l <= u16::MAX as usize => rng.gen::<u16>() as usize,
		l if l <= u32::MAX as usize => rng.gen::<u32>() as usize,
		_ => rng.gen::<usize>(),
	};
	let ix = ix % routes.len();

	for key in routes[ix..].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(*key)
		}
	}
	for key in routes[..ix].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(*key)
		}
	}
	None
}

fn random_path(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	from: &MixnetId,
	to: &MixnetId,
	size_path: usize,
) -> Option<Vec<MixnetId>> {
	trace!(target: "mixnet", "routing from {:?}, to {:?}, path size {:?}", from, to, size_path);
	// TODO some minimal length??
	if size_path < 3 {
		return None
	}
	let mut rng = rand::thread_rng();
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(*from);
	exclude.insert(*to);
	let mut result = Vec::<MixnetId>::with_capacity(size_path); // allocate two extra for case where a node is
															// appended front or/and back.
	result.push(*from);
	// TODO consider Vec instead of hashset (small nb elt)
	let mut touched = Vec::<HashSet<MixnetId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	// TODO this is making num hop equal to num peer eg 3 is only two transport.
	// So should switch to `at > 1` or even 0.
	while at > 2 {
		if let Some(paths) = result.last().and_then(|from| {
			paths.get(&at).and_then(|paths| paths.get(to)).and_then(|paths| paths.get(from))
		}) {
			if let Some(next) = random_path_inner(&mut rng, paths, |p| {
				exclude.contains(p) ||
					touched.last().map(|touched| touched.contains(p)).unwrap_or(false)
			}) {
				result.push(next);
				if let Some(touched) = touched.last_mut() {
					touched.insert(next);
				}
				touched.push(HashSet::new());
				exclude.insert(next);
				at -= 1;
				continue
			}
		}
		// dead end path
		if result.len() == 1 {
			return None
		}
		if let Some(child) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	result.remove(0); // TODO rewrite to avoid it.
	Some(result)
}

fn count_paths(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	from: &MixnetId,
	to: Option<&MixnetId>,
	size_path: usize,
) -> (usize, Option<MixnetId>) {
	let mut total = 0;
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(*from);
	to.map(|to| exclude.insert(*to));
	let mut result_dest = None;
	let mut result = Vec::<(MixnetId, usize)>::with_capacity(size_path); // allocate two extra for case where a node is
																	 // appended front or/and back.
	result.push((*from, 0));
	let mut touched = Vec::<HashSet<MixnetId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	loop {
		if let Some((paths, at_ix)) = result.last().and_then(|(from, at_ix)| {
			paths
				.get(&at)
				.and_then(|paths| {
					if let Some(to) = to {
						paths.get(to)
					} else {
						// select dest with largest number of path (not 100% accurate but don't want
						// to check path by path).
						paths.iter().max_by_key(|paths| paths.1.len()).map(|paths| {
							result_dest = Some(*paths.0);
							exclude.insert(*paths.0);
							paths.1
						})
					}
				})
				.and_then(|paths| paths.get(from))
				.map(|p| (p, *at_ix))
		}) {
			if let Some(next) = paths.get(at_ix).cloned() {
				if let Some((_, at_ix)) = result.last_mut() {
					*at_ix += 1;
				}
				if !exclude.contains(&next) &&
					!touched.last().map(|touched| touched.contains(&next)).unwrap_or(false)
				{
					if at == 3 {
						total += 1;
					} else {
						result.push((next, 0));
						if let Some(touched) = touched.last_mut() {
							touched.insert(next);
						};
						touched.push(HashSet::new());
						exclude.insert(next);
						at -= 1;
					}
					continue
				} else {
					continue
				}
			}
		}
		if result.len() == 1 {
			break
		}
		if let Some((child, _)) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	(total, result_dest)
}

#[cfg(test)]
mod test {
	use super::*;

	#[derive(Debug, Clone, Copy)]
	struct TestFillConf {
		nb_peers: u16,
		nb_disco: u16,
		nb_forward: usize,
		depth: usize,
		nb_layers: u8,
		min_layer_size: usize,
	}

	#[derive(Debug)]
	struct TestFillResult {
		average_number_connection: f64,
		number_reachable: usize,
		reachable_ratio: f64,
		dest_size: Vec<usize>,
	}

	//#[test]
	fn test_fill_paths() {
		let targets_single_layer = vec![(1000, 0, 10, 5, 5), (5, 0, 3, 4, 0)];
		let nb_layers = 3;
		let min_layer_size = 5;
		for i in targets_single_layer {
			let conf = TestFillConf {
				nb_peers: i.0,
				nb_disco: i.1,
				nb_forward: i.2,
				depth: i.3,
				nb_layers,
				min_layer_size,
			};
			let percent_margin = i.4 as f64;
			let percent_margin = (100.0 - percent_margin) / 100.0;
			let result = test_all_accessible(conf);
			println!("{:?} for {:?}", result, conf);
			assert!(result.reachable_ratio >= percent_margin);
			assert!(result.average_number_connection >= conf.nb_forward as f64 * percent_margin);
		}
		//	panic!("to print");
	}

	fn test_all_accessible(conf: TestFillConf) -> TestFillResult {
		let TestFillConf { nb_peers, nb_disco, nb_forward, depth, nb_layers, min_layer_size } =
			conf;
		let peers: Vec<[u8; 32]> = (0..nb_peers)
			.map(|i| {
				let mut id = [0u8; 32];
				id[0] = (i % 8) as u8;
				id[1] = (i / 8) as u8;
				id
			})
			.collect();
		let disco: HashSet<[u8; 32]> = peers[..nb_disco as usize].iter().cloned().collect();
		let local_id = [255u8; 32];
		let routing_set: BTreeSet<_> =
			peers.iter().chain(std::iter::once(&local_id)).cloned().collect();

		let overlayed_set = refresh_overlay(&local_id, &routing_set, nb_layers, min_layer_size);

		let mut from_to: HashMap<MixnetId, Vec<MixnetId>> = Default::default();
		for p in peers[nb_disco as usize..].iter().chain(std::iter::once(&local_id)) {
			let routing_set = if let Some((sets, ixs, _)) = &overlayed_set {
				let ix = *ixs.get(p).unwrap() as usize + 1;
				&sets[ix % sets.len()]
			} else {
				&routing_set
			};
			let tos = should_connect_to(p, routing_set, nb_forward);
			let tos = if disco.len() > 0 {
				tos.into_iter().filter(|t| !disco.contains(t)).collect()
			} else {
				tos
			};
			from_to.insert(*p, tos);
		}
		let mut to_from: HashMap<MixnetId, Vec<MixnetId>> = Default::default();
		for (from, tos) in from_to.iter() {
			for to in tos.iter() {
				to_from.entry(*to).or_default().push(*from);
			}
		}
		let mut paths = BTreeMap::new();
		let paths_depth = 0;
		fill_paths_inner(to_from, &mut paths, paths_depth, depth);
		println!("size {:?}", paths_mem_size(&paths));

		let (nb_path, _new_dest) = count_paths(&paths, &local_id, peers.last(), depth);
		println!("nb_path {:?}", nb_path);
		let path = random_path(&paths, &local_id, peers.last().unwrap(), depth);
		if path.is_none() {
			assert_eq!(nb_path, 0);
		}
		//println!("{:?}", path);
		let mut number_reachable = 0;
		let mut med_nb_con = 0;
		let from = peers.last().unwrap();
		let from_overlay = overlayed_set.as_ref().and_then(|s| s.1.get(from).copied()).unwrap_or(0);
		let mut nb_dest = 0;
		for i in nb_disco as usize..(nb_peers - 1) as usize {
			if let Some((sets, ixs, _)) = &overlayed_set {
				if let Some(ix) = ixs.get(&peers[i]) {
					// skip not reachable
					if *ix as usize != layer_dest(from_overlay as usize, sets.len(), conf.depth) {
						continue
					}
				}
			}
			nb_dest += 1;
			let path = random_path(&paths, from, &peers[i], depth);
			if path.is_some() {
				number_reachable += 1;
			}
			let (nb_path, _new_dest) = count_paths(&paths, from, Some(&peers[i]), depth);
			med_nb_con += nb_path;
		}
		let average_number_connection = med_nb_con as f64 / nb_dest as f64;
		let reachable_ratio = number_reachable as f64 / nb_dest as f64;
		let dest_size = overlayed_set
			.as_ref()
			.map(|s| s.0.iter().map(|s| s.len()).collect())
			.unwrap_or(vec![conf.nb_peers as usize]);
		TestFillResult { average_number_connection, reachable_ratio, number_reachable, dest_size }
	}

	// should have some command line checkers.
	#[test]
	fn launch_find_limit() {
		let percent_margin = 10f64;
		let percent_disco = 5f64;
		let mut conf = TestFillConf {
			nb_peers: 0,
			nb_disco: 0,
			nb_forward: 5,
			depth: 4,
			nb_layers: 3,
			min_layer_size: 5,
		};
		for nb_peers in &[5, 10, 20, 40, 80] {
			conf.nb_peers = *nb_peers;
			conf.nb_disco = (conf.nb_peers as f64 * percent_disco / 100.0) as u16;
			let percent_margin = (100.0 - percent_margin) / 100.0;
			let result = test_all_accessible(conf);

			let left = result.reachable_ratio >= percent_margin;
			//let right = result.average_number_connection >= conf.nb_forward as f64 *
			// percent_margin;
			let right = true;
			println!("{:} - {:?} -> {:?}", left && right, conf, result);
		}
		panic!("disp");
	}
}
