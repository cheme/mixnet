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

//! Mixnet connection interface.
//!
//! Connection bandwidth is limited on reception
//! of packet.

use crate::{
	core::{ConnectedKind, PacketType, QueuedPacket, WindowInfo, WINDOW_MARGIN_PERCENT},
	traits::Configuration,
	MixPublicKey, MixnetId, NetworkId, Packet, PeerCount,
};
use futures_timer::Delay;
use std::{
	collections::{BinaryHeap, VecDeque},
	num::Wrapping,
	task::Poll,
	time::{Duration, Instant},
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Events sent from a polled connection to the main mixnet loop.
pub(crate) enum ConnectionResult {
	/// Post handshake infos.
	Established(MixnetId, MixPublicKey),
	/// Received packet.
	Received(Packet),
	/// Closed connection.
	Broken(Option<MixnetId>),
}

/// All message that are not part of a sphinx session.
/// TODO rem as meta proto
#[derive(Clone, Copy)]
#[repr(u8)]
enum MetaMessage {
	Handshake = 1,
	Disconnect = 5,
}

pub(crate) struct ManagedConnection {
	local_id: MixnetId,
	local_public_key: MixPublicKey,
	network_id: NetworkId,
	kind: ConnectedKind,

	// TODO all handshake here in an enum (still a bit redundant with `kind`).
	handshake_done_id: Option<MixnetId>,
	meta_queued: VecDeque<(MetaMessage, Vec<u8>)>,
	handshake_sent: bool,
	handshake_received: bool,
	public_key: Option<MixPublicKey>, // public key is only needed for creating cover messages.
	// Packet queue of manually set messages.
	// Messages manually set are lower priority than the `packet_queue` one
	// and will only replace cover messages.
	// Warning this queue do not have a size limit, we trust.
	// TODO have a safe mode that error on too big (but then
	// need a mechanism to rollback other message chunk in other connections).
	packet_queue_inject: BinaryHeap<QueuedPacket>,
	// TODO most buff use Vec<u8>, but could use Packet
	next_packet: Option<(Vec<u8>, PacketType)>,
	// If we did not receive for a while, close connection.
	read_timeout: Delay,
	current_window: Wrapping<usize>,
	sent_in_window: usize,
	recv_in_window: usize,
	gracefull_nb_packet_receive: usize,
	gracefull_nb_packet_send: usize,
	// hard limit when disconnecting, should
	// disconnect when connection broken or gracefull_nb_packet
	// both at 0.
	gracefull_disconnecting: Option<Instant>, // TODO gracefull conf in a single struct for clarity
	// Receive is only call to match the expected bandwidth.
	// Yet with most transport it will just make the transport
	// buffer grow.
	// Using an internal buffer we can just drop connection earlier
	// by receiving all and dropping when this buffer grow out
	// of the expected badwidth limits.
	receive_buffer: Option<(VecDeque<Packet>, usize, usize)>,
	stats: Option<(ConnectionStats, Option<PacketType>)>,
}

impl ManagedConnection {
	pub fn new(
		local_id: MixnetId,
		local_public_key: MixPublicKey,
		network_id: NetworkId,
		peer_id: Option<MixnetId>,
		current_window: Wrapping<usize>,
		with_stats: bool,
		peers: &mut PeerCount,
		receive_buffer: Option<usize>,
	) -> Self {
		peers.nb_pending_handshake += 1;
		Self {
			local_id,
			local_public_key,
			handshake_done_id: peer_id,
			network_id,
			kind: ConnectedKind::PendingHandshake,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			current_window,
			public_key: None,
			meta_queued: Default::default(),
			handshake_sent: false,
			handshake_received: false,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue_inject: Default::default(),
			stats: with_stats.then(Default::default),
			gracefull_nb_packet_receive: 0,
			gracefull_nb_packet_send: 0,
			gracefull_disconnecting: None,
			receive_buffer: receive_buffer.map(|size| (VecDeque::new(), 0, size)),
		}
	}

	pub(super) fn update_kind(
		&mut self,
		peers: &mut PeerCount,
		topology: &mut Box<dyn Configuration>,
		window: &WindowInfo,
		on_handshake_success: bool,
	) {
		if on_handshake_success || self.kind != ConnectedKind::PendingHandshake {
			let old_kind = self.kind;
			self.add_peer(topology, peers, window);
			peers.remove_peer(old_kind);
			topology.peer_stats(peers);

			// gracefull handling
			let disco = matches!(self.kind, ConnectedKind::Disconnected);
			// TODO include consumer here?
			// TODO what if switching one but not the other: should have gracefull
			// forward and gracefull backward ??
			let forward = old_kind.routing_forward() != self.kind.routing_forward();
			let receive = old_kind.routing_receive() != self.kind.routing_receive();
			if receive || forward {
				if self.gracefull_nb_packet_send > 0 || self.gracefull_nb_packet_receive > 0 {
					// do not reenter gracefull period ensuring an equilibrium fro constant number
					// of peers.
					return
				}
				if let Some((period, number_message_graceful_period)) =
					window.graceful_topology_change_period
				{
					if forward {
						self.gracefull_nb_packet_send = number_message_graceful_period;
					}
					if receive {
						self.gracefull_nb_packet_receive = number_message_graceful_period;
					}
					if disco {
						let period_ms = period.as_millis();
						// could be using its own margins
						let period_ms = period_ms * (100 + WINDOW_MARGIN_PERCENT as u128) / 100;
						let period = Duration::from_millis(period_ms as u64);
						let deadline = window.last_now + period;
						self.gracefull_disconnecting = Some(deadline);
					}
				}
			}
		}
	}

	pub fn mixnet_id(&self) -> Option<&MixnetId> {
		self.handshake_done_id.as_ref()
	}

	pub fn network_id(&self) -> NetworkId {
		self.network_id
	}

	// TODO rename as it can be existing peer that change kind
	// actually in a single place: remove function
	fn add_peer(
		&mut self,
		topology: &mut Box<dyn Configuration>,
		peer_counts: &mut PeerCount,
		window: &WindowInfo,
	) {
		if let Some(peer) = self.handshake_done_id.as_ref() {
			self.kind = peer_counts.add_peer(&self.local_id, peer, topology);
		} else {
			self.kind = ConnectedKind::PendingHandshake;
		}
	}

	pub(crate) fn can_queue_packet(
		&mut self,
		packet: &QueuedPacket,
		packet_per_window: usize,
		topology: &Box<dyn Configuration>, // TODO rem param
		_peers: &PeerCount,                // TODO rem param
		window: &WindowInfo,
	) -> Result<(), crate::Error> {
		if !(self.kind.routing_forward() || self.gracefull_nb_packet_send > 0) {
			log::error!(target: "mixnet", "Dropping an injected queued packet, not routing to first hop {:?}.", self.kind);
			return Err(crate::Error::NoPath(Some(self.local_id)))
		}

		if packet.injected_packet() {
			// more priority
			if let Some((stats, _)) = self.stats.as_mut() {
				let len = self.packet_queue_inject.len();
				if len > stats.max_peer_paquet_inject_queue_size {
					stats.max_peer_paquet_inject_queue_size = len;
				}
			}

			return Ok(())
		}
		let packet_per_window = packet_per_window * (100 + WINDOW_MARGIN_PERCENT) / 100;
		if self.sent_in_window > packet_per_window {
			log::error!(target: "mixnet", "Dropping packet, queue full: {:?}", self.network_id);
			return Err(crate::Error::QueueFull)
		}

		self.update_window(window);
		let send_limit = if self.gracefull_nb_packet_send > 0 {
			window.current_packet_limit / 2
		} else {
			window.current_packet_limit
		};

		self.sent_in_window += 1;
		if self.sent_in_window > send_limit {
			return Err(crate::Error::QueueFull)
		}
		if self.gracefull_nb_packet_send > 0 {
			self.gracefull_nb_packet_send -= 1;
			if self.gracefull_nb_packet_send == 0 &&
				self.gracefull_nb_packet_receive == 0 &&
				self.gracefull_disconnecting.is_some()
			{
				return Err(crate::Error::TooManyMessages) // TODO temporary disconnect from peer on this error
			}
		}

		/* TODO stat in the forward queue (of handler??)
		if let Some((stats, _)) = self.stats.as_mut() {
			let mut len = self.packet_queue.len();
			if self.next_packet.is_some() {
				len += 1;
			}
			if len > stats.max_peer_paquet_queue_size {
				stats.max_peer_paquet_queue_size = len;
			}
		}
		*/
		Ok(())
	}

	fn broken_connection(
		&mut self,
		topology: &mut Box<dyn Configuration>,
		peers: &mut PeerCount,
	) -> Poll<ConnectionResult> {
		peers.remove_peer(self.set_disconnected_kind());
		topology.peer_stats(peers);
		Poll::Ready(ConnectionResult::Broken(self.handshake_done_id))
	}

	fn update_window(&mut self, window: &WindowInfo) {
		if window.current != self.current_window {
			if self.current_window + Wrapping(1) != window.current {
				let skipped = window.current - self.current_window;
				log::error!(target: "mixnet", "Window skipped {:?} ignoring report.", skipped);
			} else {
				let packet_per_window_less_margin =
					window.packet_per_window * (100 - WINDOW_MARGIN_PERCENT) / 100;
				if self.sent_in_window < packet_per_window_less_margin {
					// sent not enough: dest peer is not receiving enough
					log::warn!(target: "mixnet", "Low sent in window with {:?}, {:?} / {:?}", self.network_id, self.sent_in_window, packet_per_window_less_margin);
				}
				if self.recv_in_window < packet_per_window_less_margin {
					// recv not enough: origin peer is not sending enough
					log::warn!(target: "mixnet", "Low recv in window with {:?}, {:?} / {:?}", self.network_id, self.recv_in_window, packet_per_window_less_margin);
				}
			}

			self.current_window = window.current;
			self.sent_in_window = 0;
			if let Some((_buff, underbuf, _limit)) = self.receive_buffer.as_mut() {
				if self.recv_in_window < window.packet_per_window {
					*underbuf += window.packet_per_window - self.recv_in_window;
				}
			}
			self.recv_in_window = 0;
		}
	}

	pub fn connection_stats(&mut self) -> Option<&mut ConnectionStats> {
		self.stats.as_mut().map(|stats| {
			/* TODO get this from the single queue
			// heuristic we just get the queue size when queried.
			stats.0.peer_paquet_queue_size = self.packet_queue.len();
			*/
			if self.next_packet.is_some() {
				stats.0.peer_paquet_queue_size += 1;
			}
			stats.0.peer_paquet_inject_queue_size = self.packet_queue_inject.len();

			&mut stats.0
		})
	}

	pub(super) fn set_disconnected_kind(&mut self) -> ConnectedKind {
		let kind = self.kind;
		self.handshake_sent = false;
		self.handshake_received = false;
		self.kind = ConnectedKind::Disconnected;
		kind
	}
}

impl Drop for ManagedConnection {
	fn drop(&mut self) {
		if let Some((stats, _)) = self.stats.as_mut() {
			if let Some(packet) = self.next_packet.take() {
				stats.failure_packet(Some(packet.1))
			}
			/* TODO clear queue on drop connection ??
			for packet in self.packet_queue.iter() {
				stats.failure_packet(Some(packet.kind))
			}
			*/
			for packet in self.packet_queue_inject.iter() {
				stats.failure_packet(Some(packet.kind))
			}
		}
	}
}

#[derive(Default, Debug)]
pub struct ConnectionStats {
	// Do not include external or self
	pub number_forwarded_success: usize,
	pub number_forwarded_failed: usize,

	pub number_from_external_forwarded_success: usize,
	pub number_from_external_forwarded_failed: usize,

	pub number_from_self_send_success: usize,
	pub number_from_self_send_failed: usize,

	pub number_surbs_reply_success: usize,
	pub number_surbs_reply_failed: usize,

	pub number_cover_send_success: usize,
	pub number_cover_send_failed: usize,

	pub max_peer_paquet_queue_size: usize,
	pub peer_paquet_queue_size: usize,

	pub max_peer_paquet_inject_queue_size: usize,
	pub peer_paquet_inject_queue_size: usize,
}

impl ConnectionStats {
	pub(crate) fn add(&mut self, other: &Self) {
		self.number_forwarded_success += other.number_forwarded_success;
		self.number_forwarded_failed += other.number_forwarded_failed;

		self.number_from_external_forwarded_success += other.number_from_external_forwarded_success;
		self.number_from_external_forwarded_failed += other.number_from_external_forwarded_success;

		self.number_from_self_send_success += other.number_from_self_send_success;
		self.number_from_self_send_failed += other.number_from_self_send_failed;

		self.number_surbs_reply_success += other.number_surbs_reply_success;
		self.number_surbs_reply_failed += other.number_surbs_reply_failed;

		self.number_cover_send_success += other.number_cover_send_success;
		self.number_cover_send_failed += other.number_cover_send_failed;

		self.max_peer_paquet_queue_size =
			std::cmp::max(self.max_peer_paquet_queue_size, other.max_peer_paquet_queue_size);
		self.peer_paquet_queue_size += other.peer_paquet_queue_size;

		self.max_peer_paquet_inject_queue_size = std::cmp::max(
			self.max_peer_paquet_inject_queue_size,
			other.max_peer_paquet_inject_queue_size,
		);
		self.peer_paquet_inject_queue_size += other.peer_paquet_inject_queue_size;
	}

	fn success_packet(&mut self, kind: Option<PacketType>) {
		let kind = if let Some(kind) = kind { kind } else { return };

		match kind {
			PacketType::Forward => {
				self.number_forwarded_success += 1;
			},
			PacketType::ForwardExternal => {
				self.number_from_external_forwarded_success += 1;
			},
			PacketType::SendFromSelf => {
				self.number_from_self_send_success += 1;
			},
			PacketType::Cover => {
				self.number_cover_send_success += 1;
			},
			PacketType::Surbs => {
				self.number_surbs_reply_success += 1;
			},
		}
	}

	fn failure_packet(&mut self, kind: Option<PacketType>) {
		let kind = if let Some(kind) = kind { kind } else { return };

		match kind {
			PacketType::Forward => {
				self.number_forwarded_failed += 1;
			},
			PacketType::ForwardExternal => {
				self.number_from_external_forwarded_failed += 1;
			},
			PacketType::SendFromSelf => {
				self.number_from_self_send_failed += 1;
			},
			PacketType::Cover => {
				self.number_cover_send_failed += 1;
			},
			PacketType::Surbs => {
				self.number_surbs_reply_failed += 1;
			},
		}
	}
}
