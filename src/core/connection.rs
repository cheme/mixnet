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
	traits::{Configuration, Connection, Topology},
	MixPublicKey, MixnetId, NetworkId, Packet, PeerCount,
};
use futures::FutureExt;
use futures_timer::Delay;
use std::{
	collections::{BinaryHeap, VecDeque},
	num::Wrapping,
	task::{Context, Poll},
	time::Duration,
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

// TODO make it configurable
/// Only write cover every N expected cover (bandwidth will
/// not be constant, but we can have many connection this way).
const SKIP_COVER: usize = 8;

macro_rules! try_poll {
	( $call: expr ) => {
		match $call {
			Poll::Ready(Ok(result)) => Some(result),
			Poll::Ready(Err(e)) => {
				log::debug!(target: "mixnet", "Error in poll {:?}", e);
				return Poll::Ready(Err(()));
			},
			Poll::Pending => None,
		}
	}
}

/// Events sent from a polled connection to the main mixnet loop.
pub(crate) enum ConnectionResult {
	/// Received packet.
	Received(Packet),
	/// Closed connection.
	Broken(Option<MixnetId>),
}

pub(crate) struct ManagedConnection<C> {
	local_id: MixnetId,
	connection: C,
	network_id: NetworkId,
	pub(crate) kind: ConnectedKind, // TODO may be useless or at least some variants

	peer_id: Option<MixnetId>,
	public_key: Option<MixPublicKey>, // public key is only needed for creating cover messages.
	// Real messages queue, sorted by deadline (`QueuedPacket` is ord desc by deadline).
	packet_queue: BinaryHeap<QueuedPacket>,
	// Packet queue of manually set messages.
	// Messages manually set are lower priority than the `packet_queue` one
	// and will only replace cover messages.
	// Warning this queue do not have a size limit, we trust.
	packet_queue_inject: BinaryHeap<QueuedPacket>,
	// TODO most buff use Vec<u8>, but could use Packet
	next_packet: Option<(Vec<u8>, PacketType)>,
	// If we did not receive for a while, close connection.
	read_timeout: Delay,
	current_window: Wrapping<usize>,
	sent_in_window: usize,
	recv_in_window: usize,
	// Receive is only call to match the expected bandwidth.
	// Yet with most transport it will just make the transport
	// buffer grow.
	// Using an internal buffer we can just drop connection earlier
	// by receiving all and dropping when this buffer grow out
	// of the expected badwidth limits.
	receive_buffer: (VecDeque<Packet>, usize, usize),
	stats: Option<(ConnectionStats, Option<PacketType>)>,
	skipped_cover: usize,
}

impl<C: Connection> ManagedConnection<C> {
	pub fn new(
		local_id: MixnetId,
		network_id: NetworkId,
		peer_id: Option<MixnetId>,
		connection: C,
		current_window: Wrapping<usize>,
		with_stats: bool,
		receive_buffer: usize,
		topology: &mut impl Configuration,
		peer_counts: &mut PeerCount,
	) -> Self {
		let kind = if let Some(peer) = peer_id.as_ref() {
			peer_counts.add_peer(&local_id, peer, topology)
		} else {
			ConnectedKind::External
		};

		Self {
			local_id,
			connection,
			peer_id,
			network_id,
			kind,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			current_window,
			public_key: None,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue: Default::default(),
			packet_queue_inject: Default::default(),
			stats: with_stats.then(Default::default),
			receive_buffer: (VecDeque::new(), 0, receive_buffer),
			skipped_cover: 0,
		}
	}

	pub(super) fn connection_mut(&mut self) -> &mut C {
		&mut self.connection
	}

	pub(super) fn update_kind(&mut self, peers: &mut PeerCount, topology: &mut impl Configuration) {
		let old_kind = self.kind;
		self.add_peer(topology, peers);
		peers.remove_peer(old_kind);
		topology.peer_stats(peers);
	}

	pub fn mixnet_id(&self) -> Option<&MixnetId> {
		self.peer_id.as_ref()
	}

	pub fn network_id(&self) -> NetworkId {
		self.network_id
	}

	// TODO rename as it can be existing peer that change kind
	// actually in a single place: remove function
	fn add_peer(&mut self, topology: &mut impl Configuration, peer_counts: &mut PeerCount) {
		if let Some(peer) = self.peer_id.as_ref() {
			self.kind = peer_counts.add_peer(&self.local_id, peer, topology);
		} else {
			self.kind = ConnectedKind::External;
		}
	}

	fn try_send_flushed(&mut self, cx: &mut Context, is_packet: bool) -> Poll<Result<bool, ()>> {
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(sent)) => {
				if is_packet {
					if let Some((stats, kind)) = self.stats.as_mut() {
						stats.success_packet(kind.take());
					}
				}
				Poll::Ready(Ok(sent))
			},
			Poll::Ready(Err(())) => {
				if is_packet {
					log::trace!(target: "mixnet", "Error sending to peer {:?}", self.network_id);
					if let Some((stats, kind)) = self.stats.as_mut() {
						stats.failure_packet(kind.take());
					};
				} else {
					log::trace!(target: "mixnet", "Error sending meta to peer {:?}", self.network_id);
				}
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	fn try_recv_packet(
		&mut self,
		cx: &mut Context,
		current_window: Wrapping<usize>,
	) -> Poll<Result<Packet, ()>> {
		loop {
			return match self.connection.try_recv(cx) {
				Poll::Ready(Ok(Some(packet))) => {
					self.read_timeout.reset(READ_TIMEOUT);
					log::trace!(target: "mixnet", "Packet received from {:?}", self.network_id);
					let packet = Packet::from_vec(packet).unwrap();
					if self.current_window != current_window {
						self.current_window = current_window;
					}
					Poll::Ready(Ok(packet))
				},
				Poll::Ready(Ok(None)) => {
					self.read_timeout.reset(READ_TIMEOUT);
					continue
				},
				Poll::Ready(Err(())) => {
					log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", self.network_id);
					Poll::Ready(Err(()))
				},
				Poll::Pending => Poll::Pending,
			}
		}
	}

	pub(crate) fn queue_packet(
		&mut self,
		packet: QueuedPacket,
		packet_per_window: usize,
		topology: &impl Topology, // TODO rem param
		_peers: &PeerCount,       // TODO rem param
	) -> Result<(), crate::Error> {
		if let Some(peer_id) = self.peer_id.as_ref() {
			if packet.injected_packet() {
				// more priority
				self.packet_queue_inject.push(packet);
				if let Some((stats, _)) = self.stats.as_mut() {
					let len = self.packet_queue_inject.len();
					if len > stats.max_peer_paquet_inject_queue_size {
						stats.max_peer_paquet_inject_queue_size = len;
					}
				}

				return Ok(())
			}

			if !self.kind.routing_forward() {
				log::error!(target: "mixnet", "Dropping an injected queued packet, not routing to first hop {:?}.", self.kind);
				return Err(crate::Error::NoPath(Some(*peer_id)))
			}

			let packet_per_window = packet_per_window * (100 + WINDOW_MARGIN_PERCENT) / 100;
			if self.packet_queue.len() > packet_per_window {
				log::error!(target: "mixnet", "Dropping packet, queue full: {:?}", self.network_id);
				return Err(crate::Error::QueueFull)
			}

			if packet.external_packet() &&
				!topology.can_add_external_message(
					&peer_id,
					self.packet_queue.len(),
					packet_per_window,
				) {
				log::error!(target: "mixnet", "Dropping packet, queue full for external: {:?} {:} {:?}", self.network_id, self.packet_queue.len(), packet_per_window);
				return Err(crate::Error::QueueFull)
			}

			self.packet_queue.push(packet);
			if let Some((stats, _)) = self.stats.as_mut() {
				let mut len = self.packet_queue.len();
				if self.next_packet.is_some() {
					len += 1;
				}
				if len > stats.max_peer_paquet_queue_size {
					stats.max_peer_paquet_queue_size = len;
				}
			}
			Ok(())
		} else {
			Err(crate::Error::NoSphinxId)
		}
	}

	fn broken_connection(
		&mut self,
		topology: &mut impl Configuration,
		peers: &mut PeerCount,
	) -> Poll<ConnectionResult> {
		peers.remove_peer(self.kind);
		topology.peer_stats(peers);
		Poll::Ready(ConnectionResult::Broken(self.peer_id))
	}

	pub(super) fn poll(
		&mut self,
		cx: &mut Context,
		window: &WindowInfo,
		topology: &mut impl Configuration,
		peers: &mut PeerCount,
	) -> Poll<ConnectionResult> {
		// pending return on receive pending.
		// If this is not expecting to receive (forward only), we still return pending
		// (send is triggered by timer from calling method).
		// If not routing, sending is triggered manually by `queue_external_packet`.
		let mut result = Poll::Pending;

		self.update_window(window);
		match self.poll_sphinx(cx, window) {
			Poll::Ready(Ok(res)) => {
				result = Poll::Ready(res);
			},
			Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
			Poll::Pending => (),
		}

		if self.kind.routing_receive() {
			match self.read_timeout.poll_unpin(cx) {
				Poll::Ready(()) => {
					log::trace!(target: "mixnet", "Peer, nothing received for too long, dropping.");
					return self.broken_connection(topology, peers)
				},
				Poll::Pending => (),
			}
		}
		result
	}

	fn poll_sphinx(
		&mut self,
		cx: &mut Context,
		window: &WindowInfo,
	) -> Poll<Result<ConnectionResult, ()>> {
		// routing
		let send_limit = window.current_packet_limit;
		// Forward first.
		while self.sent_in_window < send_limit {
			match try_poll!(self.try_send_flushed(cx, true)) {
				Some(true) => {
					// Did send message
					self.sent_in_window += 1;
					break
				},
				Some(false) => {
					// nothing in queue, get next.
					if let Some(packet) = self.next_packet.take() {
						if self.connection.can_queue_send() {
							self.connection.queue_send(None, packet.0);
							if let Some(stats) = self.stats.as_mut() {
								stats.1 = Some(packet.1);
							}
						} else {
							log::error!(target: "mixnet", "Queue should be flushed.");
							if let Some((stats, _)) = self.stats.as_mut() {
								stats.failure_packet(Some(packet.1));
							}
							self.next_packet = Some(packet);
						}
						continue
					}
					let deadline =
						self.packet_queue.peek().map_or(false, |p| p.deadline <= window.last_now);
					if deadline {
						if let Some(packet) = self.packet_queue.pop() {
							self.next_packet = Some((packet.data.into_vec(), packet.kind));
						}
					} else {
						let deadline = self
							.packet_queue_inject
							.peek()
							.map_or(false, |p| p.deadline <= window.last_now);
						if deadline {
							if let Some(packet) = self.packet_queue_inject.pop() {
								self.next_packet = Some((packet.data.into_vec(), packet.kind));
							}
						}
						if self.next_packet.is_none() && self.kind.routing_forward() {
							if let Some(key) = self.public_key {
								if let Some(peer_id) = self.peer_id {
									if self.skipped_cover != SKIP_COVER {
										self.skipped_cover += 1;
									} else {
										self.next_packet =
											crate::core::cover_message_to(&peer_id, key)
												.map(|p| (p.into_vec(), PacketType::Cover));
										if self.next_packet.is_none() {
											log::error!(target: "mixnet", "Could not create cover for {:?}", self.network_id);
											if let Some(stats) = self.stats.as_mut() {
												stats.0.number_cover_send_failed += 1;
											}
										}
									}
								}
							}
						}
						if self.next_packet.is_none() {
							break
						}
					}
				},
				None => break,
			}
		}

		// Limit reception.
		let current = window.current_packet_limit;
		let can_receive = self.recv_in_window < current;
		loop {
			match self.try_recv_packet(cx, window.current) {
				Poll::Ready(Ok(packet)) => {
					self.recv_in_window += 1;
					let (buf, underbuf, limit) = &mut self.receive_buffer;
					buf.push_back(packet);
					if buf.len() > *limit + *underbuf {
						log::warn!(target: "mixnet", "Disconnecting, received too many messages");
						return Poll::Ready(Err(()))
					}
				},
				Poll::Ready(Err(())) => return Poll::Ready(Err(())),
				Poll::Pending => break,
			}
		}

		if can_receive {
			let (buf, _underbuf, _limit) = &mut self.receive_buffer;
			if let Some(mess) = buf.pop_front() {
				return Poll::Ready(Ok(ConnectionResult::Received(mess)))
			}
		}

		Poll::Pending
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
			let (_buff, underbuf, _limit) = &mut self.receive_buffer;
			if self.recv_in_window < window.packet_per_window {
				*underbuf += window.packet_per_window - self.recv_in_window;
			}
			self.recv_in_window = 0;
		}
	}

	pub fn connection_stats(&mut self) -> Option<&mut ConnectionStats> {
		self.stats.as_mut().map(|stats| {
			// heuristic we just get the queue size when queried.
			stats.0.peer_paquet_queue_size = self.packet_queue.len();
			if self.next_packet.is_some() {
				stats.0.peer_paquet_queue_size += 1;
			}
			stats.0.peer_paquet_inject_queue_size = self.packet_queue_inject.len();

			&mut stats.0
		})
	}
}

impl<C> Drop for ManagedConnection<C> {
	fn drop(&mut self) {
		if let Some((stats, _)) = self.stats.as_mut() {
			if let Some(packet) = self.next_packet.take() {
				stats.failure_packet(Some(packet.1))
			}
			for packet in self.packet_queue.iter() {
				stats.failure_packet(Some(packet.kind))
			}
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
