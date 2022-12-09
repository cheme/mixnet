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
	core::{
		ConnectedKind, PacketType, QueuedPacket, QueuedUnconnectedPackets, WindowInfo,
		WINDOW_MARGIN_PERCENT,
	},
	traits::{Configuration, Connection, Handshake, Topology},
	MixPublicKey, MixnetId, NetworkId, Packet, PeerCount, PACKET_SIZE,
};
use futures::FutureExt;
use futures_timer::Delay;
use std::{
	collections::{BinaryHeap, VecDeque},
	num::Wrapping,
	task::{Context, Poll},
	time::{Duration, Instant},
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const EXTERNAL_QUERY_SIZE: usize = PACKET_SIZE; // TODO other stuff needed
pub(crate) const EXTERNAL_REPLY_SIZE: usize = PACKET_SIZE; // TODO other stuff needed

/// Events sent from a polled connection to the main mixnet loop.
/// TODO rename Event by Result, and make it clear it is local
/// to the main mixnet thread.
pub(crate) enum ConnectionEvent {
	/// Post handshake infos.
	Established(MixnetId, MixPublicKey),
	/// Received packet.
	Received(Packet),
	/// Closed connection.
	Broken(Option<MixnetId>),
	/// Noops.
	None,
}

/// All message that are not part of a sphinx session.
#[derive(Clone, Copy)]
#[repr(u8)]
enum MetaMessage {
	Handshake = 1,
	ExternalQuery = 2,
	ExternalReply = 3,
	Disconnect = 4,
}

pub(crate) struct ManagedConnection<C> {
	local_id: MixnetId,
	local_public_key: MixPublicKey,
	connection: C,
	network_id: NetworkId,
	kind: ConnectedKind,

	// TODO all handshake here in an enum (still a bit redundant with `kind`).
	handshake_done_id: Option<MixnetId>,
	handshake_queue: bool,
	handshake_sent: bool,
	handshake_received: bool,
	public_key: Option<MixPublicKey>, // public key is only needed for creating cover messages.
	// Real messages queue, sorted by deadline (`QueuedPacket` is ord desc by deadline).
	packet_queue: BinaryHeap<QueuedPacket>,
	// Packet queue of manually set messages.
	// Messages manually set are lower priority than the `packet_queue` one
	// and will only replace cover messages.
	// Warning this queue do not have a size limit, we trust.
	// TODO have a safe mode that error on too big (but then
	// need a mechanism to rollback other message chunk in other connections).
	packet_queue_inject: BinaryHeap<QueuedPacket>,
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
	gracefull_disconnecting: Option<Instant>,
	// Receive is only call to match the expected bandwidth.
	// Yet with most transport it will just make the transport
	// buffer grow.
	// Using an internal buffer we can just drop connection earlier
	// by receiving all and dropping when this buffer grow out
	// of the expected badwidth limits.
	receive_buffer: Option<(VecDeque<Packet>, usize, usize)>,
	stats: Option<(ConnectionStats, Option<PacketType>)>,
}

impl<C: Connection> ManagedConnection<C> {
	pub fn new(
		local_id: MixnetId,
		local_public_key: MixPublicKey,
		network_id: NetworkId,
		connection: C,
		current_window: Wrapping<usize>,
		with_stats: bool,
		peers: &mut PeerCount,
		receive_buffer: Option<usize>,
	) -> Self {
		peers.nb_pending_handshake += 1;
		Self {
			local_id,
			local_public_key,
			connection,
			handshake_done_id: None,
			network_id,
			kind: ConnectedKind::PendingHandshake,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			current_window,
			public_key: None,
			handshake_queue: false,
			handshake_sent: false,
			handshake_received: false,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue: Default::default(),
			packet_queue_inject: Default::default(),
			stats: with_stats.then(Default::default),
			gracefull_nb_packet_receive: 0,
			gracefull_nb_packet_send: 0,
			gracefull_disconnecting: None,
			receive_buffer: receive_buffer.map(|size| (VecDeque::new(), 0, size)),
		}
	}

	pub(super) fn connection_mut(&mut self) -> &mut C {
		&mut self.connection
	}

	pub(super) fn set_kind_changed(
		&mut self,
		peers: &mut PeerCount,
		topology: &mut impl Configuration,
		forward_queue: Option<&mut QueuedUnconnectedPackets>,
		window: &WindowInfo,
		on_handshake_success: bool,
	) {
		if on_handshake_success || self.kind != ConnectedKind::PendingHandshake {
			let old_kind = self.kind;
			self.add_peer(topology, forward_queue, peers, window);
			peers.remove_peer(old_kind);
			topology.peer_stats(peers);

			// gracefull handling
			let disco = matches!(self.kind, ConnectedKind::Disconnected);
			// TODO include consumer here?
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
		topology: &mut impl Configuration,
		forward_queue: Option<&mut QueuedUnconnectedPackets>,
		peer_counts: &mut PeerCount,
		window: &WindowInfo,
	) {
		if let Some(peer) = self.handshake_done_id.as_ref() {
			self.kind = peer_counts.add_peer(&self.local_id, peer, topology);
			if self.kind.routing_forward() {
				if let Some(queue_packets) = forward_queue.and_then(|q| q.remove(peer)) {
					for (packet, _) in queue_packets {
						let queued = self.queue_packet(
							packet,
							window.packet_per_window,
							topology,
							peer_counts,
						);
						if queued.is_err() {
							log::error!(
								"Could not queue packet received before handshake: {:?}",
								queued
							);
						}
					}
				}
			}
		} else {
			self.kind = ConnectedKind::PendingHandshake;
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

	fn try_recv_meta(
		&mut self,
		cx: &mut Context,
		topology: &mut impl Configuration,
	) -> Poll<Result<(MetaMessage, Vec<u8>), ()>> {
		let mut is_content: Option<(MetaMessage, usize)> = None;
		loop {
			return match self
				.connection
				.try_recv(cx, is_content.as_ref().map(|content| content.1).unwrap_or(1))
			{
				Poll::Ready(Ok(Some(data))) => {
					self.read_timeout.reset(READ_TIMEOUT);
					if let Some((kind, _)) = is_content.as_ref() {
						Poll::Ready(Ok((*kind, data)))
					} else {
						match data[0] {
							k if k == (MetaMessage::Handshake as u8) => {
								is_content =
									Some((MetaMessage::Handshake, topology.handshake_size()));
								continue
							},
							k if k == (MetaMessage::ExternalQuery as u8) => {
								is_content = Some((MetaMessage::Handshake, EXTERNAL_QUERY_SIZE));
								continue
							},
							k if k == (MetaMessage::ExternalReply as u8) => {
								is_content = Some((MetaMessage::Handshake, EXTERNAL_REPLY_SIZE));
								continue
							},
							k if k == (MetaMessage::Disconnect as u8) =>
								Poll::Ready(Ok((MetaMessage::Disconnect, Vec::new()))),
							_ => {
								log::trace!(target: "mixnet", "Unexpected message kind, closing: {:?}", self.network_id);
								Poll::Ready(Err(()))
							},
						}
					}
				},
				Poll::Ready(Ok(None)) => {
					self.read_timeout.reset(READ_TIMEOUT);
					continue
				},
				Poll::Ready(Err(())) => {
					// TODO could need a delay to try to handshake again rather than full disconnect
					// reconnect.
					log::trace!(target: "mixnet", "Error receiving message type from peer, closing: {:?}", self.network_id);
					Poll::Ready(Err(()))
				},
				Poll::Pending => Poll::Pending,
			}
		}
	}

	fn received_handshake(
		&mut self,
		handshake: Vec<u8>,
		topology: &mut impl Configuration,
		peers: &PeerCount,
	) -> Result<(), ()> {
		log::trace!(target: "mixnet", "Handshake message from {:?}", self.network_id);
		if let Some((peer_id, pk)) =
			topology.check_handshake(handshake.as_slice(), &self.network_id)
		{
			let accepted = topology.accept_peer(&peer_id, peers);
			self.handshake_done_id = Some(peer_id);
			self.public_key = Some(pk);
			self.handshake_received = true;
			if !accepted {
				log::trace!(target: "mixnet", "Valid handshake, rejected peer, closing: {:?} from {:?}", peer_id, self.local_id);
				Err(())
			} else {
				Ok(())
			}
		} else {
			log::trace!(target: "mixnet", "Invalid handshake from peer, closing: {:?}", self.network_id);
			Err(())
		}
	}

	fn try_recv_packet(
		&mut self,
		cx: &mut Context,
		current_window: Wrapping<usize>,
	) -> Poll<Result<Packet, ()>> {
		if !self.kind.is_mixnet_routing() {
			// this is actually unreachable but ignore it.
			return Poll::Pending
		}
		loop {
			return match self.connection.try_recv(cx, PACKET_SIZE) {
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
		if let Some(peer_id) = self.handshake_done_id.as_ref() {
			if !(self.kind.routing_forward() || self.gracefull_nb_packet_send > 0) {
				log::error!(target: "mixnet", "Dropping an injected queued packet, not routing to first hop {:?}.", self.kind);
				return Err(crate::Error::NoPath(Some(*peer_id)))
			}

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
			let packet_per_window = packet_per_window * (100 + WINDOW_MARGIN_PERCENT) / 100;
			if self.packet_queue.len() > packet_per_window {
				log::error!(target: "mixnet", "Dropping packet, queue full: {:?}", self.network_id);
				return Err(crate::Error::QueueFull)
			}

			if packet.external_packet() &&
				topology.can_add_external_message(
					&peer_id,
					self.packet_queue.len(),
					packet_per_window,
				) {
				log::error!(target: "mixnet", "Dropping packet, queue full for external: {:?}", self.network_id);
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
	) -> Poll<ConnectionEvent> {
		peers.remove_peer(self.disconnected_kind());
		topology.peer_stats(peers);
		Poll::Ready(ConnectionEvent::Broken(self.handshake_done_id))
	}

	pub(super) fn poll(
		&mut self,
		cx: &mut Context,
		window: &WindowInfo,
		topology: &mut impl Configuration,
		peers: &mut PeerCount,
		forward_queue: Option<&mut QueuedUnconnectedPackets>,
	) -> Poll<ConnectionEvent> {
		if let Some(gracefull_disco_deadline) = self.gracefull_disconnecting.as_ref() {
			if gracefull_disco_deadline <= &window.last_now {
				return self.broken_connection(topology, peers)
			}
		}
		let mut result = Poll::Pending;
		if !(self.handshake_sent && self.handshake_received) {
			let mut result = Poll::Pending;
			if !self.handshake_received {
			//	if self.meta_queued.is_none() {
					match self.try_recv_meta(cx, topology) {
						Poll::Ready(Ok((MetaMessage::Handshake, data))) => {
							if let Err(()) = self.received_handshake(data, topology, peers) {
								return self.broken_connection(topology, peers)
							}

						if matches!(result, Poll::Pending) {
							result = Poll::Ready(ConnectionEvent::None);
						}

						},
						Poll::Ready(Ok((MetaMessage::ExternalQuery, data))) => {
							unimplemented!()
						},
						Poll::Ready(Ok((MetaMessage::ExternalReply, data))) => {
							unimplemented!()
						},
						Poll::Ready(Ok((MetaMessage::Disconnect, _))) => {
							return self.broken_connection(topology, peers)
						},
						Poll::Ready(Err(())) => {
							return self.broken_connection(topology, peers)
						},
						Poll::Pending =>(),
							/*if matches!(result, Poll::Ready(ConnectionEvent::None)) {
								result = Poll::Pending
							},*/
					}
				}


			if !self.handshake_queue {
				let handshake = if let Some(mut handshake) =
					topology.handshake(&self.network_id, &self.local_public_key)
				{
					handshake
				} else {
					// TODO allow no handshake from topo and only switch to sphinx only if
					// needed
					log::trace!(target: "mixnet", "Cannot create handshake with {}", self.network_id);
					return self.broken_connection(topology, peers)
				};
				if self.connection.can_queue_send() {
					self.connection.queue_send(Some(MetaMessage::Handshake as u8), handshake);
				} else {
					return self.broken_connection(topology, peers)
				}
				//self.handshake_sent = true;
				self.handshake_queue = true;
			}


			if !self.handshake_sent { // TODO try remove this cond
			loop {
				match self.try_send_flushed(cx, false) {
					Poll::Ready(Ok(true)) => {
						self.handshake_sent = true;
						if matches!(result, Poll::Pending) {
							result = Poll::Ready(ConnectionEvent::None);
						}

						assert!(self.connection.can_queue_send());
							continue

						/*if let Some((kind, data)) = self.meta_queued.take() {
							self.connection.queue_send(Some(kind as u8), data);
							continue
						}*/
					},
					Poll::Ready(Ok(false)) => {
						// nothing
						break
					},
					Poll::Ready(Err(())) => {
						return self.broken_connection(topology, peers)
					},
					Poll::Pending => {
						/*
						if matches!(result, Poll::Ready(ConnectionEvent::None)) {
							result = Poll::Pending
						}

						// do not swich kind unless all is really flushed
						return result */
						()
					},
				}
				break
			}
			}


			if self.handshake_sent && self.handshake_received {
				log::debug!(target: "mixnet", "Handshake success from {:?} to {:?}", self.local_id, self.handshake_done_id);
				if let (Some(mixnet_id), Some(public_key)) = (self.handshake_done_id, self.public_key) {
					self.current_window = window.current;
					self.sent_in_window = window.current_packet_limit;
					self.recv_in_window = window.current_packet_limit;
					self.set_kind_changed(peers, topology, forward_queue, window, true);
					return Poll::Ready(ConnectionEvent::Established(mixnet_id, public_key))
				} else {
					// is actually unreachable
					return self.broken_connection(topology, peers)
				}
			} else {
				return result
			}
		} else if let Some(peer_id) = self.handshake_done_id {
			let send_limit = if self.gracefull_nb_packet_send > 0 {
				window.current_packet_limit / 2
			} else {
				window.current_packet_limit
			};
			// Forward first.
			while self.sent_in_window < send_limit {
				match self.try_send_flushed(cx, true) {
					Poll::Ready(Ok(true)) => {
						// Did send message
						self.sent_in_window += 1;
						if self.gracefull_nb_packet_send > 0 {
							self.gracefull_nb_packet_send -= 1;
							if self.gracefull_nb_packet_send == 0 &&
								self.gracefull_nb_packet_receive == 0 &&
								self.gracefull_disconnecting.is_some()
							{
								return self.broken_connection(topology, peers)
							}
						}
						break
					},
					Poll::Ready(Ok(false)) => {
						// nothing in queue, get next.
						if let Some(packet) = self.next_packet.take() {
							if self.connection.can_queue_send() {
								self.connection.queue_send(None, packet.0);
								if let Some(stats) = self.stats.as_mut() {
									stats.1 = Some(packet.1);
								}
							} else {
								log::error!(target: "mixnet", "try send should not fail on flushed queue.");
								if let Some((stats, _)) = self.stats.as_mut() {
									stats.failure_packet(Some(packet.1));
								}
								self.next_packet = Some(packet);
							}
							continue
						}
						let deadline = self
							.packet_queue
							.peek()
							.map_or(false, |p| p.deadline <= window.last_now);
						if deadline {
							if let Some(packet) = self.packet_queue.pop() {
								self.next_packet = Some((packet.data.into_vec(), packet.kind));
							}
						} else if let Some(key) = self.public_key {
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
								self.next_packet = crate::core::cover_message_to(&peer_id, key)
									.map(|p| (p.into_vec(), PacketType::Cover));
								if self.next_packet.is_none() {
									log::error!(target: "mixnet", "Could not create cover for {:?}", self.network_id);
									if let Some(stats) = self.stats.as_mut() {
										stats.0.number_cover_send_failed += 1;
									}
								}
							}
							if self.next_packet.is_none() {
								break
							}
						}
					},
					Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
					Poll::Pending => break,
				}
			}

			// Limit reception.
			let current = if self.kind.routing_receive() { window.current_packet_limit } else { 0 };
			let current = if self.gracefull_nb_packet_receive > 0 {
				window.current_packet_limit / 2
			} else {
				current
			};
			let can_receive = self.recv_in_window < current;
			if self.receive_buffer.is_some() || can_receive {
				loop {
					match self.try_recv_packet(cx, window.current) {
						Poll::Ready(Ok(packet)) => {
							self.recv_in_window += 1;
							if self.gracefull_nb_packet_receive > 0 {
								self.gracefull_nb_packet_receive -= 1;
								if self.gracefull_nb_packet_send == 0 &&
									self.gracefull_nb_packet_receive == 0 &&
									self.gracefull_disconnecting.is_some()
								{
									self.gracefull_disconnecting = Some(window.last_now);
								}
							}

							if let Some((buf, underbuf, limit)) = self.receive_buffer.as_mut() {
								buf.push_back(packet);
								if buf.len() > *limit + *underbuf {
									log::warn!(target: "mixnet", "Disconnecting, received too many messages");
									return self.broken_connection(topology, peers)
								}
							} else {
								result = Poll::Ready(ConnectionEvent::Received(packet));
								break
							}
						},
						Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
						Poll::Pending => break,
					}
				}

				if can_receive {
					if let Some((buf, _underbuf, _limit)) = self.receive_buffer.as_mut() {
						if let Some(mess) = buf.pop_front() {
							result = Poll::Ready(ConnectionEvent::Received(mess));
						}
					}
				}
			}

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
		} else {
			log::trace!(target: "mixnet", "No sphinx id, dropping.");
			return Poll::Ready(ConnectionEvent::None)
		}

		match self.read_timeout.poll_unpin(cx) {
			Poll::Ready(()) => {
				log::trace!(target: "mixnet", "Peer, nothing received for too long, dropping.");
				return self.broken_connection(topology, peers)
			},
			Poll::Pending => (),
		}
		result
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

	pub(super) fn disconnected_kind(&mut self) -> ConnectedKind {
		let kind = self.kind;
		self.handshake_sent = false;
		self.handshake_received = false;
		self.kind = ConnectedKind::Disconnected;
		kind
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
