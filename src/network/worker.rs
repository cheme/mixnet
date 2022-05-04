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

//! `NetworkBehaviour` can be to heavy (especially when shared with others), using
//! a worker allows sending the process to a queue instead of runing it directly.

use std::{collections::HashMap, num::Wrapping, time::Duration};

use crate::{
	core::{
		Config, Error, MixEvent, MixPublicKey, Mixnet, Packet, SurbsPayload, Topology,
		PUBLIC_KEY_LEN,
	},
	MessageType, MixPeerId, SendOptions,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	future::FutureExt,
	AsyncRead, AsyncWrite, Sink, Stream,
};
use futures_timer::Delay;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{ConnectionHandler, ConnectionHandlerEvent, KeepAlive, NegotiatedSubstream};
use std::{
	pin::Pin,
	task::{Context, Poll},
};

pub const WINDOW_LIMIT: Duration = Duration::from_secs(5);
pub type WorkerStream = Pin<Box<dyn Stream<Item = WorkerIn> + Send>>;
pub type WorkerSink = Pin<Box<dyn Sink<WorkerOut, Error = SendError> + Send>>;

pub enum WorkerIn {
	RegisterMessage(Option<MixPeerId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, SurbsPayload),
	AddConnectedPeer(MixPeerId, MixPublicKey, ConnectionId),
	AddConnectedInbound(MixPeerId, ConnectionId, Option<OneShotSender<()>>, NegotiatedSubstream),
	// TODO merge with AddConnectedInbound -> then remove lot of option)?
	AddConnectedOutbound(MixPeerId, ConnectionId, Option<OneShotSender<()>>, NegotiatedSubstream),
	RemoveConnectedPeer(MixPeerId),
	ImportMessage(MixPeerId, Packet),
}

pub enum WorkerOut {
	Event(MixEvent),
	ReceivedMessage(MixPeerId, Vec<u8>, MessageType),
}

/// Internal information tracked for an established connection.
struct Connection {
	id: ConnectionId,
	peer_id: MixPeerId,
	read_timeout: Delay, // TODO use handler TTL instead?
	inbound: Option<Pin<Box<NegotiatedSubstream>>>, // TOOD remove some pin with Ext traits
	outbound: Option<Pin<Box<NegotiatedSubstream>>>, /* TODO just use a single stream for in and
	                                                 * out? */
	outbound_waiting: Option<(Vec<u8>, usize)>,
	inbound_waiting: (Vec<u8>, usize),
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	limit_msg: Option<u32>,
	window_count: u32,
	current_window: Wrapping<usize>,
	public_key: Option<MixPublicKey>,
	handshake_flushing: bool,
	handshake_sent: bool,
	// inform connection handler when closing.
	oneshot_handler: Option<OneShotSender<()>>,
}

impl Connection {
	fn new(
		id: ConnectionId,
		peer_id: MixPeerId,
		limit_msg: Option<u32>,
		oneshot_handler: Option<OneShotSender<()>>,
	) -> Self {
		Self {
			id,
			peer_id,
			read_timeout: Delay::new(Duration::new(2, 0)),
			limit_msg,
			window_count: 0,
			current_window: Wrapping(0),
			inbound: None,
			outbound: None,
			outbound_waiting: None,
			inbound_waiting: (vec![0; crate::PACKET_SIZE], 0),
			public_key: None,
			handshake_flushing: false,
			handshake_sent: false,
			oneshot_handler,
		}
	}

	fn handshake_received(&self) -> bool {
		self.public_key.is_some()
	}

	fn is_ready(&self) -> bool {
		self.handshake_sent &&
			self.handshake_received() &&
			self.inbound.is_some() &&
			self.outbound.is_some()
	}

	// return true if not pending
	fn try_send_handshake(
		&mut self,
		cx: &mut Context,
		public_key: &MixPublicKey,
	) -> Result<bool, ()> {
		if self.handshake_flushing {
			if let Some(outbound) = self.outbound.as_mut() {
				match outbound.as_mut().poll_flush(cx) {
					Poll::Ready(Ok(())) => {
						self.handshake_flushing = false;
						self.handshake_sent = true;
					},
					Poll::Ready(Err(_)) => {
						return Err(());
					},
					Poll::Pending => {
						return Ok(false)
					},
				}
			}
		}
		if self.handshake_sent {
			return Ok(false)
		}
		if let Some(outbound) = self.outbound.as_mut() {
			let (handshake, mut ix) = self
				.outbound_waiting
				.take()
				.unwrap_or_else(|| (public_key.to_bytes().to_vec(), 0));

			match outbound.as_mut().poll_write(cx, &handshake.as_slice()[ix..]) {
				Poll::Pending => {
					// Not ready, buffing in next
					self.outbound_waiting = Some((handshake, ix));
				},
				Poll::Ready(Ok(nb)) => {
					ix += nb;
					if ix == handshake.len() {
						self.handshake_flushing = true;
					} else {
						self.outbound_waiting = Some((handshake, ix));
					}
					return Ok(true)
				},
				Poll::Ready(Err(e)) => {
					log::trace!(target: "mixnet", "Error sending to peer, closing: {:?}", e);
					return Err(())
				},
			}
		}

		Ok(false)
	}

	// return true if not pending
	fn try_recv_handshake(&mut self, cx: &mut Context) -> Result<bool, ()> {
		if self.handshake_received() {
			return Ok(false)
		}
		if let Some(inbound) = self.inbound.as_mut() {
			match inbound
				.as_mut()
				.poll_read(cx, &mut self.inbound_waiting.0[self.inbound_waiting.1..PUBLIC_KEY_LEN])
			{
				Poll::Pending => (),
				Poll::Ready(Ok(nb)) => {
					self.read_timeout.reset(Duration::new(2, 0));
					self.inbound_waiting.1 += nb;
					if self.inbound_waiting.1 == PUBLIC_KEY_LEN {
						let mut pk = [0u8; PUBLIC_KEY_LEN];
						pk.copy_from_slice(&self.inbound_waiting.0[..PUBLIC_KEY_LEN]);
						self.inbound_waiting.1 = 0;
						self.public_key = Some(MixPublicKey::from(pk));
						log::trace!(target: "mixnet", "Handshake message from {:?}", self.peer_id);
					}
					return Ok(true)
				},
				Poll::Ready(Err(e)) => {
					log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", e);
					return Err(())
				},
			}
		}

		Ok(false)
	}
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<T> {
	pub mixnet: Mixnet<T>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,

	default_limit_msg: Option<u32>,
	current_window: Wrapping<usize>,
	window_delay: Delay,

	connected: HashMap<PeerId, Connection>,
}

impl<T: Topology> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let default_limit_msg = config.limit_per_window;
		let (worker_out, worker_in) = inner_channels;
		let mixnet = crate::core::Mixnet::new(config, topology);
		let window_delay = Delay::new(WINDOW_LIMIT);
		MixnetWorker {
			mixnet,
			worker_in,
			worker_out,
			connected: Default::default(),
			current_window: Wrapping(0),
			default_limit_msg,
			window_delay,
		}
	}

	pub fn local_id(&self) -> &MixPeerId {
		self.mixnet.local_id()
	}

	pub fn change_peer_limit_window(&mut self, peer: MixPeerId, new_limit: Option<u32>) {
		if let Err(e) = self
			.worker_out
			.as_mut()
			.start_send(WorkerOut::Event(MixEvent::ChangeLimit(peer, new_limit)))
		{
			log::error!(target: "mixnet", "Error sending event to channel: {:?}", e);
		}
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<bool> {
		if let Poll::Ready(e) = self.mixnet.poll(cx) {
			if let Err(e) = self.worker_out.as_mut().start_send(WorkerOut::Event(e)) {
				log::error!(target: "mixnet", "Error sending event to channel: {:?}", e);
				if e.is_disconnected() {
					return Poll::Ready(false)
				}
			}
		}

		match self.worker_in.as_mut().poll_next(cx) {
			Poll::Ready(Some(message)) =>
				match message {
					WorkerIn::RegisterMessage(peer_id, message, send_options) => {
						match self.mixnet.register_message(peer_id, message, send_options) {
							Ok(()) => (),
							Err(e) => {
								log::error!(target: "mixnet", "Error registering message: {:?}", e);
							},
						}
						return Poll::Ready(true)
					},
					WorkerIn::RegisterSurbs(message, surbs) => {
						match self.mixnet.register_surbs(message, surbs) {
							Ok(()) => (),
							Err(e) => {
								log::error!(target: "mixnet", "Error registering surbs: {:?}", e);
							},
						}
						return Poll::Ready(true)
					},
					WorkerIn::AddConnectedPeer(peer, public_key, con_id) => {
						unimplemented!("TODO remove: part of handshake");
						/*						let con = self.connected.entry(peer.clone()).or_insert_with(|| {
							Connection::new(con_id, self.default_limit_msg.clone())
						});

						log::error!(target: "mixnet", "added peer: {:?}", (peer, con.inbound.is_some(), con.outbound.is_some()));
						self.mixnet.add_connected_peer(peer, public_key);*/
					},
					WorkerIn::AddConnectedInbound(peer, con_id, mut handler, inbound) => {
						let con = self.connected.entry(peer.clone()).or_insert_with(|| {
							Connection::new(
								con_id,
								peer.clone(),
								self.default_limit_msg.clone(),
								handler.take(),
							)
						});
						con.inbound = Some(Box::pin(inbound));
						con.inbound_waiting.1 = 0;
						if handler.is_some() {
							con.oneshot_handler = handler;
						}
						log::error!(target: "mixnet", "added peer in: {:?}", (peer, con.inbound.is_some(), con.outbound.is_some()));
					},
					WorkerIn::AddConnectedOutbound(peer, con_id, mut handler, outbound) => {
						let con = self.connected.entry(peer.clone()).or_insert_with(|| {
							Connection::new(
								con_id,
								peer.clone(),
								self.default_limit_msg.clone(),
								handler.take(),
							)
						});
						con.outbound = Some(Box::pin(outbound));
						con.outbound_waiting = None;
						if handler.is_some() {
							con.oneshot_handler = handler;
						}
						log::error!(target: "mixnet", "added peer out: {:?}", (peer, con.inbound.is_some(), con.outbound.is_some()));
					},
					WorkerIn::RemoveConnectedPeer(peer) => {
						self.mixnet.remove_connected_peer(&peer);
					},
					WorkerIn::ImportMessage(peer, message) => {
						match self.mixnet.import_message(peer, message) {
							Ok(Some((full_message, surbs))) => {
								if let Err(e) = self.worker_out.as_mut().start_send(
									WorkerOut::ReceivedMessage(peer, full_message, surbs),
								) {
									log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
									if e.is_disconnected() {
										return Poll::Ready(false)
									}
								}
							},
							Ok(None) => (),
							Err(e) => {
								log::warn!(target: "mixnet", "Error importing message: {:?}", e);
							},
						}
					},
				},
			Poll::Ready(None) => {
				// handler dropped, shutting down.
				log::debug!(target: "mixnet", "Worker input closed, shutting down.");
				return Poll::Ready(false)
			},
			_ => (),
		}

		let mut result = Poll::Pending;
		let mut disconnected = Vec::new();
		for (_, connection) in self.connected.iter_mut() {
			if !connection.is_ready() {
				match connection.try_recv_handshake(cx) {
					Ok(true) => {
						result = Poll::Ready(true);
					},
					Ok(false) => (),
					Err(()) => {
						connection.oneshot_handler.take().map(|s| s.send(()));
						disconnected.push(connection.peer_id.clone());
						continue
					},
				}
				match connection.try_send_handshake(cx, &self.mixnet.public) {
					Ok(true) => {
						result = Poll::Ready(true);
					},
					Ok(false) => (),
					Err(()) => {
						connection.oneshot_handler.take().map(|s| s.send(()));
						disconnected.push(connection.peer_id.clone());
						continue
					},
				}
				match connection.read_timeout.poll_unpin(cx) {
					Poll::Ready(()) => {
						connection.oneshot_handler.take().map(|s| s.send(()));
						disconnected.push(connection.peer_id.clone());
					},
					Poll::Pending => (),
				}
			}
		}
		for peer in disconnected {
			self.connected.remove(&peer);
		}

		result
	}
}
