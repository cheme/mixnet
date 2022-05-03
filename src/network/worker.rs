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
	core::{Config, MixEvent, MixPublicKey, Mixnet, Packet, SurbsPayload, Topology},
	MessageType, MixPeerId, SendOptions,
};
use futures::{channel::mpsc::SendError, Sink, Stream};
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
	AddConnectedPeer(
		MixPeerId,
		MixPublicKey,
		ConnectionId,
	),
	AddConnectedInbound(MixPeerId, NegotiatedSubstream),
	AddConnectedOutbound(MixPeerId, NegotiatedSubstream),
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
	read_timeout: Delay, /* TODO this is quite unpolled: could poll it in the worker?? actually
	                      * on disconnect connection may stay open -> use keep alive of handler? */
	inbound: Option<NegotiatedSubstream>,
	outbound: Option<NegotiatedSubstream>,
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	limit_msg: Option<u32>,
	window_count: u32,
	current_window: Wrapping<usize>,
}

impl Connection {
	fn new(id: ConnectionId, limit_msg: Option<u32>) -> Self {
		Self {
			id,
			read_timeout: Delay::new(Duration::new(2, 0)),
			limit_msg,
			window_count: 0,
			current_window: Wrapping(0),
			inbound: None,
			outbound: None,
		}
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
					WorkerIn::AddConnectedPeer(
						peer,
						public_key,
						con_id,
					) => {
						self.connected.entry(peer.clone()).or_insert_with(|| {
							Connection::new(con_id, self.default_limit_msg.clone())
						});
						self.mixnet.add_connected_peer(peer, public_key);
					},
					WorkerIn::AddConnectedInbound(peer, inbound) => {
						if let Some(con) = self.connected.get_mut(&peer) {
							con.inbound = Some(inbound);
						} else {
							log::error!(target: "mixnet", "Inbound stream for unregistered peer: {:?}", peer);
						}
					},
					WorkerIn::AddConnectedOutbound(peer, outbound) => {
						if let Some(con) = self.connected.get_mut(&peer) {
							con.outbound = Some(outbound);
						} else {
							log::error!(target: "mixnet", "Outbound stream for unregistered peer: {:?}", peer);
						}
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

		Poll::Pending
	}
}
