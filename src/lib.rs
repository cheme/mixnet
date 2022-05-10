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

#[macro_use]
extern crate arrayref;

mod core;
mod network;

pub use crate::core::{
	public_from_ed25519, secret_from_ed25519, Config, Error, MixPublicKey, MixSecretKey,
	NoTopology, Packet, SurbsPayload, Topology, PACKET_SIZE,
};
pub use network::{
	DecodedMessage, MessageType, MixnetBehaviour, MixnetWorker, NetworkEvent, WorkerChannels,
	WorkerOut, WorkerSink, WorkerSink2, WorkerStream, Connection2,
};

/// Mixnet peer identity.
pub type MixPeerId = libp2p_core::PeerId;

/// Options for sending a message in the mixnet.
pub struct SendOptions {
	/// Number of hop for the message.
	/// If undefined, mixnet defined number of hop will be used.
	/// For its surbs the same number will be use.
	pub num_hop: Option<usize>,

	/// Do we attach a surbs with the message.
	pub with_surbs: bool,
}
