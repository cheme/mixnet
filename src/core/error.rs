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

use crate::core::sphinx::Error as SphinxError;
/// Error handling
use crate::{MixPeerId, NetworkPeerId};
use std::fmt;

/// Mixnet generic error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Attempting to send oversized message.
	MessageTooLarge,
	/// Sphinx format error.
	SphinxError(SphinxError),
	/// No path to give peer or no random peer to select from.
	NoPath(Option<MixPeerId>),
	/// Invalid network id.
	InvalidId(NetworkPeerId),
	/// Invalid id in the Sphinx packet.
	InvalidSphinxId(MixPeerId),
	/// Invalid message fragment format.
	BadFragment,
	/// Packet queue is full.
	QueueFull,
	/// Surb reply not expected.
	UnexpectedSurbReply,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::MessageTooLarge => write!(f, "Mix message is too large."),
			Error::SphinxError(e) => write!(f, "Sphinx packet format error: {:?}.", e),
			Error::NoPath(p) => write!(f, "No path to {:?}.", p),
			Error::InvalidId(id) => write!(f, "Invalid peer id: {}.", id),
			Error::InvalidSphinxId(id) =>
				write!(f, "Invalid peer id in the Sphinx packet: {:?}.", id),
			Error::BadFragment => write!(f, "Bad message fragment."),
			Error::QueueFull => write!(f, "Packet queue is full."),
			Error::UnexpectedSurbReply => write!(f, "Surb reply received but not expected."),
		}
	}
}
