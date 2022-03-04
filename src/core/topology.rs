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


// TODO layered topo with fix number of nodes, and elections??
// possibly with multiple node being able to act in a same slot: can even double the header size for
// it??
//
// TODO for layer, we define pool, and we like the fact that layers got a good connection between
// themselves.
// It also allow to think of mechanism to try to avoid peers being in multiple layers (same as
// avoid multiple peers on network): could use some staking/locking token.
// Should use some trust building token.
// Generally multiple system between layer.
// Actually none of this seems good.
// Could also keep a full pool layer: alas pool is biased too.
//
// TODO could each layer/group have multiple next layer possibility. Not trying to be acyclic, when
// creating the message we ensure no layer got queried twice.
//
// TODO topology only really help produce valid and resistant path.
// Peers are allowed to block message if they don't respect topology (they can always do but here
// they are expected too).
//
// TODO generaly group/layer should publish their rules.
//
// TODO does not work well as cover message needs to follow a unique scheme that the users want to
// follow too.
use crate::core::{MixPeerId, MixPublicKey};

/// Provide network topology information to the mixnet.
pub trait Topology: Send + 'static {
	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(&self) -> Option<MixPeerId>;

	/// For a given peer return a list of peers it is supposed to be connected to.
	fn neighbors(&self, id: &MixPeerId) -> Vec<(MixPeerId, MixPublicKey)>;
}
