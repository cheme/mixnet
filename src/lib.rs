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


// TODO surbs: 
// - add surbs id to header: on receive if there is a surbs id, lookup in persistence, run n registered hop encode
// -> need a tag as receiving
// -> need a tag as message start by subs
// - surbs are just stored in message in first position and decode: surbsheader, first decode key,
// first hop address : in reverse order.
// Thats all

#[macro_use]
extern crate arrayref;

mod core;
mod network;

pub use crate::core::{
	public_from_ed25519, secret_from_ed25519, Config, Error, MixPublicKey, MixSecretKey, Topology,
};
pub use network::{DecodedMessage, Mixnet, NetworkEvent};
