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

// This module is largely based on the the Sphinx implementation by David Stainton
// at https://github.com/sphinx-cryptography/rust-sphinxcrypto
// and loosely follows Katzenpost specification.
//
// Notable changes include:
// * Switching to Lioness cipher for payload encryption.
// * Simplifying routing commands into a fixed structure: a node id and some reserved node id for
// the command variant (last nodes, last node with SURB and last node from SURB).
// * Drop support for Delay command.

///! Sphinx packet format.
mod crypto;

use super::HeaderInfo;
use crate::core::{Packet, ReplayFilter, ReplayTag, SurbsCollection};
pub use crypto::{hash, HASH_OUTPUT_SIZE};
use crypto::{PacketKeys, StreamCipher, GROUP_ELEMENT_SIZE, MAC_SIZE, SPRP_KEY_SIZE};
use rand::{CryptoRng, Rng};
use std::time::Instant;
use subtle::ConstantTimeEq;

pub type StaticSecret = x25519_dalek::StaticSecret;
pub type PublicKey = x25519_dalek::PublicKey;
pub type Delay = u32;
pub type NodeId = [u8; NODE_ID_SIZE];

type Header = [u8; HEADER_SIZE];
type RawKey = [u8; KEY_SIZE];
type HeaderWithInfo = (Header, HeaderInfo);

/// Maximum hops the packet format supports.
pub const MAX_HOPS: usize = 5;
pub const OVERHEAD_SIZE: usize = HEADER_SIZE + PAYLOAD_TAG_SIZE;

/// The node identifier size in bytes.
const NODE_ID_SIZE: usize = 32;

const KEY_SIZE: usize = 32;

/// Empty node id, last hop.
const EMPTY_ID_NO_SURB: NodeId = [0u8; NODE_ID_SIZE];

/// Empty node id, last hop.
const EMPTY_ID_WITH_SURB: NodeId = [1u8; NODE_ID_SIZE];

/// Empty node id, last hop, this is a surb reply.
const EMPTY_ID_REPLY: NodeId = [2u8; NODE_ID_SIZE];

/// The "authenticated data" portion of the Sphinx
/// packet header which as specified contains the
/// version number.
const AD_SIZE: usize = 2;

/// The first section of our Sphinx packet, the authenticated
/// unencrypted data containing version number.
const V0_AD: [u8; AD_SIZE] = [0u8; 2];

/// The size in bytes of the payload tag.
pub const PAYLOAD_TAG_SIZE: usize = 16;

/// Tag for payload authentication purpose.
const PAYLOAD_TAG: [u8; PAYLOAD_TAG_SIZE] = [0u8; PAYLOAD_TAG_SIZE];

/// The size of the Sphinx packet header in bytes.
pub(crate) const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// Size of the surb definition in payload.
pub(crate) const SURB_REPLY_SIZE: usize = NODE_ID_SIZE + SPRP_KEY_SIZE + HEADER_SIZE;

/// The size in bytes of each routing info slot.
const PER_HOP_ROUTING_INFO_SIZE: usize = NODE_ID_SIZE + MAC_SIZE;

/// The size in bytes of the routing info section of the packet
/// header.
const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * MAX_HOPS;

const GROUP_ELEMENT_OFFSET: usize = AD_SIZE;
const ROUTING_INFO_OFFSET: usize = GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE;
const MAC_OFFSET: usize = ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE;

const NEXT_HOP_MAC_OFFSET: usize = NODE_ID_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Invalid packet size or wrong authenticated data.
	InvalidPacket,
	/// Payload authentication mismatch.
	Payload,
	/// MAC mismatch.
	MACmismatch,
	/// Payload decryption error.
	PayloadDecrypt,
	/// Payload encryption error.
	PayloadEncrypt,
	/// Surb missing error.
	MissingSurb,
	/// Message already seen.
	Replay,
}

/// PathHop describes a route hop that a Sphinx Packet will traverse,
#[derive(Clone, Debug)]
pub struct PathHop {
	/// Node id
	pub id: NodeId,
	/// ECDH Public key for the node.
	pub public_key: PublicKey,
}

/// SprpKey is a struct that contains a SPRP (Strong Pseudo-Random Permutation) key.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SprpKey {
	pub key: [u8; SPRP_KEY_SIZE],
}

fn blind(pk: PublicKey, factor: [u8; KEY_SIZE]) -> PublicKey {
	PublicKey::from(x25519_dalek::x25519(factor, pk.to_bytes()))
}

#[derive(Clone)]
struct NextHop {
	pub id: NodeId,
	pub mac: [u8; MAC_SIZE],
}

pub enum Unwrapped {
	Forward((NodeId, Delay, Packet)),
	Payload(Vec<u8>),
	PayloadWithSurb(Vec<u8>, Vec<u8>),
	SurbReply(Vec<u8>, Box<(crate::MixPeerId, crate::MixPublicKey)>),
}
enum NextHopOutcome {
	Forward(NextHop),
	Payload,
	PayloadWithSurb,
	SurbReply,
}

pub struct SentSurbInfo {
	pub keys: Vec<SprpKey>,
	pub recipient: (crate::MixPeerId, crate::MixPublicKey),
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[repr(C)]
pub struct SurbPayload {
	pub first_node: NodeId,
	pub first_key: SprpKey,
	pub header: Header,
}

unsafe impl bytemuck::Zeroable for SurbPayload {}
unsafe impl bytemuck::Pod for SurbPayload {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct EncodedSurbPayload([u8; SURB_REPLY_SIZE]);

unsafe impl bytemuck::Zeroable for EncodedSurbPayload {}
unsafe impl bytemuck::Pod for EncodedSurbPayload {}

impl From<Vec<u8>> for SurbPayload {
	fn from(encoded: Vec<u8>) -> Self {
		let buf: &[u8; SURB_REPLY_SIZE] =
			unsafe { &*(encoded.as_slice().as_ptr() as *const [u8; SURB_REPLY_SIZE]) };
		bytemuck::cast(EncodedSurbPayload(*buf))
	}
}

impl SurbPayload {
	fn append_to(&self, dest: &mut Vec<u8>) {
		dest.extend_from_slice(&self.first_node[..]);
		dest.extend_from_slice(&self.first_key.key[..]);
		dest.extend_from_slice(&self.header[..]);
	}
}

struct EncodedHop<'a>(&'a mut [u8]);

impl<'a> EncodedHop<'a> {
	fn next_hop(&self) -> NextHopOutcome {
		let mut id = [0u8; NODE_ID_SIZE];
		id.copy_from_slice(&self.0[..NODE_ID_SIZE]);
		if id == EMPTY_ID_NO_SURB {
			NextHopOutcome::Payload
		} else if id == EMPTY_ID_WITH_SURB {
			NextHopOutcome::PayloadWithSurb
		} else if id == EMPTY_ID_REPLY {
			NextHopOutcome::SurbReply
		} else {
			let mut mac = [0u8; MAC_SIZE];
			mac.copy_from_slice(&self.0[NEXT_HOP_MAC_OFFSET..NEXT_HOP_MAC_OFFSET + MAC_SIZE]);
			NextHopOutcome::Forward(NextHop { id, mac })
		}
	}

	fn set_next_hop(&mut self, hop: NextHop) {
		self.0[..NODE_ID_SIZE].copy_from_slice(&hop.id);
		self.0[NEXT_HOP_MAC_OFFSET..NEXT_HOP_MAC_OFFSET + MAC_SIZE].copy_from_slice(&hop.mac);
	}
}

fn create_header<T: Rng + CryptoRng>(
	rng: &mut T,
	path: Vec<PathHop>,
	surb_header: bool,
	with_surb: bool,
) -> Result<HeaderWithInfo, Error> {
	let num_hops = path.len();
	// Derive the key material for each hop.
	let mut raw_key: [u8; KEY_SIZE] = Default::default();
	rng.fill_bytes(&mut raw_key);
	let secret_key = StaticSecret::from(raw_key);
	let mut group_elements: Vec<PublicKey> = vec![];
	let mut keys: Vec<PacketKeys> = vec![];
	let mut shared_secret: [u8; GROUP_ELEMENT_SIZE] =
		secret_key.diffie_hellman(&path[0].public_key).to_bytes();
	keys.push(crypto::kdf(&shared_secret));
	let mut group_element = PublicKey::from(&secret_key);
	group_elements.push(group_element);

	let mut header = [0u8; HEADER_SIZE];
	header[0..AD_SIZE].copy_from_slice(&V0_AD);

	for i in 1..num_hops {
		// Last key of surb do not have to be derived, but doing for code clarity.
		shared_secret = secret_key.diffie_hellman(&path[i].public_key).to_bytes();
		let mut j = 0;
		while j < i {
			shared_secret = x25519_dalek::x25519(keys[j].blinding_factor, shared_secret);
			j += 1;
		}
		keys.push(crypto::kdf(&shared_secret));
		group_element = blind(group_element, keys[i - 1].blinding_factor);
		group_elements.push(group_element);
	}

	let surb_id = if surb_header { Some(ReplayTag(hash(&shared_secret))) } else { None };
	// Derive the routing_information keystream and encrypted padding
	// for each hop.
	let mut ri_keystream: Vec<Vec<u8>> = vec![];
	let mut ri_padding: Vec<Vec<u8>> = vec![];
	for i in 0..num_hops {
		let mut steam_cipher =
			StreamCipher::new(&keys[i].header_encryption, &keys[i].header_encryption_iv);
		let stream = steam_cipher.generate(ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE); // Extra hop for padding
		let ks_len = stream.len() - ((i + 1) * PER_HOP_ROUTING_INFO_SIZE);
		ri_keystream.push(stream[..ks_len].to_vec());
		ri_padding.push(stream[ks_len..].to_vec());
		if i > 0 {
			let prev_pad_len = ri_padding[i - 1].len();
			let current = ri_padding[i - 1].clone();
			lioness::xor_assign(&mut ri_padding[i][..prev_pad_len], &current);
		}
	}

	// Create the routing_information block.
	let routing_info = &mut header[ROUTING_INFO_OFFSET..ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE];
	let mut mac = [0u8; MAC_SIZE];

	let skipped_hops = MAX_HOPS - num_hops;
	if skipped_hops > 0 {
		rng.fill_bytes(&mut routing_info[(MAX_HOPS - skipped_hops) * PER_HOP_ROUTING_INFO_SIZE..]);
	}
	if with_surb {
		let offset = (num_hops - 1) * PER_HOP_ROUTING_INFO_SIZE;
		routing_info[offset..offset + NODE_ID_SIZE].copy_from_slice(&EMPTY_ID_WITH_SURB[..]);
	}
	if surb_header {
		let offset = (num_hops - 1) * PER_HOP_ROUTING_INFO_SIZE;
		routing_info[offset..offset + NODE_ID_SIZE].copy_from_slice(&EMPTY_ID_REPLY[..]);
	}
	let mut hop_index = num_hops - 1;
	loop {
		let hop_slice = &mut routing_info[hop_index * PER_HOP_ROUTING_INFO_SIZE..];
		let mut hop = EncodedHop(hop_slice);
		if hop_index != num_hops - 1 {
			hop.set_next_hop(NextHop { id: path[hop_index + 1].id, mac });
		}

		lioness::xor_assign(hop_slice, ri_keystream[hop_index].as_slice());
		let padding = if hop_index > 0 { ri_padding[hop_index - 1].as_slice() } else { &[] };
		let mac_data = [&group_elements[hop_index].as_bytes()[..], hop_slice, padding];
		mac = crypto::hmac_list(&keys[hop_index].header_mac, &mac_data);

		if hop_index == 0 {
			break
		}
		hop_index -= 1;
	}

	// Assemble the completed Sphinx Packet Header and Sphinx Packet Payload
	// SPRP key vector.
	header[GROUP_ELEMENT_OFFSET..GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE]
		.copy_from_slice(group_elements[0].as_bytes());
	header[MAC_OFFSET..].copy_from_slice(&mac);

	let mut sprp_keys = vec![];
	let mut i = 0;
	while i < num_hops {
		let k = SprpKey { key: keys[i].payload_encryption };
		sprp_keys.push(k);
		i += 1
	}
	Ok((header, HeaderInfo { sprp_keys, surb_id }))
}

/// Create a new sphinx packet
pub fn new_packet<T: Rng + CryptoRng>(
	mut rng: T,
	path: Vec<PathHop>,
	payload: Vec<u8>,
	with_surb: Option<(NodeId, Vec<PathHop>)>,
) -> Result<(Packet, Option<HeaderInfo>), Error> {
	let (header, HeaderInfo { sprp_keys, .. }) =
		create_header(&mut rng, path, false, with_surb.is_some())?;

	// prepend payload tag of zero bytes
	let mut tagged_payload;
	let surb_key = if let Some((first_node, path)) = with_surb {
		tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + SURB_REPLY_SIZE + payload.len());
		let (header, HeaderInfo { sprp_keys, surb_id }) =
			create_header(&mut rng, path, true, false)?;

		debug_assert!(header.len() == HEADER_SIZE);
		tagged_payload.resize(PAYLOAD_TAG_SIZE, 0u8);
		let first_key = SprpKey { key: sprp_keys[sprp_keys.len() - 1].key };
		let encoded = SurbPayload { first_node, first_key, header };
		debug_assert!(tagged_payload.len() == PAYLOAD_TAG_SIZE);
		encoded.append_to(&mut tagged_payload);
		debug_assert!(
			tagged_payload.len() == SURB_REPLY_SIZE + PAYLOAD_TAG_SIZE,
			"{:?}",
			(tagged_payload.len(), SURB_REPLY_SIZE + PAYLOAD_TAG_SIZE)
		);
		debug_assert!(
			crate::core::fragment::FRAGMENT_PACKET_SIZE == SURB_REPLY_SIZE + payload.len()
		);
		Some(HeaderInfo { sprp_keys, surb_id })
	} else {
		tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + payload.len());
		tagged_payload.resize(PAYLOAD_TAG_SIZE, 0u8);
		None
	};
	tagged_payload.extend_from_slice(&payload);

	// encrypt tagged payload with SPRP
	for key in sprp_keys.into_iter().rev() {
		tagged_payload =
			crypto::sprp_encrypt(&key.key, tagged_payload).map_err(|_| Error::PayloadEncrypt)?;
	}

	let packet = Packet::new(&header[..], &tagged_payload[..]);
	Ok((packet, surb_key))
}

/// Create a new sphinx packet from a surb header.
pub fn new_surb_packet(
	first_key: SprpKey,
	message: Vec<u8>,
	surb_header: Header,
) -> Result<Packet, Error> {
	let mut tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + message.len());
	tagged_payload.resize(PAYLOAD_TAG_SIZE, 0u8);
	tagged_payload.extend_from_slice(&message[..]);
	tagged_payload =
		crypto::sprp_encrypt(&first_key.key, tagged_payload).map_err(|_| Error::PayloadEncrypt)?;

	let packet = Packet::new(&surb_header[..], &tagged_payload[..]);
	Ok(packet)
}

/// Unwrap one layer of encryption and return next layer information or the final payload.
pub fn unwrap_packet(
	private_key: &StaticSecret,
	mut packet: Packet,
	surb: &mut SurbsCollection,
	filter: &mut ReplayFilter,
	next_delay: impl FnOnce() -> u32,
) -> Result<Unwrapped, Error> {
	// Split into mutable references and validate the AD
	let (header, payload) = packet.as_mut().split_at_mut(HEADER_SIZE);
	let (authed_header, header_mac) = header.split_at_mut(MAC_OFFSET);
	let (ad, after_ad) = authed_header.split_at_mut(AD_SIZE);
	let (group_element_bytes, routing_info) = after_ad.split_at_mut(GROUP_ELEMENT_SIZE);

	if ad.ct_eq(&V0_AD).unwrap_u8() == 0 {
		return Err(Error::InvalidPacket)
	}

	let group_element_bytes: &mut [u8; GROUP_ELEMENT_SIZE] =
		unsafe { &mut *(group_element_bytes.as_ptr() as *mut [u8; GROUP_ELEMENT_SIZE]) };

	// Calculate the hop's shared secret, and replay_tag.
	let mut group_element = PublicKey::from(*group_element_bytes);
	let shared_secret = private_key.diffie_hellman(&group_element);

	let replay_tag = ReplayTag(hash(shared_secret.as_bytes()));
	if filter.contains(&replay_tag) {
		log::trace!(target: "mixnet", "Seen replay {:?}", &replay_tag);
		return Err(Error::Replay)
	}

	// Derive the various keys required for packet processing.
	let keys = crypto::kdf(shared_secret.as_bytes());

	// Validate the Sphinx Packet Header.
	let mac_key = keys.header_mac;
	let mac_data = [&group_element_bytes[..], routing_info];
	let calculated_mac = crypto::hmac_list(&mac_key, &mac_data);

	// compare MAC in constant time
	if calculated_mac.ct_eq(header_mac).unwrap_u8() == 0 {
		return Err(Error::MACmismatch)
	}

	// Append padding to preserve length invariance, decrypt the (padded)
	// routing_info block, and extract the section for the current hop.
	let mut stream_cipher = StreamCipher::new(&keys.header_encryption, &keys.header_encryption_iv);
	let mut a = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
	let mut b = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
	a[..ROUTING_INFO_SIZE].clone_from_slice(routing_info);
	stream_cipher.xor_key_stream(&mut b, &a);
	let (cmd_buf, new_routing_info) = b.split_at_mut(PER_HOP_ROUTING_INFO_SIZE);

	// Parse the per-hop routing commands.
	let hop = EncodedHop(cmd_buf);
	let maybe_next_hop = hop.next_hop();

	// Transform the packet for forwarding to the next mix
	match maybe_next_hop {
		NextHopOutcome::Forward(next_hop) => {
			let decrypted_payload =
				crypto::sprp_decrypt(&keys.payload_encryption, payload.to_vec())
					.map_err(|_| Error::PayloadDecrypt)?;

			group_element = blind(group_element, keys.blinding_factor);
			group_element_bytes.copy_from_slice(group_element.as_bytes());
			routing_info.copy_from_slice(new_routing_info);
			header_mac.copy_from_slice(&next_hop.mac);
			payload.copy_from_slice(&decrypted_payload);
			filter.insert(replay_tag, Instant::now());

			Ok(Unwrapped::Forward((next_hop.id, next_delay(), packet)))
		},
		NextHopOutcome::Payload => {
			let mut decrypted_payload =
				crypto::sprp_decrypt(&keys.payload_encryption, payload.to_vec())
					.map_err(|_| Error::PayloadDecrypt)?;
			if decrypted_payload[..PAYLOAD_TAG_SIZE] != PAYLOAD_TAG {
				return Err(Error::Payload)
			}
			let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
			filter.insert(replay_tag, Instant::now());
			Ok(Unwrapped::Payload(decrypted_payload))
		},
		NextHopOutcome::PayloadWithSurb => {
			let mut decrypted_payload =
				crypto::sprp_decrypt(&keys.payload_encryption, payload.to_vec())
					.map_err(|_| Error::PayloadDecrypt)?;
			if decrypted_payload[..PAYLOAD_TAG_SIZE] != PAYLOAD_TAG {
				return Err(Error::Payload)
			}
			let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
			let payload = decrypted_payload.split_off(SURB_REPLY_SIZE);
			filter.insert(replay_tag, Instant::now());
			Ok(Unwrapped::PayloadWithSurb(decrypted_payload, payload))
		},
		NextHopOutcome::SurbReply =>
		// Previous reading of header was only for hmac.
			read_surb_payload(&replay_tag, payload.to_vec(), surb),
	}
}

pub fn read_surb_payload(
	replay_tag: &ReplayTag,
	payload: Vec<u8>,
	surb: &mut SurbsCollection,
) -> Result<Unwrapped, Error> {
	// Split into mutable references and validate the AD
	match surb.pending.remove(replay_tag) {
		Some(surb) => {
			//
			let mut decrypted_payload = payload;
			let nb_key = surb.keys.len();
			for key in surb.keys[..nb_key - 1].iter().rev() {
				decrypted_payload = crypto::sprp_encrypt(&key.key, decrypted_payload)
					.map_err(|_| Error::PayloadDecrypt)?;
			}
			let first_key = &surb.keys[nb_key - 1].key;
			decrypted_payload = crypto::sprp_decrypt(first_key, decrypted_payload)
				.map_err(|_| Error::PayloadDecrypt)?;
			if decrypted_payload[..PAYLOAD_TAG_SIZE] != PAYLOAD_TAG {
				return Err(Error::Payload)
			}
			let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
			Ok(Unwrapped::SurbReply(decrypted_payload, Box::new(surb.recipient)))
		},
		None => {
			log::trace!(target: "mixnet", "Surb reply received after timeout {:?}", &replay_tag);
			Err(Error::MissingSurb)
		},
	}
}

#[cfg(test)]
mod test {
	use super::{
		Delay, HeaderInfo, NodeId, PathHop, PublicKey, RawKey, StaticSecret, Unwrapped, MAX_HOPS,
	};
	use rand::{rngs::OsRng, CryptoRng, RngCore};

	struct NodeParams {
		pub id: NodeId,
		pub private_key: StaticSecret,
	}

	fn new_node<T: RngCore + CryptoRng + Copy>(mut csprng: T) -> NodeParams {
		let mut id = NodeId::default();
		csprng.fill_bytes(&mut id);
		let mut raw_key: RawKey = Default::default();
		csprng.fill_bytes(&mut raw_key);
		let private_key = StaticSecret::from(raw_key);
		NodeParams { id, private_key }
	}

	fn new_path_vector<T: RngCore + CryptoRng + Copy>(
		csprng: T,
		num_hops: u8,
	) -> (Vec<NodeParams>, Vec<PathHop>, Vec<Delay>) {
		const DELAY_BASE: u32 = 123;

		// Generate the keypairs and node identifiers for the "nodes".
		let mut nodes = vec![];
		for _ in 0..num_hops {
			nodes.push(new_node(csprng));
		}

		// Assemble the path vector.
		let mut path = vec![];
		let mut delays = vec![];
		for i in 0..num_hops {
			let delay = DELAY_BASE * (i as u32 + 1);
			let public_key = PublicKey::from(&nodes[i as usize].private_key);
			path.push(PathHop { id: nodes[i as usize].id, public_key });
			delays.push(delay);
		}
		(nodes, path, delays)
	}

	#[test]
	fn sphinx_forward_test() {
		let payload = b"We must defend our own privacy if we expect to have any. \
    We must come together and create systems which allow anonymous transactions to take place. \
    People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
    closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
    privacy, but electronic technologies do.";

		let keypair = libp2p_core::identity::Keypair::generate_ed25519();
		let network_id = keypair.public().into();
		let id = crate::core::to_mix_peer_id(&network_id).unwrap();
		let config = crate::Config::new(id);
		// Generate the "nodes" and path for the forward sphinx packet.
		let mut num_hops = 1;
		while num_hops <= MAX_HOPS {
			let _tuple = new_path_vector(OsRng, num_hops as u8);
			let nodes = _tuple.0;
			let path = _tuple.1;
			let delays = _tuple.2;
			let path_c = path.clone();
			let recipient =
				(path.last().as_ref().unwrap().id, path.last().as_ref().unwrap().public_key);
			let mut surb_collection = super::SurbsCollection::new(&config);
			let mut replay_filter = super::ReplayFilter::new(&config);

			let mut payload = payload.to_vec();
			let paylod_len = crate::core::PACKET_SIZE -
				crate::core::sphinx::HEADER_SIZE -
				crate::core::sphinx::PAYLOAD_TAG_SIZE;
			payload.resize(paylod_len, 0u8);
			// Create the packet.
			let (mut packet, surb_keys) =
				super::new_packet(OsRng, path, payload.to_vec(), None).unwrap();
			if let Some(HeaderInfo { sprp_keys: keys, surb_id: Some(surb_id) }) = surb_keys {
				let persistance = crate::core::sphinx::SentSurbInfo { keys, recipient };
				surb_collection.insert(surb_id, persistance.into(), std::time::Instant::now());
			}

			// Unwrap the packet, validating the output.
			for i in 0..num_hops {
				let next_delay = || delays[i + 1];
				let unwrap_result = super::unwrap_packet(
					&nodes[i].private_key,
					packet,
					&mut surb_collection,
					&mut replay_filter,
					next_delay,
				)
				.unwrap();

				if i == nodes.len() - 1 {
					let p = match unwrap_result {
						Unwrapped::Payload(p) => p,
						_ => panic!("Unexpected result"),
					};
					assert_eq!(p.as_slice(), &payload[..]);
					return
				} else {
					let (id, delay, next) = match unwrap_result {
						Unwrapped::Forward(f) => f,
						_ => panic!("Unexpected result"),
					};
					let hop = &path_c[i + 1];
					assert_eq!(delay, delays[i + 1]); // a bit useless test with delay out of frame
					assert_eq!(id, hop.id);
					packet = next;
				}
			}
			num_hops += 1;
		}
	}
}
