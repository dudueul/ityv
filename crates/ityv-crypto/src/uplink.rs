//! Uplink hashes (ADR-0022, ADR-0041; PROTOCOL.md §5.8; ENCODING.md
//! §8.22–§8.24, §8.82–§8.83).
//!
//! * [`link_id`]: a link is a transmitter, named by its frame key:
//!   `SHA3-512("ityv:link:v1" ‖ 0x00 ‖ frame_key)`.
//! * [`chain_start`], [`chain_next`]: the gateway's chain over a link's
//!   frames: `h_0 = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ link_id_hash)`,
//!   `h_i = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ h_{i−1} ‖ header_hash_i)`,
//!   where `header_hash_i` is the object hash of the frame's
//!   `UplinkFrameHeader`.
//! * [`chunk_leaf`], [`payload_root`], [`payload_root_of`]: the frame's
//!   payload, zero-extended to 1,048,576 bytes, in 256 chunks of 4,096
//!   bytes; leaf `SHA3-512("ityv:uplink-chunk:v1" ‖ 0x00 ‖ chunk)`, node
//!   `SHA3-512("ityv:uplink-node:v1" ‖ 0x00 ‖ left ‖ right)`, a perfect
//!   binary tree. A root rebuilt from a frame's data-chunk leaves and the
//!   [`zero_leaf`] proves every later chunk zero (the padding proof).
//! * [`capture_hash`]: `SHA3-512("ityv:capture:v1" ‖ 0x00 ‖ file)`, the
//!   hash an observer signs for a capture file.
//!
//! What this module does not prove: that a root is the device's (the
//! frame signature does), that a chain is the gateway's (the session
//! signature does), or anything about bytes it is not given.

use ityv_encoding::{CHUNK_LEN, FRAME_KEY_LEN, Hash512, PAYLOAD_CHUNKS};

use crate::hash::Hasher;

/// Label of a link identifier.
pub const LINK_LABEL: &[u8] = b"ityv:link:v1";
/// Label of the gateway's chain.
pub const CHAIN_LABEL: &[u8] = b"ityv:uplink:v1";
/// Label of a payload chunk leaf.
pub const CHUNK_LABEL: &[u8] = b"ityv:uplink-chunk:v1";
/// Label of a payload tree node.
pub const NODE_LABEL: &[u8] = b"ityv:uplink-node:v1";
/// Label of a capture file hash.
pub const CAPTURE_LABEL: &[u8] = b"ityv:capture:v1";

/// The depth of the payload tree: `2^8 = 256` leaves.
const TREE_DEPTH: usize = 8;

fn labelled(label: &[u8], parts: &[&[u8]]) -> Hash512 {
    let mut hasher = Hasher::new();
    hasher.absorb(label);
    hasher.absorb(&[0x00]);
    for p in parts {
        hasher.absorb(p);
    }
    Hash512(hasher.finish())
}

/// The link of the transmitter whose frame key is `frame_key`.
#[must_use]
pub fn link_id(frame_key: &[u8; FRAME_KEY_LEN]) -> Hash512 {
    labelled(LINK_LABEL, &[frame_key])
}

/// The chain head before a link's first frame.
#[must_use]
pub fn chain_start(link_id_hash: &Hash512) -> Hash512 {
    labelled(CHAIN_LABEL, &[link_id_hash.as_bytes()])
}

/// The chain head after a frame whose header's object hash is
/// `header_hash`.
#[must_use]
pub fn chain_next(previous: &Hash512, header_hash: &Hash512) -> Hash512 {
    labelled(CHAIN_LABEL, &[previous.as_bytes(), header_hash.as_bytes()])
}

/// The leaf of one chunk: `chunk` (at most 4,096 bytes) zero-extended to
/// 4,096 bytes. A longer `chunk` is cut at 4,096 bytes.
#[must_use]
pub fn chunk_leaf(chunk: &[u8]) -> Hash512 {
    let used = chunk.get(..CHUNK_LEN).unwrap_or(chunk);
    let zeros = [0u8; CHUNK_LEN];
    let fill = zeros
        .get(..CHUNK_LEN.saturating_sub(used.len()))
        .unwrap_or(&[]);
    labelled(CHUNK_LABEL, &[used, fill])
}

/// The leaf of an all-zero chunk.
#[must_use]
pub fn zero_leaf() -> Hash512 {
    chunk_leaf(&[])
}

fn node(left: &Hash512, right: &Hash512) -> Hash512 {
    labelled(NODE_LABEL, &[left.as_bytes(), right.as_bytes()])
}

/// The roots of all-zero subtrees: `ZERO[0]` the zero leaf, `ZERO[k]` the
/// node over two `ZERO[k − 1]`.
fn zero_subtrees() -> [Hash512; TREE_DEPTH + 1] {
    let leaf = zero_leaf();
    let mut out = [leaf; TREE_DEPTH + 1];
    let mut previous = leaf;
    for slot in out.iter_mut().skip(1) {
        previous = node(&previous, &previous);
        *slot = previous;
    }
    out
}

/// The payload root of a frame whose first chunks have the leaves
/// `data_leaves` and whose other chunks are zero, or `None` if there are
/// more than 256 leaves.
///
/// The data leaves are folded left to right with one pending left subtree
/// per level (a binary counter); the zero chunks after them are not hashed
/// one by one: the frontier is closed with the all-zero subtree of each
/// level, so a frame with `d` data chunks costs about `d + 17` hashes.
#[must_use]
pub fn payload_root<I: IntoIterator<Item = Hash512>>(data_leaves: I) -> Option<Hash512> {
    let zero = zero_subtrees();
    let mut pending: [Option<Hash512>; TREE_DEPTH] = [None; TREE_DEPTH];
    let mut leaves = data_leaves.into_iter();
    while let Some(leaf) = leaves.next() {
        let mut carry = Some(leaf);
        for slot in &mut pending {
            let Some(right) = carry else {
                break;
            };
            if let Some(left) = slot.take() {
                carry = Some(node(&left, &right));
            } else {
                *slot = Some(right);
                carry = None;
            }
        }
        // Only the 256th leaf carries past the eighth level: the root, and
        // no leaf may follow it.
        if let Some(root) = carry {
            return leaves.next().is_none().then_some(root);
        }
    }
    // Close the frontier: at each level, a pending left subtree takes the
    // part built so far (or zeros) as its right sibling; a part built so
    // far with no pending left subtree takes zeros as its right sibling.
    let mut built: Option<Hash512> = None;
    for (slot, z) in pending.iter().zip(zero.iter()) {
        built = match (slot, built) {
            (Some(left), b) => Some(node(left, &b.unwrap_or(*z))),
            (None, Some(b)) => Some(node(&b, z)),
            (None, None) => None,
        };
    }
    Some(built.unwrap_or(zero[TREE_DEPTH]))
}

/// The payload root of `payload` (at most 1,048,576 bytes; zero-extended),
/// computed from its bytes. A longer `payload` is cut.
#[must_use]
pub fn payload_root_of(payload: &[u8]) -> Hash512 {
    let leaves = payload
        .chunks(CHUNK_LEN)
        .take(PAYLOAD_CHUNKS)
        .map(chunk_leaf);
    payload_root(leaves).unwrap_or(Hash512::ZERO)
}

/// The hash of a capture file.
#[must_use]
pub fn capture_hash(file: &[u8]) -> Hash512 {
    labelled(CAPTURE_LABEL, &[file])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn reference_root(leaves: &[Hash512]) -> Hash512 {
        let mut level: std::vec::Vec<Hash512> = leaves.to_vec();
        while level.len() > 1 {
            level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        }
        level[0]
    }

    #[test]
    fn the_root_is_the_perfect_tree_over_256_leaves() {
        let zero = zero_leaf();
        let all_zero = [zero; PAYLOAD_CHUNKS];
        assert_eq!(payload_root([]), Some(reference_root(&all_zero)));
        let mut leaves = [zero; PAYLOAD_CHUNKS];
        leaves[0] = chunk_leaf(b"one");
        leaves[1] = chunk_leaf(b"two");
        assert_eq!(
            payload_root([leaves[0], leaves[1]]),
            Some(reference_root(&leaves))
        );
        let full: std::vec::Vec<Hash512> = (0..PAYLOAD_CHUNKS)
            .map(|i| chunk_leaf(&i.to_be_bytes()))
            .collect();
        assert_eq!(
            payload_root(full.iter().copied()),
            Some(reference_root(&full))
        );
        let mut over = full.clone();
        over.push(zero);
        assert_eq!(payload_root(over), None);
        // Every frontier: the data leaves then zeros.
        for d in [1usize, 3, 5, 64, 100, 129, 255] {
            let mut leaves = [zero; PAYLOAD_CHUNKS];
            leaves[..d].copy_from_slice(&full[..d]);
            assert_eq!(
                payload_root(full[..d].iter().copied()),
                Some(reference_root(&leaves)),
                "{d}"
            );
        }
    }

    #[test]
    fn a_payload_root_counts_every_byte_and_the_fill() {
        let mut payload = std::vec![0u8; 1_048_425];
        payload[..5].copy_from_slice(b"hello");
        let root = payload_root_of(&payload);
        assert_eq!(root, payload_root([chunk_leaf(b"hello")]).unwrap());
        assert_eq!(payload_root_of(b"hello"), root);
        payload[1_048_424] = 1;
        assert_ne!(payload_root_of(&payload), root);
        assert_eq!(chunk_leaf(&[0u8; 4096]), zero_leaf());
        assert_eq!(chunk_leaf(&[0u8; 5000]), zero_leaf());
    }

    fn unhex(s: &str) -> Hash512 {
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        Hash512(out)
    }

    /// Answers computed with Python's `hashlib.sha3_512` over the labelled
    /// inputs, independently of this crate.
    #[test]
    fn known_answers_from_an_independent_sha3() {
        let link = link_id(&[7; 32]);
        assert_eq!(
            link,
            unhex(
                "07ae4f64248fd0d79bc59e74b0322565d5740aaf080e57ac36ac22436b8a67dad187a8ad9386a6edfae0c6f20781fcb0df75d5423a857ee8ecbd9d185cea5d1b"
            )
        );
        let h0 = chain_start(&link);
        assert_eq!(
            h0,
            unhex(
                "252f5282f42f30514a87fa3af792aed83e923312902e2655a62ea46bd7c9d5cb375e6b339e62f1a216bec5c2d01304e7ed91c659aac99928e338886a41348173"
            )
        );
        assert_eq!(
            chain_next(&h0, &Hash512([1; 64])),
            unhex(
                "f99466e8118d38497466554bfb470652efffe25acb6f56c652760eb93e1c57853233bc56f6e466e7031ed286cd5a905855675d251b724247e1737e54e3a37aad"
            )
        );
        assert_eq!(
            zero_leaf(),
            unhex(
                "d5cfe59623f682b692a678ee2a5f243521fe330ac3a329b6b9ede60eadaa478702203d5acb7aee03075e8aae8f531477badbbdba9e43ec4cdaf2194d12017e94"
            )
        );
        assert_eq!(
            chunk_leaf(b"hello"),
            unhex(
                "a78c126545f70873ad81a9f49f302aa5f21df6f61c5699c9abe4ae63f4ec56970483b38fe47db2f41bde2aa43ecd3cc687403b1cfd60d0a4f8169ca2c7ed6563"
            )
        );
        assert_eq!(
            payload_root([]),
            Some(unhex(
                "a8dbf2f3da7e0460d8c20a3cedc5ab825e79f67eefb9fd098d95f1f831714de102f2edf8468552b4148630b0506bf0e4bbeceba6679092cfd5c012f75173885b"
            ))
        );
        assert_eq!(
            payload_root_of(b"hello"),
            unhex(
                "6729aa74bc0e791a057ea2d8f4535805ccf06d3eef7b18549eefc64dfed5a6513497cac158e4e2da4adb71f6f7c5b874979d954770f3685e245ebadb8e91d2dd"
            )
        );
        assert_eq!(
            capture_hash(b"capture file"),
            unhex(
                "89478283a860e617b09fb2324b5940b8ab0f2f0b71cd8b19666981bf5d1700d69f71f76ac545af91ce5994f774f446214a3055d4d563d804a6c9a0680f33c768"
            )
        );
    }

    #[test]
    fn labels_separate_the_hashes() {
        let key = [7u8; 32];
        let link = link_id(&key);
        assert_ne!(link, labelled(CHAIN_LABEL, &[&key]));
        let h0 = chain_start(&link);
        assert_ne!(h0, link);
        let h1 = chain_next(&h0, &Hash512([1; 64]));
        assert_ne!(h1, chain_next(&h1, &Hash512([1; 64])));
        assert_ne!(capture_hash(b"x"), labelled(LINK_LABEL, &[b"x"]));
    }
}
