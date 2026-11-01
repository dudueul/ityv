//! Cryptographic wrapper for ityv (ADR-0015).
//!
//! Every other ityv crate reaches cryptography only through this crate. It
//! exposes typed, misuse-resistant operations and hides the algorithm
//! libraries behind the `backend` module:
//!
//! | module | contents | specification |
//! |---|---|---|
//! | [`hash`] | domain-separated SHA3-512, signing digest, Fiat-Shamir | ENCODING.md §4 |
//! | [`sig`] | hybrid ML-DSA-87 + Ed25519, record Ed25519, archive SLH-DSA | PROTOCOL.md §3.1, §7.2.1 |
//! | [`kem`] | ML-KEM-1024 + X25519 with `ChaCha20-Poly1305` | PROTOCOL.md §9.6 |
//! | [`mod@commit`] | generalized Pedersen commitments, digit packing | PROTOCOL.md §7.4 |
//! | [`orproof`] | 1-of-(m+2) OR proof of representation | PROTOCOL.md §7.5 |
//! | [`shares`] | chamber access structure, linear secret sharing | PROTOCOL.md §9.2 |
//! | [`otmac`], [`pad`] | Poly1305 one-time MAC, one-time pad XOR | PROTOCOL.md §9.3, §9.4 |
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]`, no heap allocation, no `unsafe`, no panics (workspace
//!   lint set; Kani harnesses under `cfg(kani)` for the pure arithmetic).
//! * Every verification returns a [`Verified`] token that only this crate
//!   can create and that borrows every verified input (key, purpose, object
//!   and signature; statement and proof; commitments and opening; the
//!   authenticated message; the decrypted plaintext). There is no `bool` to
//!   ignore and no token without its subject.
//! * Every secret key type is zeroized on drop and prints nothing. KEM keys
//!   are split into a [`SealKey`] and an [`OpenKey`] that are consumed by
//!   their one operation.
//! * Randomness comes only from a caller-supplied `rand_core::CryptoRng`;
//!   the crate never opens an operating-system random source.
//! * Fixed capacities: 64 options, 8 chunks, 6 chambers, 8 members per
//!   chamber. Nothing is sized by input.
//!
//! What this crate does **not** prove or provide:
//!
//! * Constant-time execution and side-channel resistance rest on the
//!   algorithm libraries' own claims; this crate adds only constant-time
//!   comparisons of its own.
//! * No key custody: seeds are returned to the caller for storage in a
//!   custody device (HSM). Zeroization covers this crate's own copies.
//! * The backends are not formally verified yet (ADR-0015 open item); the
//!   trait boundary in `backend` is where verified implementations go. The
//!   Ristretto255 group has no trait yet (its verified path is a build
//!   configuration of `curve25519-dalek`).
//! * Soundness of the OR proof and binding of the commitments are
//!   computational (discrete logarithm on Ristretto255) and hold only while
//!   that assumption holds; hiding is unconditional.
//! * The Σ-protocol and the group arithmetic are at verification level V1
//!   (property tests, mutation testing, known-answer vectors); V3 is
//!   scheduled with the backend replacement (ROADMAP M1).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod backend;
pub mod commit;
pub mod error;
pub mod hash;
pub mod kem;
pub mod orproof;
pub mod otmac;
pub mod pad;
pub mod scalar;
pub mod shares;
pub mod sig;
pub mod verified;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use commit::{
    AggregateOpening, Bases, CastId, ChunkIndex, Commitment, DIGIT_BITS, DIGITS_PER_CHUNK,
    MAX_CHUNKS, MAX_OPTIONS, OpenedCommitments, Opening, OptionCount, OptionIndex, commit,
    decode_digits, packed_exponent, packed_value, sum_commitments, verify_aggregate,
    verify_opening,
};
pub use error::Error;
pub use hash::{Hasher as Sha3Hasher, Purpose, fiat_shamir_challenge, object_hash, signing_digest};
pub use kem::{
    AeadTag, HybridCiphertext, HybridKemPublicKey, HybridKemSecretKey, OpenKey, SealKey,
    decapsulate, encapsulate, open, seal,
};
pub use orproof::{
    FS_LABEL_OR_REP_V1, PROOF_SYSTEM_OR_REP_V1, Proof, ProvenStatement, Statement, prove,
    prove_into, verify,
};
pub use otmac::{
    OneTimeKey, Tag as OneTimeTag, tag as one_time_tag, verify_tag as verify_one_time_tag,
};
pub use pad::xor_in_place;
pub use scalar::Scalar;
pub use shares::{
    AccessStructure, CHAMBER_COUNT, Chamber, MAX_MEMBERS, MemberId, MemberShares, Share, Threshold,
    is_qualified, reconstruct, split,
};
pub use sig::{
    ArchiveSignature, ArchiveSigned, ArchiveSigningKey, ArchiveVerifyingKey, HybridSignature,
    HybridSigned, HybridSigningKey, HybridVerifyingKey, PURPOSE_CAST_RECORD, PURPOSE_CHECKPOINT,
    PURPOSE_CHECKPOINT_ARCHIVE, PURPOSE_MODULE_RECORD, RecordPurpose, RecordSignature,
    RecordSigned, RecordSigningKey, RecordVerifyingKey, sign_archive, sign_hybrid, sign_record,
    verify_archive, verify_hybrid, verify_record,
};
pub use verified::Verified;
