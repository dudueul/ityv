//! Known-answer vectors: `vectors/ledger.txt` was produced independently
//! with Python `hashlib.sha3_512` and the RFC 9162 definitions; this file
//! checks the crate against it and keeps a regression file
//! (`vectors/regression.txt`) for the crate's own encodings.
// Integration-test crate: outside the TCB (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use common::{
    ELECTION, body_object, body_parts, encode_to_vec, frame_chain, hex, leaf_input, leaves,
    load_vectors, unhex_hash, unhex_hashes,
};
use ityv_encoding::{Hash512, Writer};
use ityv_ledger::{
    Accumulator, ChainState, ConsistencyProof, EMPTY_ROOT, InclusionProof, WitnessMemory,
    consistency_proof, inclusion_proof, leaf_hash, node_hash, root_of_leaves, sorted_set_root,
    verify_consistency, verify_inclusion, write_record,
};
use std::collections::BTreeMap;
use std::string::{String, ToString};

#[test]
fn independent_hash_vectors() {
    let v = load_vectors("ledger.txt");
    assert_eq!(EMPTY_ROOT, unhex_hash(&v["empty_root"]));
    assert_eq!(leaf_hash(&leaf_input(0)), unhex_hash(&v["leaf_hash_L0"]));
    assert_eq!(leaf_hash(&leaf_input(1)), unhex_hash(&v["leaf_hash_L1"]));
    assert_eq!(
        node_hash(&leaf_hash(&leaf_input(0)), &leaf_hash(&leaf_input(1))),
        unhex_hash(&v["node_hash_L0_L1"])
    );
}

#[test]
fn independent_roots() {
    let v = load_vectors("ledger.txt");
    for n in 0..=8usize {
        let expected = unhex_hash(&v[&std::format!("root_n{n}")]);
        let ls = leaves(n);
        let by_fn = root_of_leaves(&ls.as_slice(), n as u64).unwrap();
        assert_eq!(by_fn, expected, "root_of_leaves n={n}");
        let mut acc = Accumulator::empty();
        for l in &ls {
            acc.push(l).unwrap();
        }
        assert_eq!(acc.root(), expected, "accumulator n={n}");
        assert_eq!(acc.size(), n as u64);
    }
}

#[test]
fn independent_inclusion_paths() {
    let v = load_vectors("ledger.txt");
    for (m, n) in [(0u64, 1u64), (2, 5), (4, 5), (6, 7), (3, 8)] {
        let key = std::format!("inclusion_path_m{m}_n{n}");
        let expected = unhex_hashes(&v[&key]);
        let ls = leaves(n as usize);
        let proof = inclusion_proof(&ls.as_slice(), n, m).unwrap();
        assert_eq!(proof.hashes(), expected.as_slice(), "{key}");
        let root = unhex_hash(&v[&std::format!("root_n{n}")]);
        let leaf = leaf_input(m as u8);
        let ok = verify_inclusion(&root, n, m, &leaf, &proof).unwrap();
        assert_eq!(ok.get().index(), m);
    }
}

#[test]
fn independent_consistency_paths() {
    let v = load_vectors("ledger.txt");
    for (a, b) in [(1u64, 2u64), (2, 5), (3, 7), (4, 8), (5, 8), (7, 8)] {
        let key = std::format!("consistency_path_old{a}_new{b}");
        let expected = unhex_hashes(&v[&key]);
        let ls = leaves(b as usize);
        let proof = consistency_proof(&ls.as_slice(), a, b).unwrap();
        assert_eq!(proof.hashes(), expected.as_slice(), "{key}");
        let old_root = unhex_hash(&v[&std::format!("root_n{a}")]);
        let new_root = unhex_hash(&v[&std::format!("root_n{b}")]);
        let ok = verify_consistency(a, &old_root, b, &new_root, &proof).unwrap();
        assert_eq!(ok.get().new_size(), b);
    }
}

#[test]
fn independent_sorted_set_root() {
    let v = load_vectors("ledger.txt");
    let set = [leaf_input(1), leaf_input(2), leaf_input(3)];
    assert_eq!(
        sorted_set_root(&set).unwrap(),
        unhex_hash(&v["sorted_set_root_L1_L2_L3"])
    );
}

const REGRESSION_HEADER: &str = "\
# ityv-ledger regression vectors: produced by this implementation's own
# encoders from fixed inputs. Not independent. Regenerate with
# ITYV_UPDATE_VECTORS=1 and say so in the commit message.
# Format: name = lowercase hex
";

fn regression() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let ls = leaves(5);
    let mut acc = Accumulator::empty();
    for l in &ls {
        acc.push(l).unwrap();
    }
    out.insert("accumulator_n5".to_string(), hex(&encode_to_vec(&acc)));
    let incl = inclusion_proof(&ls.as_slice(), 5, 2).unwrap();
    out.insert(
        "inclusion_proof_m2_n5".to_string(),
        hex(&encode_to_vec(&incl)),
    );
    let cons = consistency_proof(&ls.as_slice(), 2, 5).unwrap();
    out.insert(
        "consistency_proof_old2_new5".to_string(),
        hex(&encode_to_vec(&cons)),
    );
    out.insert(
        "consistency_proof_empty".to_string(),
        hex(&encode_to_vec(&ConsistencyProof::EMPTY)),
    );
    let chain = frame_chain(3);
    let mut state = ChainState::empty();
    let mut stream = std::vec![0u8; 3 * 300];
    let mut w = Writer::new(&mut stream);
    for f in &chain {
        state.append(f).unwrap();
        write_record(&mut w, f).unwrap();
    }
    let used = w.finish();
    stream.truncate(used);
    out.insert("frame_stream_3".to_string(), hex(&stream));
    out.insert("chain_state_3".to_string(), hex(&encode_to_vec(&state)));
    let body = body_parts(
        1,
        3,
        state.accumulator().root(),
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        Hash512([7; 64]),
        10,
    );
    let body_bytes = body_object(&body);
    out.insert("checkpoint_body_seq1".to_string(), hex(&body_bytes));
    let (token, memory) = WitnessMemory::fresh().may_sign(
        &body_bytes,
        &ConsistencyProof::EMPTY,
        &[],
        &[],
        &Hash512([7; 64]),
    );
    let token = token.unwrap();
    assert_eq!(token.get().body_bytes(), body_bytes.as_slice());
    let mut persisted = [0u8; 16 + 208];
    let used = memory.to_object(&mut persisted).unwrap();
    out.insert(
        "witness_memory_object_after_seq1".to_string(),
        hex(&persisted[..used]),
    );
    let mut fresh = [0u8; 16 + 208];
    let used = WitnessMemory::fresh().to_object(&mut fresh).unwrap();
    out.insert(
        "witness_memory_object_fresh".to_string(),
        hex(&fresh[..used]),
    );
    out.insert("election_id_bytes".to_string(), hex(ELECTION));
    let _ = InclusionProof::from_hashes(&[]).unwrap();
    out
}

fn render(map: &BTreeMap<String, String>) -> String {
    let mut text = String::from(REGRESSION_HEADER);
    for (name, value) in map {
        text.push_str(name);
        text.push_str(" = ");
        text.push_str(value);
        text.push('\n');
    }
    text
}

#[test]
fn regression_vectors_match() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/regression.txt");
    let computed = regression();
    if std::env::var_os("ITYV_UPDATE_VECTORS").is_some() {
        std::fs::write(&path, render(&computed)).unwrap();
    }
    let stored = load_vectors("regression.txt");
    for (name, value) in &computed {
        assert_eq!(
            stored.get(name),
            Some(value),
            "vector {name} differs; if the change is intended, regenerate with ITYV_UPDATE_VECTORS=1"
        );
    }
    assert_eq!(stored.len(), computed.len(), "stale or missing vectors");
}
