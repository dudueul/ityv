//! Shared fixtures: a leaked `'static` election configuration, a
//! deterministic mock chamber module and a mock journal.
// Integration-test helper module: outside the TCB. Fixtures express "this
// must hold" with unwrap/expect/panic/indexing, compute offsets with plain
// arithmetic and casts, leak a configuration to obtain `'static` borrows,
// and not every test binary uses every helper; the mock module's
// misbehaviour switches are independent booleans; so these lints are relaxed
// for this file only (CONSTITUTION.md §1.1).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]

use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use ityv_crypto::{
    AccessStructure, Chamber, HybridKemSecretKey, HybridSignature, HybridSigningKey,
    HybridVerifyingKey, OneTimeKey, OptionCount, Purpose, RecordPurpose, RecordSignature,
    RecordSigningKey, RecordVerifyingKey, Scalar, Sha3Hasher, Threshold, one_time_tag, sign_hybrid,
    sign_record,
};
use ityv_cunit::ballot::{
    Ballot, BallotWork, BuildBuffers, Built, SCRATCH_SLOT_LEN, member_share_len, scratch_len,
};
use ityv_cunit::boxstate::{OpenBox, Signer};
use ityv_cunit::config::{
    BallotStyle, ConfigParts, ElectionConfig, ModuleConfig, Profile, TrusteeConfig,
};
use ityv_cunit::link::{
    Interpretation, ModuleIssue, ModuleIssueParts, SCHEMA_INTERPRETATION, SCHEMA_MODULE_ISSUE,
    SCHEMA_VISIT_END, VisitEnd,
};
use ityv_cunit::port::{
    JournalError, JournalItem, JournalSink, JournalSource, ModuleAttestation, ModulePort,
    PortError, Sealed, Staged, StagingPort, module_may_sign_batch, module_may_sign_record,
};
use ityv_cunit::rules::{PAD_MAC_KEY_OFFSET, PAD_PLAINTEXT_OFFSET, PAD_TAG_KEY_OFFSET};
use ityv_cunit::visit::{Decision, VisitWork};
use ityv_cunit::{Bound, Choice};
use ityv_encoding::{
    AttestationChallenge, Decode, Encode, Ident, ModuleStatementMessage, Reader, Writer,
};
use ityv_encoding::{
    BallotStyleId, BatchAttestBody, BoxId, ElectionId, Hash512, ModuleId, SCHEMA_BATCH_ATTEST_BODY,
    SCHEMA_VERSION_1, Scalar32, StationId, TimeBucket, Token192, TrusteeId, decode_object,
    encode_object,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(crate) fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// The ballot style with four options (`m = 2`, one chunk).
pub(crate) const STYLE_SMALL: &[u8] = b"P-4";
/// The ballot style with twelve options (two chunks).
pub(crate) const STYLE_WIDE: &[u8] = b"L-12";

/// One configured module and its spec for the mock.
#[derive(Clone, Copy)]
pub(crate) struct ModuleSpec {
    pub(crate) id: &'static [u8],
    pub(crate) chamber: Chamber,
    pub(crate) neutral: bool,
}

/// The default module set for two parties: own modules for P1, P2 and J;
/// neutral modules for A and C; none for N (KEM transport). Ascending by
/// identifier.
pub(crate) const MODULES: [ModuleSpec; 5] = [
    ModuleSpec {
        id: b"mod-a",
        chamber: Chamber::A,
        neutral: true,
    },
    ModuleSpec {
        id: b"mod-c",
        chamber: Chamber::C,
        neutral: true,
    },
    ModuleSpec {
        id: b"mod-j",
        chamber: Chamber::J,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p1",
        chamber: Chamber::P1,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p2",
        chamber: Chamber::P2,
        neutral: false,
    },
];

/// The largest module set: four parties with own modules, own modules for
/// J, A and C (seven modules, ADR-0019 §7). Ascending by identifier.
pub(crate) const MODULES_FOUR_PARTIES: [ModuleSpec; 7] = [
    ModuleSpec {
        id: b"mod-a",
        chamber: Chamber::A,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-c",
        chamber: Chamber::C,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-j",
        chamber: Chamber::J,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p1",
        chamber: Chamber::P1,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p2",
        chamber: Chamber::P2,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p3",
        chamber: Chamber::P3,
        neutral: false,
    },
    ModuleSpec {
        id: b"mod-p4",
        chamber: Chamber::P4,
        neutral: false,
    },
];

pub(crate) const fn chamber_letter(chamber: Chamber) -> u8 {
    match chamber {
        Chamber::P1 => b'1',
        Chamber::P2 => b'2',
        Chamber::P3 => b'3',
        Chamber::P4 => b'4',
        Chamber::J => b'j',
        Chamber::A => b'a',
        Chamber::C => b'c',
        Chamber::N => b'n',
    }
}

/// A trustee and its secret key.
pub(crate) struct TrusteeSecret {
    pub(crate) id: &'static [u8],
    pub(crate) chamber: Chamber,
    pub(crate) member_index: u8,
    pub(crate) pad_id: u32,
    pub(crate) kem: HybridKemSecretKey,
}

/// Everything a test needs, with `'static` borrows.
pub(crate) struct World {
    pub(crate) config: &'static ElectionConfig<'static>,
    pub(crate) trustees: Vec<TrusteeSecret>,
    pub(crate) device_record: RecordSigningKey,
    pub(crate) device_hybrid: HybridSigningKey,
    pub(crate) modules: Vec<ModuleSpec>,
}

pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

pub(crate) fn leak_bytes(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// Builds a world with the default modules (two parties), two trustees per
/// chamber taking part (thresholds 2-of-2 for the party chambers, 1-of-2
/// elsewhere) and both styles.
pub(crate) fn world(profile: Profile, voter_code: bool) -> World {
    world_with(profile, voter_code, &MODULES)
}

/// `n` styles `S0000`, `S0001`, … (ascending), with option counts cycling
/// through 3..=64 so that every chunk count occurs.
pub(crate) fn styles(n: usize) -> &'static [BallotStyle<'static>] {
    let list: Vec<BallotStyle<'static>> = (0..n)
        .map(|i| {
            let id = leak_bytes(std::format!("S{i:04}").into_bytes());
            BallotStyle::new(
                BallotStyleId::new(id).unwrap(),
                OptionCount::new(3 + (i % 62) as u16).unwrap(),
            )
        })
        .collect();
    Box::leak(list.into_boxed_slice())
}

pub(crate) fn world_with(profile: Profile, voter_code: bool, modules: &[ModuleSpec]) -> World {
    // ascending by identifier bytes: "L-12" < "P-4"
    let styles: &'static [BallotStyle<'static>] = Box::leak(
        vec![
            BallotStyle::new(
                BallotStyleId::new(STYLE_WIDE).unwrap(),
                OptionCount::new(12).unwrap(),
            ),
            BallotStyle::new(
                BallotStyleId::new(STYLE_SMALL).unwrap(),
                OptionCount::new(4).unwrap(),
            ),
        ]
        .into_boxed_slice(),
    );
    world_full(profile, voter_code, modules, styles)
}

/// The access structure of a world with `parties` party chambers: 2-of-2
/// in every party chamber, 1-of-2 in J, A, C and N.
pub(crate) fn access(parties: u8) -> AccessStructure {
    let t22 = Threshold::new(2, 2).unwrap();
    let t12 = Threshold::new(1, 2).unwrap();
    AccessStructure::new(parties, [t22, t22, t22, t22, t12, t12, t12, t12]).unwrap()
}

/// The party count of a module set: its party modules, at least two.
pub(crate) fn parties_of(modules: &[ModuleSpec]) -> u8 {
    let n = modules.iter().filter(|m| m.chamber.is_party()).count();
    u8::try_from(n.max(2)).unwrap()
}

/// A world with the given modules and styles; the party count follows
/// from the modules ([`parties_of`]).
pub(crate) fn world_full(
    profile: Profile,
    voter_code: bool,
    modules: &[ModuleSpec],
    styles: &'static [BallotStyle<'static>],
) -> World {
    let mut r = rng(7);
    let access = access(parties_of(modules));
    let mut trustees = Vec::new();
    for chamber in Chamber::ALL.into_iter().filter(|&c| access.includes(c)) {
        for member_index in 0..2u8 {
            let id = leak_bytes(vec![
                b't',
                b'-',
                chamber_letter(chamber),
                b'-',
                b'0' + member_index,
            ]);
            trustees.push(TrusteeSecret {
                id,
                chamber,
                member_index,
                pad_id: 100 + u32::from(chamber_letter(chamber)) * 10 + u32::from(member_index),
                kem: HybridKemSecretKey::generate(&mut r),
            });
        }
    }
    trustees.sort_by(|a, b| a.id.cmp(b.id));
    let configs: Vec<TrusteeConfig<'static>> = trustees
        .iter()
        .map(|t| {
            TrusteeConfig::new(
                TrusteeId::new(t.id).unwrap(),
                t.chamber,
                t.member_index,
                t.pad_id,
                leak(t.kem.public_key()),
            )
        })
        .collect();
    let module_configs: Vec<ModuleConfig<'static>> = modules
        .iter()
        .map(|m| module_config(m.id, m.chamber, m.neutral))
        .collect();
    let parts = ConfigParts {
        election_id: ElectionId::new(b"E-2026").unwrap(),
        box_id: BoxId::new(b"BOX-1").unwrap(),
        station_id: StationId::new(b"ST-1").unwrap(),
        profile,
        styles,
        modules: Box::leak(module_configs.into_boxed_slice()),
        trustees: Box::leak(configs.into_boxed_slice()),
        access,
        voter_code_enabled: voter_code,
    };
    let config = leak(ElectionConfig::new(parts).unwrap());
    World {
        config,
        trustees,
        device_record: RecordSigningKey::from_seed([3; 32]),
        device_hybrid: HybridSigningKey::from_seeds([4; 32], [5; 32]),
        modules: modules.to_vec(),
    }
}

/// A module entry with the mock module's genesis keys.
pub(crate) fn module_config(
    id: &'static [u8],
    chamber: Chamber,
    neutral: bool,
) -> ModuleConfig<'static> {
    let (record, batch) = module_keys(id);
    ModuleConfig::new(
        ModuleId::new(id).unwrap(),
        chamber,
        neutral,
        record.verifying_key(),
        leak(batch.verifying_key()),
    )
}

/// The record and batch signing keys of the mock module `id`.
pub(crate) fn module_keys(id: &[u8]) -> (RecordSigningKey, HybridSigningKey) {
    let seed = token_from(b"seed", &[id]);
    let mut s32 = [0u8; 32];
    s32[..24].copy_from_slice(&seed);
    (
        RecordSigningKey::from_seed(s32),
        HybridSigningKey::from_seeds(s32, [9; 32]),
    )
}

/// The pad stream of member `member` of module `module` at `offset`.
pub(crate) fn pad_bytes(module: &[u8], member: u8, offset: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = offset / 64;
    let mut skip = (offset % 64) as usize;
    while out.len() < len {
        let mut h = Sha3Hasher::new();
        h.absorb(b"test-pad");
        h.absorb(module);
        h.absorb(&[member]);
        h.absorb(&block.to_be_bytes());
        let digest = h.finish();
        for &b in &digest[skip..] {
            if out.len() < len {
                out.push(b);
            }
        }
        skip = 0;
        block += 1;
    }
    out
}

fn scalar_from(label: &[u8], parts: &[&[u8]]) -> Scalar32 {
    let mut h = Sha3Hasher::new();
    h.absorb(label);
    for p in parts {
        h.absorb(p);
    }
    Scalar32(Scalar::from_bytes_mod_order_wide(&h.finish()).to_bytes())
}

fn token_from(label: &[u8], parts: &[&[u8]]) -> [u8; 24] {
    let mut h = Sha3Hasher::new();
    h.absorb(label);
    for p in parts {
        h.absorb(p);
    }
    let digest = h.finish();
    let mut out = [0u8; 24];
    out.copy_from_slice(&digest[..24]);
    out
}

/// What a mock module issued for one counter (kept to check challenges).
#[derive(Clone)]
pub(crate) struct IssueRecord {
    pub(crate) counter: u64,
    pub(crate) rand: Vec<Scalar32>,
    pub(crate) cid: [u8; 24],
    pub(crate) lab: Option<[u8; 24]>,
}

/// A deterministic chamber module.
pub(crate) struct MockModule {
    pub(crate) id: &'static [u8],
    pub(crate) chamber_code: u8,
    pub(crate) members: u8,
    pub(crate) counter: u64,
    pub(crate) label: bool,
    pub(crate) pad_b: u64,
    pub(crate) pad_ids: Vec<u32>,
    pub(crate) record_key: RecordSigningKey,
    pub(crate) batch_key: HybridSigningKey,
    pub(crate) pending: Vec<u64>,
    pub(crate) issued: Vec<IssueRecord>,
    /// The body hash signed for each counter (VC-068).
    pub(crate) signed: BTreeMap<u64, [u8; 64]>,
    /// Calls to `check_batch` and to `sign_batch`.
    pub(crate) checks: usize,
    pub(crate) signs: usize,
    /// Every `(member, offset, len)` pad range a seal consumed.
    pub(crate) pad_uses: Vec<(u8, u64, u64)>,
    // misbehaviour switches
    pub(crate) exhaust_member: Option<u8>,
    pub(crate) refuse_batches: bool,
    pub(crate) refuse_at_signing: bool,
    pub(crate) wrong_record_key: bool,
    pub(crate) wrong_batch_key: bool,
    pub(crate) force_counter: Option<u64>,
    pub(crate) wrong_pad_index: bool,
    pub(crate) wrong_pad_id: bool,
    pub(crate) skip_counter: bool,
    pub(crate) wrong_id: bool,
    pub(crate) wrong_chamber: bool,
    pub(crate) extra_tag: bool,
    pub(crate) flip_label: bool,
    pub(crate) extra_rand: bool,
    pub(crate) fail_issue: bool,
    /// Calls to `attest`, and its misbehaviour switches.
    pub(crate) attests: usize,
    pub(crate) wrong_attest_key: bool,
    pub(crate) refuse_attest: bool,
}

impl MockModule {
    pub(crate) fn new(world: &World, spec: &ModuleSpec) -> Self {
        let label = world.config.profile().has_label();
        // b is one per box: the longest member share over the box's styles
        // plus the two 32-byte keys (PROTOCOL.md §9.4.3).
        let longest = world
            .config
            .styles()
            .iter()
            .map(|s| {
                let secrets = world.modules.len() * usize::from(s.chunk_count()) + 1;
                member_share_len(secrets + usize::from(label), label)
            })
            .max()
            .unwrap();
        let pad_b = (longest + 64) as u64;
        let pad_ids = world
            .trustees
            .iter()
            .filter(|t| t.chamber == spec.chamber)
            .map(|t| (t.member_index, t.pad_id))
            .fold(vec![0u32; 2], |mut acc, (i, id)| {
                acc[usize::from(i)] = id;
                acc
            });
        let (record_key, batch_key) = module_keys(spec.id);
        Self {
            id: spec.id,
            chamber_code: ityv_cunit::config::chamber_code(spec.chamber).code(),
            members: 2,
            counter: 0,
            label,
            pad_b,
            pad_ids,
            record_key,
            batch_key,
            pending: Vec::new(),
            issued: Vec::new(),
            signed: BTreeMap::new(),
            checks: 0,
            signs: 0,
            pad_uses: Vec::new(),
            exhaust_member: None,
            refuse_batches: false,
            refuse_at_signing: false,
            wrong_record_key: false,
            wrong_batch_key: false,
            force_counter: None,
            wrong_pad_index: false,
            wrong_pad_id: false,
            skip_counter: false,
            wrong_id: false,
            wrong_chamber: false,
            extra_tag: false,
            flip_label: false,
            extra_rand: false,
            attests: 0,
            wrong_attest_key: false,
            refuse_attest: false,
            fail_issue: false,
        }
    }

    pub(crate) fn record_verifying_key(&self) -> RecordVerifyingKey {
        self.record_key.verifying_key()
    }

    pub(crate) fn batch_verifying_key(&self) -> HybridVerifyingKey {
        self.batch_key.verifying_key()
    }

    pub(crate) fn last_issue(&self) -> &IssueRecord {
        self.issued.last().unwrap()
    }
}

impl ModulePort for MockModule {
    fn issue(&mut self, chunk_count: u8, out: &mut [u8]) -> Result<usize, PortError> {
        if self.fail_issue {
            return Err(PortError::Transport);
        }
        let n = if let Some(forced) = self.force_counter.take() {
            forced
        } else {
            self.counter += if self.skip_counter { 2 } else { 1 };
            self.counter
        };
        let rand_count = usize::from(chunk_count) + usize::from(self.extra_rand);
        let rand: Vec<Scalar32> = (0..rand_count)
            .map(|j| scalar_from(b"rand", &[self.id, &n.to_be_bytes(), &[j as u8]]))
            .collect();
        let cid = token_from(b"cid", &[self.id, &n.to_be_bytes()]);
        let lab = (self.label != self.flip_label)
            .then(|| token_from(b"lab", &[self.id, &n.to_be_bytes()]));
        let mut message = Vec::new();
        for r in &rand {
            message.extend_from_slice(&r.0);
        }
        message.extend_from_slice(&cid);
        if let Some(l) = &lab {
            message.extend_from_slice(l);
        }
        let tag_count = usize::from(self.members) + usize::from(self.extra_tag);
        let tags: Vec<[u8; 16]> = (0..tag_count)
            .map(|i| {
                let key = pad_bytes(self.id, i as u8, n * self.pad_b + PAD_TAG_KEY_OFFSET, 32);
                *one_time_tag(OneTimeKey::from_bytes(key.try_into().unwrap()), &message).as_bytes()
            })
            .collect();
        let id = if self.wrong_id {
            b"mod-zz".as_slice()
        } else {
            self.id
        };
        let chamber = match (self.wrong_chamber, self.chamber_code) {
            (false, code) => code,
            (true, 1) => 2,
            (true, _) => 1,
        };
        let issue = ModuleIssue::new(&ModuleIssueParts {
            module_id: ModuleId::new(id).unwrap(),
            chamber,
            counter: n,
            rand: &rand,
            cid: Token192(cid),
            lab: lab.map(Token192),
            tags: &tags,
        })
        .unwrap();
        self.pending.push(n);
        self.issued.push(IssueRecord {
            counter: n,
            rand: rand.clone(),
            cid,
            lab,
        });
        encode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &issue, out)
            .map_err(|_| PortError::BufferTooSmall)
    }

    fn seal_member(&mut self, member_index: u8, buffer: &mut [u8]) -> Result<Sealed, PortError> {
        if self.exhaust_member == Some(member_index) {
            return Err(PortError::Exhausted);
        }
        let offset = self.counter * self.pad_b;
        let len = buffer.len();
        assert!(
            PAD_PLAINTEXT_OFFSET + len as u64 <= self.pad_b,
            "share fits the region"
        );
        self.pad_uses.push((member_index, offset, self.pad_b));
        let key = pad_bytes(self.id, member_index, offset + PAD_MAC_KEY_OFFSET, 32);
        let tag = *one_time_tag(OneTimeKey::from_bytes(key.try_into().unwrap()), buffer).as_bytes();
        let pad = pad_bytes(self.id, member_index, offset + PAD_PLAINTEXT_OFFSET, len);
        for (b, p) in buffer.iter_mut().zip(pad) {
            *b ^= p;
        }
        let pad_id = self.pad_ids[usize::from(member_index)] + u32::from(self.wrong_pad_id);
        let pad_index = offset + u64::from(self.wrong_pad_index);
        Ok(Sealed {
            pad_id,
            pad_index,
            tag,
        })
    }

    fn sign_record(&mut self, message: &[u8]) -> Result<RecordSignature, PortError> {
        // message = body_hash (64) ‖ module_id (u32 length ‖ bytes) ‖ counter (u64)
        let body_hash: [u8; 64] = message[..64].try_into().unwrap();
        let counter = u64::from_be_bytes(message[message.len() - 8..].try_into().unwrap());
        if !module_may_sign_record(self.signed.get(&counter), &body_hash) {
            return Err(PortError::Refused);
        }
        self.signed.insert(counter, body_hash);
        let key = if self.wrong_record_key {
            module_keys(b"someone-else").0
        } else {
            module_keys(self.id).0
        };
        sign_record(&key, RecordPurpose::ModuleRecord, message).map_err(|_| PortError::Transport)
    }

    fn check_batch(&mut self, counter_first: u64, counter_last: u64) -> Result<bool, PortError> {
        self.checks += 1;
        Ok(!self.refuse_batches
            && module_may_sign_batch(&self.pending, counter_first, counter_last))
    }

    fn sign_batch(&mut self, body: &[u8]) -> Result<HybridSignature, PortError> {
        self.signs += 1;
        let parsed: BatchAttestBody<'_> =
            decode_object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, body)
                .map_err(|_| PortError::Transport)?;
        let range = parsed
            .module_ranges()
            .find(|r| r.module_id.as_bytes() == self.id)
            .ok_or(PortError::Transport)?;
        if self.refuse_at_signing
            || self.refuse_batches
            || !module_may_sign_batch(&self.pending, range.counter_first, range.counter_last)
        {
            return Err(PortError::Refused);
        }
        let purpose = Purpose::new(b"batch-attest").unwrap();
        let key = if self.wrong_batch_key {
            module_keys(b"someone-else").1
        } else {
            module_keys(self.id).1
        };
        let sig = sign_hybrid(&key, &purpose, body, &mut rng(self.counter))
            .map_err(|_| PortError::Transport)?;
        // Real firmware marks the range attested as it signs.
        self.pending.retain(|&c| c > range.counter_last);
        Ok(sig)
    }

    fn attest(
        &mut self,
        device_id: &[u8],
        challenge: &[u8],
    ) -> Result<ModuleAttestation, PortError> {
        self.attests += 1;
        if self.refuse_attest {
            return Err(PortError::Refused);
        }
        let mut r = Reader::new(challenge);
        let challenge = AttestationChallenge::decode(&mut r).map_err(|_| PortError::Transport)?;
        let (build, image_hash, boot_count) = module_boot(self.chamber_code);
        let message = ModuleStatementMessage {
            device_id: Ident::new(device_id, 64).ok_or(PortError::Transport)?,
            challenge,
            module_id: ModuleId::new(self.id).unwrap(),
            build,
            image_hash,
            boot_count,
        };
        let mut bytes = vec![0u8; message.encoded_len()];
        let mut w = Writer::new(&mut bytes);
        message.encode(&mut w).map_err(|_| PortError::Transport)?;
        let key = module_attestation_key(if self.wrong_attest_key {
            b"someone-else"
        } else {
            self.id
        });
        let purpose = Purpose::new(b"module-attestation").unwrap();
        let sig =
            sign_hybrid(&key, &purpose, &bytes, &mut rng(7)).map_err(|_| PortError::Transport)?;
        Ok(ModuleAttestation {
            build,
            image_hash,
            boot_count,
            sig,
        })
    }
}

/// A mock module's boot measurements: build, image hash, boot count.
pub(crate) fn module_boot(chamber_code: u8) -> (u64, Hash512, u32) {
    (
        100 + u64::from(chamber_code),
        Hash512([chamber_code; 64]),
        3,
    )
}

/// A module's attestation key (image-bound in real hardware).
pub(crate) fn module_attestation_key(id: &[u8]) -> HybridSigningKey {
    let seed = token_from(b"attest", &[id]);
    let mut s32 = [0u8; 32];
    s32[..24].copy_from_slice(&seed);
    HybridSigningKey::from_seeds(s32, [11; 32])
}

/// Mock modules for every configured module.
pub(crate) fn mocks(world: &World) -> Vec<MockModule> {
    world
        .modules
        .iter()
        .map(|m| MockModule::new(world, m))
        .collect()
}

/// The ports slice the unit takes.
pub(crate) fn ports(mocks: &mut [MockModule]) -> Vec<&mut dyn ModulePort> {
    mocks
        .iter_mut()
        .map(|m| -> &mut dyn ModulePort { m })
        .collect()
}

/// A journal kept in memory.
#[derive(Default)]
pub(crate) struct MemJournal {
    pub(crate) entries: Vec<Vec<u8>>,
    pub(crate) packages: Vec<Option<Vec<u8>>>,
    pub(crate) fail: bool,
    /// Fails the append after this many more successful ones.
    pub(crate) fail_after: Option<usize>,
    /// Durable appends (each an fsync) and deferred ones.
    pub(crate) syncs: usize,
    pub(crate) deferred: usize,
    /// Entries not yet durable (deferred and not followed by a durable
    /// append): what a power loss would drop.
    pub(crate) unsynced: usize,
}

impl MemJournal {
    fn push(&mut self, entry: &[u8], share_package: Option<&[u8]>) -> Result<(), JournalError> {
        if self.fail {
            return Err(JournalError::NotDurable);
        }
        if let Some(n) = self.fail_after.as_mut() {
            if *n == 0 {
                return Err(JournalError::NotDurable);
            }
            *n -= 1;
        }
        self.entries.push(entry.to_vec());
        self.packages.push(share_package.map(<[u8]>::to_vec));
        Ok(())
    }

    /// Drops the entries a power loss would lose (the deferred ones not
    /// yet made durable).
    pub(crate) fn lose_unsynced(&mut self) {
        for _ in 0..self.unsynced {
            self.entries.pop();
            self.packages.pop();
        }
        self.unsynced = 0;
    }
}

impl JournalSink for MemJournal {
    fn append(&mut self, entry: &[u8], share_package: Option<&[u8]>) -> Result<(), JournalError> {
        self.push(entry, share_package)?;
        self.syncs += 1;
        self.unsynced = 0;
        Ok(())
    }

    fn append_deferred(
        &mut self,
        entry: &[u8],
        share_package: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        self.push(entry, share_package)?;
        self.deferred += 1;
        self.unsynced += 1;
        Ok(())
    }
}

impl MemJournal {
    /// A source reading the journal back from the first entry.
    pub(crate) fn reader(&self) -> MemReader<'_> {
        MemReader {
            journal: self,
            next: 0,
            fail_at: None,
        }
    }

    /// The head after the last entry, as the host re-reads it.
    pub(crate) fn head(&self) -> Hash512 {
        self.entries
            .last()
            .map_or(Hash512::ZERO, |e| ityv_crypto::object_hash(e))
    }
}

/// The stream of a `MemJournal`.
pub(crate) struct MemReader<'a> {
    journal: &'a MemJournal,
    next: usize,
    pub(crate) fail_at: Option<usize>,
}

impl JournalSource for MemReader<'_> {
    fn next_item(
        &mut self,
        entry: &mut [u8],
        package: &mut [u8],
    ) -> Result<Option<JournalItem>, JournalError> {
        if self.fail_at == Some(self.next) {
            return Err(JournalError::Unreadable);
        }
        let Some(bytes) = self.journal.entries.get(self.next) else {
            return Ok(None);
        };
        entry[..bytes.len()].copy_from_slice(bytes);
        let package_len = self.journal.packages[self.next].as_ref().map(|p| {
            package[..p.len()].copy_from_slice(p);
            p.len()
        });
        self.next += 1;
        Ok(Some(JournalItem {
            entry_len: bytes.len(),
            package_len,
        }))
    }
}

/// An `Interpretation` object.
pub(crate) fn interpretation(election: &[u8], style: &[u8], option: u16) -> Vec<u8> {
    let value = Interpretation::new(
        ElectionId::new(election).unwrap(),
        BallotStyleId::new(style).unwrap(),
        option,
    );
    let mut out = vec![0u8; 256];
    let len = encode_object(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, &value, &mut out).unwrap();
    out.truncate(len);
    out
}

/// A boxed work area (about 30 KB, kept off the test thread's stack).
pub(crate) fn work() -> Box<BallotWork> {
    Box::new(BallotWork::new())
}

/// A boxed visit work area.
pub(crate) fn visit_work() -> Box<VisitWork> {
    Box::new(VisitWork::new())
}

/// The device's signer for one operation.
pub(crate) fn signer(world: &World) -> Signer<'_> {
    Signer::new(&world.device_hybrid, &SEED)
}

/// The per-operation device seed of every test.
pub(crate) const SEED: [u8; 32] = [11; 32];

pub(crate) fn tb(n: u64) -> TimeBucket {
    TimeBucket::new(n)
}

/// A `VisitEnd` object.
pub(crate) fn visit_end(election: &[u8], ballots: u8) -> Vec<u8> {
    let value = VisitEnd::new(ElectionId::new(election).unwrap(), ballots).unwrap();
    let mut out = vec![0u8; 128];
    let len = encode_object(SCHEMA_VISIT_END, SCHEMA_VERSION_1, &value, &mut out).unwrap();
    out.truncate(len);
    out
}

/// A staging store in memory, with failure and tampering switches.
#[derive(Default)]
pub(crate) struct MemStaging {
    pub(crate) objects: BTreeMap<(u8, bool), Vec<u8>>,
    pub(crate) fail: bool,
    /// Flips one byte of what `fetch` returns for this object.
    pub(crate) tamper: Option<(u8, Staged)>,
}

fn staged_key(position: u8, kind: Staged) -> (u8, bool) {
    (position, kind == Staged::Package)
}

impl StagingPort for MemStaging {
    fn stage(&mut self, position: u8, kind: Staged, bytes: &[u8]) -> Result<(), PortError> {
        if self.fail {
            return Err(PortError::Transport);
        }
        self.objects
            .insert(staged_key(position, kind), bytes.to_vec());
        Ok(())
    }

    fn fetch(&mut self, position: u8, kind: Staged, out: &mut [u8]) -> Result<usize, PortError> {
        let bytes = self
            .objects
            .get(&staged_key(position, kind))
            .ok_or(PortError::Transport)?;
        let dst = out
            .get_mut(..bytes.len())
            .ok_or(PortError::BufferTooSmall)?;
        dst.copy_from_slice(bytes);
        if self.tamper == Some((position, kind)) {
            dst[20] ^= 1;
        }
        Ok(bytes.len())
    }
}

/// Builds the next position of `ballot` (style, option) and binds it.
pub(crate) fn build_position(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    staging: &mut MemStaging,
    visit: &mut VisitWork,
    (style, option): (&[u8], u16),
) -> Bound {
    let mut bufs = Buffers::new(w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", style, option), &mut area)
        .unwrap();
    let ballot = ballot.issue(b, &mut ports(m), &SEED).unwrap();
    let ballot = ballot.commit(b).unwrap();
    let ballot = ballot
        .build(b, &mut ports(m), &w.device_record, bufs.as_build())
        .unwrap();
    let now = b.last_time_bucket();
    let bound = ballot.bind(b, j, staging, visit, now).unwrap();
    assert!(area.is_clear(), "the work area is wiped once bound");
    bound
}

/// Binds a built ballot as the only position of a visit, casts and
/// imprints it, prints the sticker out of district, finishes.
pub(crate) fn cast_built(
    box_: &mut OpenBox<'static>,
    journal: &mut MemJournal,
    ballot: Ballot<'static, '_, Built<'_>>,
) {
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let now = box_.last_time_bucket();
    ballot
        .bind(box_, journal, &mut staging, &mut visit, now)
        .unwrap();
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            box_,
            Decision::CAST_ALL,
            journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(box_, journal, tb(1)).unwrap();
    let mut processed = decided.finish_positions(box_).unwrap();
    if processed.label_command(box_).is_ok() {
        processed.label_printed(box_, journal, tb(1)).unwrap();
    }
    processed.finish(box_).unwrap();
}

/// What a whole visit produced.
pub(crate) struct VisitResult {
    /// The tracking code of every position.
    pub(crate) codes: Vec<Hash512>,
    /// The `ChallengeOpening` of every checked position, in order.
    pub(crate) openings: Vec<Vec<u8>>,
    /// The staged `CastRecord` and `SharePackage` of every position.
    pub(crate) staging: MemStaging,
}

/// Runs one whole visit: builds and binds every ballot, ends the visit,
/// decides (`checks` bit i = check position i), imprints every cast
/// position and opens every checked one, prints the sticker out of
/// district, finishes. Every entry carries bucket `at`.
pub(crate) fn run_visit(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    ballots: &[(&[u8], u16)],
    checks: u8,
    at: u64,
) -> VisitResult {
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let mut codes = Vec::new();
    for &(style, option) in ballots {
        let bound = build_position(w, b, m, j, &mut staging, &mut visit, (style, option));
        codes.push(*bound.tracking_code());
    }
    let ready = b
        .end_visit(
            &visit_end(b"E-2026", u8::try_from(ballots.len()).unwrap()),
            &mut visit,
        )
        .unwrap();
    let mut package = vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            b,
            Decision::from_checks(checks),
            j,
            &mut staging,
            &mut package,
            tb(at),
        )
        .unwrap();
    let mut openings = Vec::new();
    for _ in ballots {
        let (_, choice) = decided.current(b).expect("a position is left");
        match choice {
            Choice::Cast => {
                let command = decided.imprint_command(b).unwrap();
                assert_eq!(command.cast_id().len(), 24);
                decided.imprinted(b, j, tb(at)).unwrap();
            }
            Choice::Check => {
                let mut out = vec![0u8; 8192];
                let opening = decided.open_challenge(b, signer(w), &mut out).unwrap();
                openings.push(opening.to_vec());
            }
        }
    }
    assert_eq!(decided.current(b), None, "every position is processed");
    let mut processed = decided.finish_positions(b).unwrap();
    if processed.label_command(b).is_ok() {
        processed.label_printed(b, j, tb(at)).unwrap();
    }
    processed.finish(b).unwrap();
    assert!(visit.is_clear(), "the visit work area is wiped at the end");
    VisitResult {
        codes,
        openings,
        staging,
    }
}

/// Casts and imprints one ballot of `style` choosing `option` in a visit
/// of its own; returns its tracking code.
pub(crate) fn cast_with(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    style: &[u8],
    option: u16,
    at: u64,
) -> Hash512 {
    run_visit(w, b, m, j, &[(style, option)], 0, at).codes[0]
}

/// Casts and imprints one small-style ballot; returns its tracking code.
pub(crate) fn cast_one(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) -> Hash512 {
    cast_with(w, b, m, j, STYLE_SMALL, 1, at)
}

/// One small-style ballot in a visit of its own, checked and opened.
pub(crate) fn challenge_one(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) {
    run_visit(w, b, m, j, &[(STYLE_SMALL, 0)], 1, at);
}

/// Owned buffers for one ballot.
pub(crate) struct Buffers {
    pub(crate) scratch: Vec<u8>,
    pub(crate) package: Vec<u8>,
    pub(crate) body: Vec<u8>,
    pub(crate) record: Vec<u8>,
}

impl Buffers {
    pub(crate) fn new(world: &World) -> Self {
        let trustees = world.config.trustees().len();
        Self {
            scratch: vec![0u8; scratch_len(trustees)],
            package: vec![0u8; trustees * SCRATCH_SLOT_LEN + 4096],
            body: vec![0u8; 24_000],
            record: vec![0u8; 24_000],
        }
    }

    pub(crate) fn as_build(&mut self) -> BuildBuffers<'_> {
        BuildBuffers {
            scratch: &mut self.scratch,
            package: &mut self.package,
            body: &mut self.body,
            record: &mut self.record,
        }
    }
}
