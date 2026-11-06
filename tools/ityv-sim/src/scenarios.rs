//! The named scenarios: clean elections at each rung of the status ladder,
//! and attacks and faults, each with what the verifier must say.
//!
//! The expectation of a scenario is part of its definition. The tests and
//! the console compare it with what the verifier actually reports, so a
//! change in either shows up as a mismatch.

use std::sync::OnceLock;

use ityv_encoding::ComparisonCode;
use ityv_encoding::{
    DisputeType, IncidentKind, ProgressAlarm, ProgressBody, ProgressTick, SCHEMA_BOX_CLOSE,
    SCHEMA_CAST_RECORD, SCHEMA_PARTICIPATION_SET, SCHEMA_PROGRESS_TICK, SCHEMA_QUORUM_SIGNED,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, decode_object,
};
use ityv_state::{AuditPhase, HoldReason, Status};
use ityv_verify::AmendmentInput;

use crate::audit::{Audit, Beacon, truthful};
use crate::catalog;
use crate::day::Mark;
use crate::election::{CastInfo, Election, Person, QUORUM};
use crate::ledger::Step;
use crate::plan::{Plan, Until, plan, unit_casts, unit_no_record};
use crate::spec::DayEvent;
use crate::uplink::{Device, Fault};
use crate::util::{leak, leak_slice};

/// Which generated set a scenario belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Set {
    /// Small and fast: CI and the tests.
    Quick,
    /// The large demonstration elections.
    Full,
}

/// How the console groups a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// 정상 선거: an election where nothing went wrong, at some rung of
    /// the ladder.
    Normal,
    /// 공격·장애: something was injected.
    Attack,
}

/// What the caller observed outside the ledger (the inputs of
/// `ityv_ledger::check_board`, and its current time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publications {
    /// The latest checkpoint's time bucket.
    pub checkpoint: u64,
    /// Buckets in which anchor receipts arrived. Kept in the bundle for
    /// the console; the verifier reads the timestamp tokens on the ledger
    /// instead (ADR-0039).
    pub receipts: Vec<u64>,
    /// The close of voting (last close bucket).
    pub close: u64,
    /// When the board was published, if it was.
    pub published: Option<u64>,
    /// The current bucket.
    pub now: u64,
}

/// A tracking code a voter might hold, for the voter app.
#[derive(Debug, Clone)]
pub struct Slip {
    /// The tracking code.
    pub code: ityv_encoding::Hash512,
    /// What the demo uses it for (Korean).
    pub note: &'static str,
}

/// The verifier outcome a scenario must give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The status.
    pub status: Status,
    /// The hold reasons, in code order (empty unless `HOLD_REVIEW`).
    pub holds: Vec<HoldReason>,
}

/// A named scenario.
pub struct Scenario {
    /// File name stem.
    pub name: &'static str,
    /// Generated set.
    pub set: Set,
    /// Console group.
    pub group: Group,
    /// Short Korean title.
    pub title: &'static str,
    /// What the scenario is or what was injected (Korean).
    pub injected: &'static str,
    /// What the verifier should show (Korean).
    pub shows: &'static str,
    /// The election.
    pub election: &'static Election,
    /// The ledger plan.
    pub steps: Vec<Step>,
    /// Amendments handed to the genesis stage.
    pub amendments: Vec<AmendmentInput<'static>>,
    /// The publication deadlines' inputs.
    pub publications: Publications,
    /// The expected outcome.
    pub expected: Expected,
    /// Tracking codes for the voter app demo.
    pub slips: Vec<Slip>,
    /// The beacon publication the caller observed, for an audited ledger
    /// (fixture data; in the bundle, and handed to the verifier).
    pub beacon: Option<Beacon>,
    /// The restricted sample openings a verifier with access would hold
    /// (never on the ledger or in the bundle).
    pub openings: Vec<&'static [u8]>,
}

fn quick_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| leak(Election::build(catalog::quick(Vec::new()))))
}

fn quick_floor_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| {
        leak(Election::build(catalog::quick(vec![DayEvent::Floor {
            at: 2,
            checked: false,
        }])))
    })
}

/// The quick election with a scanner at the election-day station that
/// reads every third candidate mark as `UNREADABLE` (a faint mark).
fn quick_faint_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| {
        leak(Election::build(catalog::quick(vec![DayEvent::Faint {
            index: 0,
            every: 3,
        }])))
    })
}

fn local_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| leak(Election::build(catalog::local())))
}

fn national_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| leak(Election::build(catalog::national())))
}

fn timely(plan: &Plan, last_checkpoint: u64) -> Publications {
    Publications {
        checkpoint: last_checkpoint,
        receipts: vec![last_checkpoint, last_checkpoint + 1, last_checkpoint + 2],
        close: plan.marks.last_close,
        published: Some(plan.marks.last_close + 8),
        now: last_checkpoint + 6,
    }
}

/// The time bucket of the last checkpoint step of `steps`.
fn last_checkpoint_bucket(steps: &[Step]) -> u64 {
    steps
        .iter()
        .rev()
        .find_map(|s| match s {
            Step::Checkpoint { bucket, .. } | Step::ForkCheckpoint { bucket, .. } => Some(*bucket),
            Step::Event { .. } | Step::Stamp { .. } | Step::Uplink(_) => None,
        })
        .unwrap_or(0)
}

fn expected(status: Status, holds: &[HoldReason]) -> Expected {
    let mut holds = holds.to_vec();
    holds.sort();
    holds.dedup();
    Expected { status, holds }
}

fn hold(holds: &[HoldReason]) -> Expected {
    expected(Status::HoldReview, holds)
}

/// A slip not on any ledger: a record the device made but never
/// published (for the voter app's "not found").
fn withheld(e: &Election, b: usize) -> Slip {
    let c = e.cast(b, 9999, 1, Mark::Candidate(1), 0, 7);
    Slip {
        code: c.code,
        note: "공개원장에 없는 코드 (시연용으로 만들고 싣지 않은 기록)",
    }
}

fn included(c: &CastInfo, note: &'static str) -> Slip {
    Slip { code: c.code, note }
}

struct Builder {
    e: &'static Election,
    plan: Plan,
}

impl Builder {
    fn new(e: &'static Election, until: Until) -> Self {
        Self {
            e,
            plan: plan(e, until),
        }
    }

    fn scenario(
        self,
        name: &'static str,
        set: Set,
        group: Group,
        text: (&'static str, &'static str, &'static str),
        expected: Expected,
        slips: Vec<Slip>,
    ) -> Scenario {
        let bucket = last_checkpoint_bucket(&self.plan.steps);
        let publications = timely(&self.plan, bucket);
        Scenario {
            name,
            set,
            group,
            title: text.0,
            injected: text.1,
            shows: text.2,
            election: self.e,
            publications,
            steps: self.plan.steps,
            amendments: Vec::new(),
            expected,
            slips,
            beacon: None,
            openings: Vec::new(),
        }
    }
}

/// The scenario of the audit `a` (quick set).
fn audited(
    a: Audit,
    name: &'static str,
    group: Group,
    text: (&'static str, &'static str, &'static str),
    expected: Expected,
    slips: Vec<Slip>,
) -> Scenario {
    let bucket = last_checkpoint_bucket(&a.plan.steps);
    let publications = timely(&a.plan, bucket);
    Scenario {
        name,
        set: Set::Quick,
        group,
        title: text.0,
        injected: text.1,
        shows: text.2,
        election: a.e,
        publications,
        steps: a.plan.steps,
        amendments: Vec::new(),
        expected,
        slips,
        beacon: a.beacon,
        openings: a.openings,
    }
}

/// An audit through its seed: freezes (`rules` where given), the commit,
/// the binding checkpoint right after it, and the seed over the first
/// fixture output for which `wanted` holds.
fn seeded(
    e: &'static Election,
    rules: &[(&'static str, Vec<(u64, u32)>)],
    wanted: impl Fn(&Audit, &ityv_encoding::Hash512) -> bool,
) -> Audit {
    let mut a = Audit::new(e);
    a.freeze_all(rules);
    a.commit();
    a.checkpoint(a.t.binding);
    a.seed(wanted);
    a
}

/// Whether the first `n` records `seed` draws for `style` include a
/// ballot the paper shows otherwise than the record.
fn misread_among_first(a: &Audit, seed: &ityv_encoding::Hash512, style: &str, n: usize) -> bool {
    a.drawn(style, seed)[..n]
        .iter()
        .any(|r| truthful(&r.cast) != ComparisonCode::Match)
}

/// The audit scenarios (quick set).
fn audit_scenarios(out: &mut Vec<Scenario>, slips: &[Slip]) {
    use HoldReason as H;
    let e = quick_election();
    let n = Group::Normal;
    let a_ = Group::Attack;
    let refused_seed = [
        H::AuditSeedRefused,
        H::SampleOpeningRefused,
        H::SampleComparisonRefused,
    ];

    // --- 정상 선거 -------------------------------------------------------
    {
        let mut a = seeded(e, &[], |_, _| true);
        for style in ["S-HB", "S-NR"] {
            let phase = a.compare(style, |r| truthful(&r.cast));
            assert_eq!(phase, AuditPhase::Concluded { round: 0 });
        }
        a.finish();
        out.push(audited(
            a,
            "audit-clean",
            n,
            (
                "빠른 시연: 감사까지 끝난 선거",
                "깨끗한 선거의 집계 뒤에 투표양식마다 감사 동결(표본 프레임과 라운드 규칙), 감사 약정(주사위 기록·비콘 지정·동결을 고정), 약정 직후의 고정 체크포인트, 비콘 공표 뒤의 시드, 표본 기록마다 신뢰기관의 열기 흔적과 감사인의 종이 대조(모두 일치)가 실렸다. 비콘 관찰(회차·출력·공표 구간)은 시연용 고정 자료다.",
                "PAPER_AUDITED. 보류 없음. 고정 체크포인트가 비콘 공표보다 7구간 앞서고(규칙은 3구간 이상), 시드보다 앞 프레임에 정부 운영 기관과 정부 밖 기관의 시점확인 토큰이 공표 전 시각으로 있으며(ADR-0039), 두 투표양식 모두 첫 라운드에서 끝났다. 비콘 관찰 없이 검증하면 감사를 끝낼 수 없어 CRYPTO_TALLY_VERIFIED에 머문다.",
            ),
            expected(Status::PaperAudited, &[]),
            slips.to_vec(),
        ));
    }
    let faint = quick_faint_election();
    {
        let mut a = seeded(faint, &[("S-HB", vec![(3, 0), (8, 3)])], |a, seed| {
            misread_among_first(a, seed, "S-HB", 3)
        });
        let phase = a.compare("S-HB", |r| truthful(&r.cast));
        assert_eq!(phase, AuditPhase::Concluded { round: 1 });
        a.compare("S-NR", |r| truthful(&r.cast));
        a.finish();
        out.push(audited(
            a,
            "audit-escalation",
            n,
            (
                "감사 확대: 둘째 라운드",
                "한빛초등학교 체육관 투표함의 스캐너가 후보 표시 세 장 가운데 한 장을 판독 불가(UNREADABLE)로 읽었다(희미한 표시). 한빛구청장 감사 규칙은 첫 라운드 3장·불일치 0장, 둘째 라운드 8장·불일치 3장이다. 첫 라운드 표본에 그런 투표지가 나와 감사인이 코드 3(기록은 판독 불가, 종이는 유효표)을 적었다.",
                "첫 라운드의 불일치가 상한을 넘어 표본이 둘째 라운드로 늘고, 둘째 라운드가 상한 안에서 끝난다: PAPER_AUDITED. 판독 불가 기록은 종이 계수 보고와 어긋나지 않는다(종이 표가 기계 표보다 적지 않다).",
            ),
            expected(Status::PaperAudited, &[]),
            slips.to_vec(),
        ));
    }
    {
        let mut a = seeded(faint, &[("S-HB", vec![(3, 0)])], |a, seed| {
            misread_among_first(a, seed, "S-HB", 3)
        });
        let phase = a.compare("S-HB", |r| truthful(&r.cast));
        assert_eq!(phase, AuditPhase::HandCount);
        a.compare("S-NR", |r| truthful(&r.cast));
        a.finish();
        out.push(audited(
            a,
            "audit-hand-count",
            n,
            (
                "감사 끝에 수검표",
                "같은 희미한 표시의 스캐너. 이번 한빛구청장 감사 규칙은 한 라운드(3장·불일치 0장)뿐이고, 그 표본에 판독 불가로 읽힌 유효표가 나왔다.",
                "마지막 라운드의 상한을 넘었으므로 그 투표양식 전체를 손으로 센다. 보고 단위의 수검표(HandCountReport)가 실려 감사가 끝난다: PAPER_AUDITED. 수검표가 법적 결과이며 검증기는 그것을 보일 뿐 기계 합계와 비교하지 않는다.",
            ),
            expected(Status::PaperAudited, &[]),
            slips.to_vec(),
        ));
    }
    {
        let mut a = seeded(e, &[], |_, _| true);
        let phase = a.compare("S-HB", |r| truthful(&r.cast));
        assert_eq!(phase, AuditPhase::Concluded { round: 0 });
        a.finish();
        out.push(audited(
            a,
            "audit-one-style",
            n,
            (
                "한 투표양식만 감사",
                "두 투표양식 모두 동결·약정·시드까지 실렸지만 종이 대조는 한빛구청장만 했다. 누리구청장 표본은 열지도 대조하지도 않았다.",
                "보류는 없지만 모든 투표양식의 감사가 끝나야 하므로 장부 전체는 CRYPTO_TALLY_VERIFIED에 머문다. 보고 단위별 표에서 한빛구는 PAPER_AUDITED, 누리구는 CRYPTO_TALLY_VERIFIED다.",
            ),
            expected(Status::CryptoTallyVerified, &[]),
            slips.to_vec(),
        ));
    }

    // --- 공격·장애 -------------------------------------------------------
    {
        let mut a = seeded(e, &[], |_, _| true);
        let hb = e.box_index("BOX-HB-1");
        let seed = a.seed.unwrap();
        let first = *a.drawn("S-HB", &seed)[..4]
            .iter()
            .find(|r| r.b == hb)
            .unwrap();
        let Mark::Candidate(t) = first.cast.mark else {
            panic!("a candidate record");
        };
        let other = e.casts[hb]
            .iter()
            .find(|c| matches!(c.mark, Mark::Candidate(u) if u != t))
            .unwrap()
            .code;
        let swapped = [first.cast.code, other];
        let phase = a.compare("S-HB", |r| {
            if swapped.contains(&r.cast.code) {
                ComparisonCode::OtherCandidate
            } else {
                truthful(&r.cast)
            }
        });
        assert!(matches!(phase, AuditPhase::Concluded { .. }));
        a.compare("S-NR", |r| truthful(&r.cast));
        a.finish();
        out.push(audited(
            a,
            "fault-swapped-readings",
            a_,
            (
                "두 판독이 뒤바뀐 스캐너",
                "한빛초등학교 체육관 투표함의 스캐너가 서로 다른 후보를 찍은 투표지 두 장의 판독을 바꿔 기록했다. 후보별 합은 그대로라 종이 계수 보고와는 맞는다. 표본에 그중 한 장이 나와 감사인이 코드 1(기록과 다른 후보)을 적었다.",
                "코드 1은 그 장치의 기록 전수 대조와 감사 발견(AuditFinding)을 부른다. 전수 대조에서 나머지 한 장도 코드 1로 나오고 발견이 기록되어 감사가 끝난다: PAPER_AUDITED. 합계 대조로는 보이지 않는 장치 결함을 기록 단위의 대조가 찾은 경우다.",
            ),
            expected(Status::PaperAudited, &[]),
            Vec::new(),
        ));
    }
    {
        let mut a = seeded(e, &[], |_, _| true);
        let seed = a.seed.unwrap();
        let missing = a.drawn("S-HB", &seed)[0].cast.code;
        a.compare("S-HB", |r| {
            if r.cast.code == missing {
                ComparisonCode::BallotMissing
            } else {
                truthful(&r.cast)
            }
        });
        a.compare("S-NR", |r| truthful(&r.cast));
        a.finish();
        out.push(audited(
            a,
            "fault-audit-ballot-missing",
            a_,
            (
                "표본 투표지가 없음(코드 5)",
                "감사인이 한빛구청장 표본의 첫 기록에 각인된 cast id를 가진 투표지를 투표함에서 찾지 못했다(코드 5).",
                "그 투표함과 투표양식의 보관을 조사해야 하므로 HOLD_REVIEW(AuditCustody). 라운드 상한 안이어도 감사는 끝나지 않는다.",
            ),
            hold(&[H::AuditCustody]),
            Vec::new(),
        ));
    }
    {
        // No checkpoint after the commit until the beacon is public; then
        // one timed two buckets before the publication.
        let mut a = Audit::new(e);
        a.freeze_all(&[]);
        a.commit();
        // The witnesses date it two buckets before the publication; the
        // honest timestamp authorities stamp it when it is made, after the
        // publication.
        let made = a.t.published + 1;
        a.checkpoint_stamped(
            a.t.published - 2,
            &[(crate::tsa::GOV, made), (crate::tsa::FREE, made)],
        );
        a.seed(|_, _| true);
        for style in ["S-HB", "S-NR"] {
            a.compare(style, |r| truthful(&r.cast));
        }
        a.finish();
        out.push(audited(
            a,
            "attack-seed-grinding",
            a_,
            (
                "비콘을 본 뒤 고른 고정 체크포인트",
                "감사 약정 뒤 체크포인트를 바로 자르지 않았다. 비콘 회차가 공표된 뒤, 공표 구간보다 2구간 앞선 시각을 적은 체크포인트에 증인 서명을 받았다. 시계가 1분 늦은 정직한 증인은 공표 직후에도 그 구간에 서명할 수 있으므로, 운영자는 비콘 값을 보고 원하는 표본이 나오는 체크포인트를 고를 수 있었다.",
                "고정 체크포인트는 공표보다 3구간 이상 앞서야 한다(binding ≤ P − 3). 시드가 늦음(Late)으로 거부되고 그 뒤의 열기 흔적과 대조도 받지 않는다: HOLD_REVIEW. 증인 시각을 속여도 소용없다: 정직한 시점확인 기관의 토큰은 체크포인트를 만든 때(공표 뒤)의 시각이라, 공표 구간보다 앞선 토큰을 요구하는 규칙(ADR-0039)으로도 거부된다. 검증기는 먼저 걸린 규칙(Late)을 보인다.",
            ),
            hold(&refused_seed),
            Vec::new(),
        ));
    }
    {
        let mut a = Audit::new(e);
        a.freeze_all(&[]);
        a.commit_with(a.dice, a.t.commit + 1);
        a.checkpoint(a.t.commit);
        a.seed(|_, _| true);
        for style in ["S-HB", "S-NR"] {
            a.compare(style, |r| truthful(&r.cast));
        }
        a.finish();
        out.push(audited(
            a,
            "attack-binding-backdated",
            a_,
            (
                "약정보다 이른 고정 체크포인트",
                "감사 약정에 실제보다 늦은 시각을 적었다. 약정을 덮는 첫 체크포인트(증인이 시각을 증언한다)가 약정에 적힌 시각보다 한 구간 이르다.",
                "증인이 증언한 시각은 줄지 않으므로 그런 약정의 시각은 증언된 것이 아니다. 시드가 Backdated로 거부되고 열기 흔적과 대조도 받지 않는다: HOLD_REVIEW.",
            ),
            hold(&refused_seed),
            Vec::new(),
        ));
    }
    {
        // The binding checkpoint stamped by the government's authority
        // alone.
        let mut a = Audit::new(e);
        a.freeze_all(&[]);
        a.commit();
        a.checkpoint_stamped(a.t.binding, &[(crate::tsa::GOV, a.t.binding)]);
        a.seed(|_, _| true);
        for style in ["S-HB", "S-NR"] {
            a.compare(style, |r| truthful(&r.cast));
        }
        a.finish();
        out.push(audited(
            a,
            "attack-binding-unstamped",
            a_,
            (
                "한 기관만 찍은 고정 체크포인트",
                "약정 직후의 고정 체크포인트에 정부 운영 시점확인 기관의 토큰만 있다. 정부 밖 기관의 토큰은 시드 전에 실리지 않았다. 증인 시각의 규칙(공표보다 3구간 이상 앞섬)은 지켰다.",
                "고정 체크포인트가 비콘 공표 전에 있었음은 증인 정족수만이 아니라 정부 운영과 정부 밖, 두 운영 주체의 토큰이 함께 보여야 한다(ADR-0039 8항). 시드가 Unstamped로 거부되고 열기 흔적과 대조도 받지 않는다: HOLD_REVIEW.",
            ),
            hold(&refused_seed),
            Vec::new(),
        ));
    }
    {
        let mut a = Audit::new(e);
        a.freeze_all(&[]);
        a.checkpoint(a.t.binding);
        a.seed(|_, _| true);
        for style in ["S-HB", "S-NR"] {
            a.compare(style, |r| truthful(&r.cast));
        }
        a.finish();
        out.push(audited(
            a,
            "fault-commit-missing",
            a_,
            (
                "감사 약정 없는 시드",
                "동결 뒤 감사 약정(AuditCommit)을 싣지 않고 체크포인트를 자른 뒤 시드를 실었다. 주사위 기록과 동결이 비콘 공표 전에 고정되지 않았다.",
                "약정이 없으면 시드는 너무 이르다(Premature): 거부되고 열기 흔적과 대조도 받지 않는다. HOLD_REVIEW.",
            ),
            hold(&refused_seed),
            Vec::new(),
        ));
    }
    {
        let mut a = Audit::new(e);
        a.freeze_all(&[]);
        a.commit();
        let other = crate::util::hash_of("audit-dice-other", &[e.eid.as_bytes()]);
        a.commit_with(other, a.t.commit);
        a.checkpoint(a.t.binding);
        a.seed(|_, _| true);
        for style in ["S-HB", "S-NR"] {
            a.compare(style, |r| truthful(&r.cast));
        }
        a.finish();
        out.push(audited(
            a,
            "attack-commit-conflict",
            a_,
            (
                "서로 다른 감사 약정 두 개",
                "첫 감사 약정 바로 뒤에, 다른 주사위 기록을 적은 두 번째 약정이 위원회와 참관인의 서명으로 실렸다. 운영자가 고를 수 있는 시드 입력이 둘이 된다.",
                "두 번째 약정은 충돌(Conflict)로 거부되어 HOLD_REVIEW(AuditCommitRefused). 감사는 첫 약정으로 끝까지 진행되지만 보류는 사람이 정리할 일이다.",
            ),
            hold(&[H::AuditCommitRefused]),
            Vec::new(),
        ));
    }
}

fn insert_after(steps: &mut Vec<Step>, at: usize, step: Step) {
    steps.insert(at + 1, step);
}

/// The record steps' casts of box `b` (by counter, from 1).
fn cast_of(e: &Election, b: usize, counter: usize) -> CastInfo {
    e.casts[b][counter - 1]
}

/// Every scenario of `set` (the full set includes the quick one).
#[must_use]
pub fn scenarios(set: Set) -> Vec<Scenario> {
    let mut out = quick_scenarios();
    if set == Set::Full {
        out.extend(full_scenarios());
    }
    out
}

fn quick_scenarios() -> Vec<Scenario> {
    use HoldReason as H;
    let e = quick_election();
    let q = Set::Quick;
    let mut out = Vec::new();
    let hb = e.box_index("BOX-HB-1");
    let out_box = e.box_index("BOX-NR-P-OUT");
    let nr_in = e.box_index("BOX-NR-P-IN");
    let slips = vec![
        included(
            &cast_of(e, hb, 1),
            "체크포인트에 포함된 코드 (한빛초등학교 체육관)",
        ),
        included(
            &cast_of(e, out_box, 1),
            "체크포인트에 포함된 코드 (관외 투표함)",
        ),
        withheld(e, hb),
    ];

    // --- 정상 선거 -------------------------------------------------------
    out.push(Builder::new(e, Until::Tallied).scenario(
        "quick-clean",
        q,
        Group::Normal,
        (
            "빠른 시연: 깨끗한 선거",
            "두 구, 투표소 둘(사전투표소의 관외 투표함 포함), 한 시간 투표, 마감, 참여 장부, 수령 대조, 단위별 집계 범위·합계 열기·종이 보고까지 모두 실렸다.",
            "CRYPTO_TALLY_VERIFIED. 보류 없음. 감사 이벤트가 없으므로 PAPER_AUDITED에는 닿지 않는다(감사까지 실린 장부는 '감사까지 끝난 선거').",
        ),
        expected(Status::CryptoTallyVerified, &[]),
        slips.clone(),
    ));
    let voting_slot = e.days[e.station_index("ST-HB-1")].open_slot + 3;
    out.push(Builder::new(e, Until::Voting(voting_slot)).scenario(
        "quick-voting",
        q,
        Group::Normal,
        (
            "빠른 시연: 투표 중",
            "사전투표소는 마감했고 선거일 투표소는 06:30까지 투표 중이다. 그때까지의 프레임을 체크포인트가 덮는다.",
            "LOG_CONSISTENT. 열린 투표함은 보류가 아니라 완전성 미달이다. 집계가 끝났다는 뜻이 아니다.",
        ),
        expected(Status::LogConsistent, &[]),
        vec![
            included(&cast_of(e, nr_in, 1), "마감한 사전투표소의 코드"),
            included(&cast_of(e, hb, 1), "투표 중인 투표소의 코드"),
        ],
    ));
    out.push(Builder::new(e, Until::Closed).scenario(
        "quick-closed",
        q,
        Group::Normal,
        (
            "빠른 시연: 마감, 집계 전",
            "모든 투표함이 마감되고 투표소 수량·참여 집합·수령 대조가 실렸다. 집계 범위와 합계 열기는 아직 없다.",
            "SOURCE_COMPLETENESS_CHECKED. 집계 단계는 아직 실행되지 않았다.",
        ),
        expected(Status::SourceCompletenessChecked, &[]),
        slips.clone(),
    ));
    let mut s = Builder::new(e, Until::Tallied).scenario(
        "quick-anchor-pending",
        q,
        Group::Normal,
        (
            "빠른 시연: 앵커 대기",
            "깨끗한 선거와 같은 장부. 다만 마지막 체크포인트의 시점확인 토큰이 아직 정부 운영 기관 하나의 것뿐이고 기한은 남았다.",
            "UNVERIFIED. 앵커가 충족되기 전에는 어떤 단계가 통과해도 사다리를 오르지 않는다.",
        ),
        expected(Status::Unverified, &[]),
        slips.clone(),
    );
    s.publications.receipts = vec![s.publications.checkpoint];
    s.publications.now = s.publications.checkpoint + 1;
    if let Some(Step::Checkpoint { stamps, .. }) = s
        .steps
        .iter_mut()
        .rev()
        .find(|step| matches!(step, Step::Checkpoint { .. }))
    {
        *stamps = 1;
    }
    out.push(s);

    // --- 공격·장애 -------------------------------------------------------
    let a = Group::Attack;
    // Tampered record (표갈이).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let orig = cast_of(e, hb, 2);
        let other = if orig.option == 1 { 2 } else { 1 };
        let changed = e.cast(hb, 2, other, Mark::Candidate(other), orig.slot, 1);
        let tampered = Election::resigned_with(&changed, &orig);
        let at = bld.plan.marks.records[hb][1];
        bld.plan.steps[at] = Step::event(SCHEMA_CAST_RECORD, tampered);
        out.push(bld.scenario(
            "attack-tampered-record",
            q,
            a,
            (
                "기록 바꿔치기(표갈이)",
                "한빛초등학교 체육관 투표함의 두 번째 기록을, 다른 선택으로 새로 만든 본문에 원래 기록의 장치·모듈 서명을 붙여 실었다.",
                "그 기록은 장치 서명이 맞지 않아 거부(RecordRejected)되고, 배치·마감 기록 집합·집계 범위가 줄줄이 어긋난다. HOLD_REVIEW.",
            ),
            hold(&[
                H::RecordRejected,
                H::IssuanceMismatch,
                H::BatchInvalid,
                H::RecordSetMismatch,
                H::TallyScopeMismatch,
                H::AggregateMismatch,
            ]),
            Vec::new(),
        ));
    }
    // Forked / rolled-back checkpoint.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let bucket = last_checkpoint_bucket(&bld.plan.steps);
        bld.plan
            .steps
            .push(Step::ForkCheckpoint { bucket, dropped: 3 });
        out.push(bld.scenario(
            "attack-checkpoint-fork",
            q,
            a,
            (
                "체크포인트 되돌리기(분기)",
                "증인 정족수가 마지막 체크포인트와 같은 순번으로, 프레임 셋을 뺀 더 작은 트리에 다시 서명했다.",
                "후속 규칙 위반으로 체크포인트 사슬이 그 자리에서 끝나고 장부 전체가 HOLD_REVIEW(CheckpointInvalid).",
            ),
            hold(&[H::CheckpointInvalid, H::StepFailed]),
            Vec::new(),
        ));
    }
    // Replayed record.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld.plan.marks.records[hb][0];
        let step = bld.plan.steps[at].clone();
        insert_after(&mut bld.plan.steps, at, step);
        out.push(bld.scenario(
            "attack-replayed-record",
            q,
            a,
            (
                "같은 기록 두 번 싣기",
                "한빛초등학교 체육관 투표함의 첫 기록을 바로 다음 프레임에 한 번 더 실었다.",
                "두 번째 프레임은 무효(재수록)이고 그 투표함이 HOLD_REVIEW(EventReplayed). 기록은 한 번만 센다.",
            ),
            hold(&[H::EventReplayed]),
            Vec::new(),
        ));
    }
    // Conflicting tally scope.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let u = bld.plan.marks.tally[0].0;
        let scope_at = bld.plan.marks.tally[0].1;
        let casts = unit_casts(e, u);
        let codes: Vec<_> = casts.iter().map(|c| c.code).collect();
        let body = e.scope_body(
            u.style,
            u.unit,
            &codes[..codes.len() - 1],
            &[],
            unit_no_record(e, u),
            bld.plan.marks.ready + 1,
        );
        insert_after(
            &mut bld.plan.steps,
            scope_at,
            Step::event(
                SCHEMA_QUORUM_SIGNED,
                e.quorum(body, b"tally-scope", &QUORUM),
            ),
        );
        out.push(bld.scenario(
            "attack-conflicting-scope",
            q,
            a,
            (
                "서로 다른 집계 범위 두 개",
                "신뢰기관 정족수가 같은 투표양식·보고 단위에 기록 하나를 뺀 두 번째 집계 범위에 서명했다.",
                "두 번째 범위는 충돌(Conflict)로 거부되고 HOLD_REVIEW(TallyScopeRefused). 사람이 정리할 일이다.",
            ),
            hold(&[H::TallyScopeRefused]),
            Vec::new(),
        ));
    }
    // Record after close.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let close_at = bld.plan.marks.closes[hb].unwrap();
        let n = e.casts[hb].len() as u64;
        let late = e.cast(hb, n + 1, 1, Mark::Candidate(1), 0, 2);
        insert_after(
            &mut bld.plan.steps,
            close_at,
            Step::event(SCHEMA_CAST_RECORD, late.event),
        );
        out.push(bld.scenario(
            "attack-record-after-close",
            q,
            a,
            (
                "마감 뒤 기록 끼워 넣기",
                "한빛초등학교 체육관 투표함의 마감 프레임 바로 뒤에, 서명이 맞는 새 기록을 하나 실었다.",
                "그 기록은 무효이고 투표함이 HOLD_REVIEW(RecordAfterClose). 집계에 들어가지 않는다.",
            ),
            hold(&[H::RecordAfterClose]),
            Vec::new(),
        ));
    }
    // A mirror's copy with an altered event.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld.plan.marks.records[nr_in][0];
        if let Step::Event { event, .. } = bld.plan.steps[at].clone() {
            let mut bytes = event.to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            bld.plan.steps[at] = Step::Event {
                schema: SCHEMA_CAST_RECORD,
                event,
                published: Some(leak_slice(bytes)),
                filed: None,
            };
        }
        out.push(bld.scenario(
            "attack-mirror-tampered",
            q,
            a,
            (
                "미러 사본의 바뀐 바이트",
                "프레임은 그대로 두고, 함께 공표한 이벤트 가운데 기록 하나의 마지막 바이트를 바꿨다(미러가 사본을 고친 경우).",
                "프레임이 가리키는 해시의 이벤트가 없어 그 프레임이 거부되고 장부 전체가 HOLD_REVIEW(LedgerUnchecked). 그 기록이 빠지므로 배치·마감 수량·교부 등식·집계 범위도 함께 어긋난다. 스캐너가 그 기록 뒤에 보낸 봉인 share 패키지는 받아들여진 기록 어느 것도 가리키지 않으므로 UplinkObjectInvalid(NotOnLedger)도 걸린다.",
            ),
            hold(&[
                H::LedgerUnchecked,
                H::StepFailed,
                H::ObservedCountMismatch,
                H::IssuanceMismatch,
                H::BatchInvalid,
                H::RecordSetMismatch,
                H::TallyScopeMismatch,
                H::AggregateMismatch,
                H::UplinkObjectInvalid,
            ]),
            Vec::new(),
        ));
    }
    // An event of a schema the verifier does not know.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld.plan.marks.authorization;
        let unknown = crate::util::text("ityv-sim: an object of no known ledger schema");
        insert_after(
            &mut bld.plan.steps,
            at,
            Step::event(SchemaId::new(0x7E57), unknown),
        );
        out.push(bld.scenario(
            "attack-unknown-event",
            q,
            a,
            (
                "알 수 없는 이벤트",
                "법적 승인 바로 뒤에, 검증기가 모르는 스키마(0x7E57)의 이벤트를 싣는 프레임을 끼웠다.",
                "그 프레임은 무효이고 장부 전체가 HOLD_REVIEW(LedgerUnchecked). 무효 프레임도 트리에는 남는다.",
            ),
            hold(&[H::LedgerUnchecked, H::StepFailed]),
            Vec::new(),
        ));
    }
    // Missing checkpoint coverage.
    {
        let mut bld = Builder::new(e, Until::Voting(voting_slot));
        let last = bld
            .plan
            .steps
            .iter()
            .rposition(|s| matches!(s, Step::Checkpoint { .. }))
            .unwrap();
        bld.plan.steps.remove(last);
        let slips = vec![
            included(
                &cast_of(e, nr_in, 1),
                "체크포인트에 포함된 코드 (사전투표소)",
            ),
            included(
                &cast_of(e, hb, 1),
                "장부에는 있지만 아직 어느 체크포인트도 덮지 않은 코드",
            ),
        ];
        let mut s = bld.scenario(
            "fault-missing-coverage",
            q,
            a,
            (
                "체크포인트가 덮지 않은 프레임",
                "선거일 투표 중의 기록과 진행 기록이 장부에 실렸지만, 그 뒤 체크포인트가 아직 없다.",
                "UNVERIFIED. 덮이지 않은 프레임이 있으면 체크포인트 단계는 통과가 아니다. 보류는 아니다.",
            ),
            expected(Status::Unverified, &[]),
            slips,
        );
        s.publications.close = e.days[0].close_bucket;
        s.publications.published = None;
        out.push(s);
    }
    // Paper count disagrees.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let (u, _, _, paper_at) = bld.plan.marks.tally[0].clone();
        let (mut votes, invalid) = e.paper_truth(u.style, u.unit);
        let top = (0..votes.len()).max_by_key(|i| votes[*i]).unwrap();
        let other = (top + 1) % votes.len();
        votes[top] -= 1;
        votes[other] += 1;
        let ready = bld.plan.marks.ready;
        bld.plan.steps[paper_at] = Step::event(
            SCHEMA_WITNESSED_EVENT,
            e.paper(u.style, u.unit, &votes, invalid, ready + 3),
        );
        out.push(bld.scenario(
            "attack-paper-mismatch",
            q,
            a,
            (
                "종이 보고가 기계 수와 다름",
                "한빛구청장 투표양식의 종이 계수 보고에서 가장 많이 받은 후보의 한 표를 다른 후보로 옮겨 적었다.",
                "그 후보의 종이 표가 확인된 기계 수보다 적어 그 단위가 HOLD_REVIEW(PaperCountMismatch). 부정의 증거 자체는 아니며 감사가 원인을 찾는다.",
            ),
            hold(&[H::PaperCountMismatch]),
            Vec::new(),
        ));
    }
    // Aggregate opening of another sum.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let (u, scope_at, openings, _) = bld.plan.marks.tally[0].clone();
        let mut casts = unit_casts(e, u);
        casts[0].option = if casts[0].option == 1 { 2 } else { 1 };
        let codes: Vec<_> = unit_casts(e, u).iter().map(|c| c.code).collect();
        let ready = bld.plan.marks.ready;
        let body = e.scope_body(
            u.style,
            u.unit,
            &codes,
            &[],
            unit_no_record(e, u),
            ready + 1,
        );
        debug_assert!(bld.plan.steps[scope_at].event_bytes().is_some());
        let ob = e.opening_body(u.style, u.unit, body, 0, &casts, ready + 2);
        bld.plan.steps[openings[0]] = Step::event(
            SCHEMA_QUORUM_SIGNED,
            e.quorum(ob, b"aggregate-opening", &QUORUM),
        );
        out.push(bld.scenario(
            "attack-aggregate-mismatch",
            q,
            a,
            (
                "합계 열기 값 조작",
                "신뢰기관이 한빛구청장 합계 열기에서 한 표를 다른 후보로 옮긴 합(packed sum)을 냈다.",
                "공개된 커밋먼트의 실제 합이 열리지 않아 그 단위가 HOLD_REVIEW(AggregateMismatch). 신뢰기관은 이분 탐색으로 잘못된 투표함을 찾는다.",
            ),
            hold(&[H::AggregateMismatch]),
            Vec::new(),
        ));
    }
    // Out-of-district receipts not resolved before the scope.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld
            .plan
            .steps
            .iter()
            .position(|s| {
                s.event_bytes()
                    .is_some_and(|ev| ev == e.resolution(out_box, bld.plan.marks.ready))
            })
            .unwrap();
        bld.plan.steps.remove(at);
        out.push(bld.scenario(
            "attack-receipt-unresolved",
            q,
            a,
            (
                "관외 수령 대조 없이 집계",
                "누리구 사전투표소 관외 투표함의 수령 대조(ReceiptResolution)를 싣지 않은 채, 한빛구청장 집계 범위와 합계 열기를 실었다.",
                "그 범위는 수령 대조를 기다려야 하므로 너무 이르다(Premature): HOLD_REVIEW(TallyScopeRefused), 범위가 없는 열기도 거부(AggregateRefused).",
            ),
            hold(&[H::TallyScopeRefused, H::AggregateRefused]),
            Vec::new(),
        ));
    }
    // Signers under roles the roster does not give them.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let s = e.station_index("ST-HB-1");
        let mut people = e.people(s);
        for p in &mut people {
            if p.id.ends_with("clerk-2") {
                *p = Person {
                    role: ityv_encoding::EventRole::Observer,
                    ..p.clone()
                };
            } else if p.id.ends_with("obs-b") {
                *p = Person {
                    role: ityv_encoding::EventRole::Clerk,
                    ..p.clone()
                };
            }
        }
        let at = bld.plan.marks.issuance[s].unwrap();
        bld.plan.steps[at] = Step::event(SCHEMA_WITNESSED_EVENT, e.issuance(s, &people));
        out.push(bld.scenario(
            "attack-wrong-role",
            q,
            a,
            (
                "역할을 바꿔 적은 서명자",
                "한빛초등학교 체육관의 교부 수(IssuanceCount)에 사무원 한 명은 참관인으로, 참관인 한 명은 사무원으로 서명했다. 서명은 그 사람들의 진짜 키다.",
                "명부가 그 역할로 등록하지 않은 서명이라 받지 못하고 HOLD_REVIEW(StationCountRefused). 마감 진행 기록과 맞춰 볼 교부 수가 없어 진행 기록 대조도 보류(ProgressStream).",
            ),
            hold(&[H::StationCountRefused, H::ProgressStream]),
            Vec::new(),
        ));
    }
    // An amendment the verifier applied is not on the ledger.
    {
        let bld = Builder::new(e, Until::Tallied);
        let mut s = bld.scenario(
            "fault-missing-amendment",
            q,
            a,
            (
                "장부에 없는 genesis 변경",
                "검증기에 genesis 변경(장치 교체 1호)을 함께 넘겼지만 장부에는 그 변경이 실리지 않았다.",
                "변경이 어느 프레임부터 적용되는지 알 수 없어 장부 전체가 HOLD_REVIEW(AmendmentMissing), 프레임 단계는 실패(StepFailed).",
            ),
            hold(&[H::AmendmentMissing, H::StepFailed]),
            Vec::new(),
        );
        s.amendments = vec![e.unchanged_amendment()];
        out.push(s);
    }
    // A floor alarm nobody checked.
    {
        let f = quick_floor_election();
        let st = f.station_index("ST-HB-1");
        let alarm = f.days[st].alarms[0];
        assert_eq!(alarm.1, ProgressAlarm::Floor);
        out.push(Builder::new(f, Until::Tallied).scenario(
            "fault-progress-unresolved",
            q,
            a,
            (
                "확인하지 않은 바닥 경보",
                "선거일 투표소에서 투표지 한 장이 두 슬롯 넘게 바깥에 머물렀는데(바닥 경보) 두 슬롯 안에 현장 확인(ProgressCheck)이 수록되지 않았다.",
                "그 투표소의 투표함이 HOLD_REVIEW(ProgressUnresolved)이고 마감까지 교부 번호 대조를 한다. 어떤 투표지도 무효가 되지 않는다.",
            ),
            hold(&[H::ProgressUnresolved]),
            Vec::new(),
        ));
    }
    // A manual close replaced by a late close after the scope.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let close_at = bld.plan.marks.closes[hb].unwrap();
        let n = e.casts[hb].len() as u64;
        let codes: Vec<_> = e.casts[hb].iter().map(|c| c.code).collect();
        bld.plan.steps[close_at] = Step::event(
            SCHEMA_BOX_CLOSE,
            e.close(hb, e.close_counts(hb, n, n), &codes, None, None),
        );
        let scope_at = bld
            .plan
            .marks
            .tally
            .iter()
            .find(|t| t.0.style == e.boxes[hb].style && t.0.unit == e.boxes[hb].unit)
            .unwrap()
            .1;
        insert_after(
            &mut bld.plan.steps,
            scope_at,
            Step::event(
                SCHEMA_BOX_CLOSE,
                e.close(
                    hb,
                    e.close_counts(hb, n, n),
                    &codes,
                    Some(b"late-box-close"),
                    None,
                ),
            ),
        );
        out.push(bld.scenario(
            "attack-late-close-after-scope",
            q,
            a,
            (
                "집계 범위 뒤의 늦은 마감",
                "한빛초등학교 체육관 투표함을 장치 서명 없이 수동 마감했고, 장치 서명이 있는 늦은 마감(late-box-close)을 집계 범위가 실린 뒤에야 실었다.",
                "투표함 단계는 늦은 마감으로 수동 마감을 풀지만, 집계 범위가 이미 그 투표양식을 고정한 뒤라 집계 단계가 그 늦은 마감을 거부한다: HOLD_REVIEW(LateCloseAfterScope).",
            ),
            hold(&[H::LateCloseAfterScope]),
            Vec::new(),
        ));
    }
    // A manual close.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let close_at = bld.plan.marks.closes[hb].unwrap();
        let n = e.casts[hb].len() as u64;
        let codes: Vec<_> = e.casts[hb].iter().map(|c| c.code).collect();
        bld.plan.steps[close_at] = Step::event(
            SCHEMA_BOX_CLOSE,
            e.close(hb, e.close_counts(hb, n, n), &codes, None, None),
        );
        out.push(bld.scenario(
            "fault-manual-close",
            q,
            a,
            (
                "장치 서명 없는 수동 마감",
                "한빛초등학교 체육관 투표함을 사람 서명만으로 마감했다(장치가 마감에 서명하지 못함).",
                "그 투표함이 HOLD_REVIEW(ManualClose). 같은 사람 수를 적은 늦은 마감이 와야 풀린다.",
            ),
            hold(&[H::ManualClose]),
            Vec::new(),
        ));
    }
    // A repeated pseudonym.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let s = e.station_index("ST-HB-1");
        let at = bld.plan.marks.participation[s].unwrap();
        bld.plan.steps[at] = Step::event(SCHEMA_PARTICIPATION_SET, e.participation(s, Some(0)));
        out.push(bld.scenario(
            "attack-duplicate-pseudonym",
            q,
            a,
            (
                "같은 가명 두 번",
                "한빛초등학교 체육관의 참여 집합에 같은 가명이 두 번 들어 있다(한 사람이 두 번 확인된 것처럼).",
                "장부 전체가 HOLD_REVIEW(DuplicatePseudonym). 중복 가명 조사를 연다.",
            ),
            hold(&[H::DuplicatePseudonym]),
            Vec::new(),
        ));
    }
    // An open dispute.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let close_at = bld.plan.marks.closes[hb].unwrap();
        let _ = withheld(e, hb);
        let bucket = e.days[e.boxes[hb].station].close_bucket + 2;
        let (filing, event) = e.filing(hb, DisputeType::CountMismatch, None, bucket);
        insert_after(
            &mut bld.plan.steps,
            close_at,
            Step::Event {
                schema: SCHEMA_WITNESSED_EVENT,
                event,
                published: None,
                filed: Some(filing),
            },
        );
        out.push(bld.scenario(
            "fault-open-dispute",
            q,
            a,
            (
                "미해결 분쟁",
                "참관인이 한빛초등학교 체육관 투표함의 마감 수량에 이의를 제기했고, 두 기관이 COUNT_MISMATCH 분쟁으로 접수했다. 아직 해결되지 않았다.",
                "미해결 분쟁이 있으면 장부 전체가 HOLD_REVIEW(OpenDispute). 분쟁 목록에 그 접수가 보인다.",
            ),
            hold(&[H::OpenDispute]),
            Vec::new(),
        ));
    }
    // Seals that did not match at opening.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld
            .plan
            .steps
            .iter()
            .position(|s| s.event_bytes().is_some_and(|ev| ev == e.opened(hb, true)))
            .unwrap();
        bld.plan.steps[at] = Step::event(SCHEMA_WITNESSED_EVENT, e.opened(hb, false));
        out.push(bld.scenario(
            "fault-seal-mismatch",
            q,
            a,
            (
                "개시 때 봉인 번호 불일치",
                "한빛초등학교 체육관 투표함을 열 때 사무원과 참관인이 봉인 번호가 맞지 않는다고 기록했다.",
                "그 투표함이 HOLD_REVIEW(SealMismatch).",
            ),
            hold(&[H::SealMismatch]),
            Vec::new(),
        ));
    }
    // The board published late.
    {
        let bld = Builder::new(e, Until::Tallied);
        let mut s = bld.scenario(
            "fault-board-late",
            q,
            a,
            (
                "공개원장 공표 지연",
                "깨끗한 선거와 같은 장부. 다만 공개원장이 투표 마감 뒤 96구간(24시간)의 기한을 넘겨 공표되었다.",
                "HOLD_REVIEW(PublicationLate). 검증기는 시계가 없으므로 기한 판정은 호출자가 준 시각으로 한다.",
            ),
            hold(&[H::PublicationLate]),
            Vec::new(),
        );
        s.publications.published = Some(s.publications.close + 200);
        s.publications.now = s.publications.close + 210;
        out.push(s);
    }
    // No legal authorization on the ledger.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = bld.plan.marks.authorization;
        bld.plan.steps.remove(at);
        out.push(bld.scenario(
            "attack-no-authorization",
            q,
            a,
            (
                "법적 승인이 없는 장부",
                "genesis가 고정한 법적 승인 객체(SignedLegalAuthorization)를 장부에 싣지 않았다.",
                "권한이 필요한 어떤 단계도 받을 수 없어 장부 전체가 HOLD_REVIEW(AuthorizationMissing), 그 위의 이벤트도 줄줄이 거부된다.",
            ),
            hold(&[
                H::AuthorizationMissing,
                H::BoxEventRefused,
                H::ProgressStream,
                H::ReceiptResolutionRefused,
                H::TallyScopeRefused,
                H::AggregateRefused,
            ]),
            Vec::new(),
        ));
    }
    // A device reporting an impossible count (u64::MAX sheets in).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let open = e.days[e.boxes[out_box].station].open_slot;
        for step in &mut bld.plan.steps {
            let Step::Event { schema, event, .. } = step else {
                continue;
            };
            if *schema != SCHEMA_PROGRESS_TICK {
                continue;
            }
            let tick: ProgressTick<'_> =
                decode_object(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, event).unwrap();
            if let ProgressBody::Box(b) = tick.body() {
                let p = *b.parts();
                if p.box_id.as_bytes() == e.boxes[out_box].id.as_bytes() && p.slot >= open + 3 {
                    *event = e.box_tick(out_box, p.slot, u64::MAX, p.state);
                }
            }
        }
        out.push(bld.scenario(
            "attack-overflow-progress",
            q,
            a,
            (
                "불가능한 진행 누계",
                "누리구 사전투표소 관외 투표함의 장치가 06:30부터 투입 누계를 2^64 − 1장으로 서명했다(같은 투표소의 다른 투표함과 더하면 64비트를 넘는 값).",
                "검증기는 진행 기록 흐름의 규칙 위반(ProgressStream)과 해소되지 않은 경보(ProgressUnresolved)로 그 투표소를 HOLD_REVIEW로 둔다. 콘솔은 넘치는 합을 계산하지 않고 '넘침'으로 보인다.",
            ),
            hold(&[H::ProgressStream, H::ProgressUnresolved]),
            Vec::new(),
        ));
    }
    timestamp_and_roll_scenarios(e, &mut out);
    connectivity_scenarios(e, &mut out);
    audit_scenarios(&mut out, &slips);
    out
}

/// The step after the roll's last event (its last custody receipt).
fn after_roll(e: &Election, steps: &[Step]) -> usize {
    let last = *e.roll().last().unwrap();
    steps
        .iter()
        .position(|s| s.event_bytes() == Some(last))
        .unwrap()
}

/// Scenarios of the timestamp tokens (ADR-0039) and the roll's custody
/// (ADR-0040), quick set.
fn timestamp_and_roll_scenarios(e: &'static Election, out: &mut Vec<Scenario>) {
    use HoldReason as H;
    let q = Set::Quick;
    let a = Group::Attack;
    let gov = crate::tsa::GOV;
    let free = crate::tsa::FREE;
    // A token earlier than the last checkpoint's witnesses' time.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let bucket = last_checkpoint_bucket(&bld.plan.steps);
        bld.plan.steps.push(Step::Stamp {
            named: free,
            by: free,
            bucket: bucket - 2,
        });
        out.push(bld.scenario(
            "attack-checkpoint-backdated",
            q,
            a,
            (
                "시점확인 토큰이 드러낸 체크포인트 시각",
                "마지막 체크포인트에 정부 밖 시점확인 기관의 토큰이 하나 더 실렸다. 토큰은 그 체크포인트가 증인들이 적은 구간보다 두 구간(30분) 앞서 이미 있었다고 말한다. 증인 정족수가 시각을 늦춰 적었거나 기관이 시각을 속였다.",
                "유효한 토큰의 가장 늦은 순간이 체크포인트 구간보다 허용(1구간)을 넘게 앞서므로 사슬이 그 체크포인트에서 끝나고(VC-116) 체크포인트 단계가 실패한다: HOLD_REVIEW(TimestampMismatch, StepFailed). 그 체크포인트가 덮던 프레임은 앞 체크포인트까지만 확인된다.",
            ),
            hold(&[H::TimestampMismatch, H::StepFailed]),
            Vec::new(),
        ));
    }
    // The last checkpoint never stamped, and its window passed.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        if let Some(Step::Checkpoint { stamps, .. }) = bld
            .plan
            .steps
            .iter_mut()
            .rev()
            .find(|step| matches!(step, Step::Checkpoint { .. }))
        {
            *stamps = 0;
        }
        let mut s = bld.scenario(
            "fault-anchor-missed",
            q,
            a,
            (
                "앵커 기한을 넘긴 마지막 체크포인트",
                "깨끗한 선거와 같은 장부. 다만 마지막 체크포인트에 시점확인 토큰이 하나도 실리지 않았고, 호출자의 지금 시각은 그 앵커 창(체크포인트 구간 + 4)을 넘었다.",
                "UNVERIFIED. 앵커 기한 위반은 보류가 아니라 미검증이다(FAILURE_CASES §8): 장부가 그 시각에 있었다는 외부 증거가 없으므로 어떤 단계가 통과해도 사다리를 오르지 않는다. 늦게라도 두 기관의 토큰이 실리고 그 위의 체크포인트가 앵커되면 풀린다.",
            ),
            expected(Status::Unverified, &[]),
            Vec::new(),
        );
        s.publications.now = s.publications.checkpoint + 5;
        out.push(s);
    }
    // A pinned authority's name over another authority's token.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let bucket = last_checkpoint_bucket(&bld.plan.steps);
        bld.plan.steps.push(Step::Stamp {
            named: gov,
            by: crate::tsa::ROGUE,
            bucket,
        });
        out.push(bld.scenario(
            "attack-tsa-unpinned",
            q,
            a,
            (
                "고정되지 않은 기관의 토큰",
                "genesis가 고정하지 않은 기관의 토큰을, 정부 운영 시점확인 기관의 이름을 붙여 마지막 체크포인트에 실었다. 토큰 자체는 형식이 맞고 서명도 맞다.",
                "그 기관의 어느 핀으로도 토큰이 검증되지 않으므로 기록을 받지 않고 장부가 HOLD_REVIEW(TimestampInvalid). 체크포인트 자체는 두 기관의 정상 토큰으로 앵커되어 있다.",
            ),
            hold(&[H::TimestampInvalid]),
            Vec::new(),
        ));
    }
    // An extract after the freeze.
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let at = after_roll(e, &bld.plan.steps);
        insert_after(
            &mut bld.plan.steps,
            at,
            Step::event(SCHEMA_WITNESSED_EVENT, e.roll_late_extract()),
        );
        out.push(bld.scenario(
            "attack-roll-extract-after-freeze",
            q,
            a,
            (
                "동결 뒤에 바꾼 명부 추출",
                "선거인명부가 동결되고 보관 기관 셋이 영수증을 낸 뒤, 구청장이 한빛초등학교 투표구의 주민등록 추출을 다른 내용으로 하나 더 서명해 실었다.",
                "동결 뒤에는 추출을 받지 않는다. 명부를 바꾸는 길은 출처 서명과 보관 기관 정족수의 새 영수증이 있는 변경뿐이다(VC-111). 그 추출은 거부되고 HOLD_REVIEW(RollEventRefused).",
            ),
            hold(&[H::RollEventRefused]),
            Vec::new(),
        ));
    }
    // An amendment with its receipts.
    for (name, custodians, text, expected_outcome) in [
        (
            "quick-roll-amended",
            &["R-C-JUD", "R-C-INT", "R-C-IVC"][..],
            (
                "빠른 시연: 동결 뒤의 명부 변경",
                "깨끗한 선거와 같은 장부에, 명부 동결 뒤 이의신청 결정으로 선거인 한 명을 더한 변경 1이 실렸다. 선관위·위원회·구청장(사유의 출처)이 서명했고, 보관 기관 셋(법원행정처, 행정안전부, 독립검증위원회)이 같은 새 명부 값에 영수증을 냈다.",
                "CRYPTO_TALLY_VERIFIED. 보류 없음. 변경은 보관 정족수(3)와 두 부처를 갖추어 효력이 있다(VC-108, VC-111).",
            ),
            expected(Status::CryptoTallyVerified, &[]),
        ),
        (
            "fault-roll-amendment-short",
            &["R-C-JUD", "R-C-INT"][..],
            (
                "보관 정족수에 못 미친 명부 변경",
                "명부 동결 뒤 이의신청 결정으로 선거인 한 명을 더한 변경 1이 실렸지만, 보관 기관 둘(법원행정처, 행정안전부)만 영수증을 냈다. genesis의 보관 정족수는 셋이다.",
                "변경이 효력을 얻지 못해 참여 장부 단계(14절 6단계)가 끝나지 않는다. 보류는 아니다(영수증이 더 실리면 풀린다). 집계는 확인되었어도 SOURCE_COMPLETENESS_CHECKED에 머문다.",
            ),
            expected(Status::SourceCompletenessChecked, &[]),
        ),
    ] {
        let mut bld = Builder::new(e, Until::Tallied);
        let first = after_roll(e, &bld.plan.steps);
        for (at, event) in (first..).zip(e.roll_amendment(custodians)) {
            insert_after(
                &mut bld.plan.steps,
                at,
                Step::event(SCHEMA_WITNESSED_EVENT, event),
            );
        }
        let group = if name.starts_with("quick") {
            Group::Normal
        } else {
            a
        };
        out.push(bld.scenario(name, q, group, text, expected_outcome, Vec::new()));
    }
}

fn full_scenarios() -> Vec<Scenario> {
    let f = Set::Full;
    let mut out = Vec::new();
    let local = local_election();
    let hb1 = local.box_index("HB-1-B");
    let out_box = local.box_index("HB-P-OUT");
    let slips = vec![
        included(
            &cast_of(local, hb1, 1),
            "체크포인트에 포함된 코드 (한빛초등학교 체육관)",
        ),
        included(
            &cast_of(local, out_box, 3),
            "체크포인트에 포함된 코드 (관외 투표함)",
        ),
        withheld(local, hb1),
    ];
    out.push(Builder::new(local, Until::Tallied).scenario(
        "local-clean",
        f,
        Group::Normal,
        (
            "가상시 동시지방선거 시연",
            "세 구·군, 투표소 여덟(사전투표소 둘과 관외 투표함), 06:00–18:00 진행 기록. 바닥·음수·과다 경보가 한 번씩 나고 모두 현장 확인으로 해소되며, 한 투표소는 한 시간 동안 비상 투입구를 썼다. 유권자마다 투표지 한 장(현재 genesis의 한계).",
            "CRYPTO_TALLY_VERIFIED. 보류 없음. 경보는 확인이 필요하다는 뜻이었고 확인으로 해소되었다.",
        ),
        expected(Status::CryptoTallyVerified, &[]),
        slips.clone(),
    ));
    let st = local.station_index("HB-1");
    let slot = local.days[st].open_slot + 48;
    out.push(Builder::new(local, Until::Voting(slot)).scenario(
        "local-voting",
        f,
        Group::Normal,
        (
            "가상시 동시지방선거 시연: 선거일 14:00",
            "사전투표는 마감했고 선거일 투표가 14:00까지 진행되었다. 그때까지의 프레임을 체크포인트가 덮는다.",
            "LOG_CONSISTENT. 집계가 끝났다는 뜻이 아니다.",
        ),
        expected(Status::LogConsistent, &[]),
        slips,
    ));
    let national = national_election();
    let g1 = national.box_index("GAP-1-B");
    out.push(Builder::new(national, Until::Tallied).scenario(
        "national-clean",
        f,
        Group::Normal,
        (
            "가상시 국회의원선거 시연",
            "두 지역구, 투표소 다섯(사전투표소 하나와 관외 투표함), 06:00–18:00 진행 기록, 과다·바닥 경보와 현장 확인. 비례대표 투표지는 현재 genesis의 한계로 뺐다.",
            "CRYPTO_TALLY_VERIFIED. 보류 없음.",
        ),
        expected(Status::CryptoTallyVerified, &[]),
        vec![
            included(&cast_of(national, g1, 1), "체크포인트에 포함된 코드 (새솔초등학교 체육관)"),
            withheld(national, g1),
        ],
    ));
    out
}

/// The quick election whose connectivity manifest gives the scanner's frame
/// link a receiving direction too (VC-077).
fn quick_two_way_election() -> &'static Election {
    static E: OnceLock<&'static Election> = OnceLock::new();
    E.get_or_init(|| {
        let mut spec = catalog::quick(Vec::new());
        spec.two_way_uplink = true;
        leak(Election::build(spec))
    })
}

/// Adds `fault` to station `s`'s `k`-th gateway session (`None`: the last).
fn uplink_fault(bld: &mut Builder, s: usize, k: Option<usize>, fault: Fault) {
    let marks = &bld.plan.marks.uplink[s];
    let at = match k {
        Some(k) => marks[k],
        None => *marks.last().unwrap(),
    };
    if let Step::Uplink(w) = &mut bld.plan.steps[at] {
        w.faults.push(fault);
    }
}

/// Puts `step` just before the last checkpoint.
fn before_last_checkpoint(steps: &mut Vec<Step>, step: Step) {
    let at = steps
        .iter()
        .rposition(|s| matches!(s, Step::Checkpoint { .. }))
        .unwrap();
    steps.insert(at, step);
}

/// Scenarios of the connectivity audit (ADR-0022, ADR-0041), quick set.
#[allow(clippy::too_many_lines)] // One scenario after another.
fn connectivity_scenarios(e: &'static Election, out: &mut Vec<Scenario>) {
    use HoldReason as H;
    let q = Set::Quick;
    let a = Group::Attack;
    let hb = e.box_index("BOX-HB-1");
    let st = e.station_index("ST-HB-1");
    let nr = e.station_index("ST-NR-P");
    let scanner = Device::Box(hb);
    let open = e.days[st].open_slot;

    // A two-way scanner port in the manifest (VC-077).
    out.push(Builder::new(quick_two_way_election(), Until::Tallied).scenario(
        "attack-manifest-two-way",
        q,
        a,
        (
            "받기도 하는 스캐너 포트",
            "genesis가 고정한 연결 목록이 커밋먼트 유닛의 업링크 포트를 양방향으로 적었다. 목록 형식은 맞고 genesis도 서명됐으며, 장부의 프레임과 세션은 깨끗한 선거와 같다.",
            "TCB 장치에 들어오는 경로를 선언한 것은 그 종류의 모든 장치에 걸리므로 장부 전체가 HOLD_REVIEW(ConnectivityManifest). 연결 단계가 목록의 어긴 규칙(TcbInbound, TwoWay, FrameLinkShape)을 보인다.",
        ),
        hold(&[H::ConnectivityManifest]),
        Vec::new(),
    ));
    // A frame the gateway hid without declaring it (VC-080).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Hide {
                device: scanner,
                slot: open + 1,
            },
        );
        out.push(bld.scenario(
            "attack-uplink-hidden-frame",
            q,
            a,
            (
                "게이트웨이가 숨긴 프레임",
                "한빛초등학교 체육관 게이트웨이가 첫 세션에서 스캐너의 둘째 슬롯 첫 프레임을 기록과 사슬에서 빼고, 그 슬롯을 빠진 슬롯으로 적지 않았다.",
                "세션이 적은 빠진 슬롯 수가 기록에서 다시 센 값과 달라 그 투표소의 모든 투표함이 HOLD_REVIEW(UplinkSessionRefused). 숨긴 프레임 자체는 참관인 캡처 대조(compare_capture)가 찾는다.",
            ),
            hold(&[H::UplinkSessionRefused]),
            Vec::new(),
        ));
    }
    // A frame the gateway signed in place of the device's (VC-078).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Inject {
                device: scanner,
                slot: open + 2,
            },
        );
        out.push(bld.scenario(
            "attack-uplink-injected-frame",
            q,
            a,
            (
                "게이트웨이가 끼워 넣은 프레임",
                "한빛초등학교 체육관 스캐너의 셋째 슬롯 마지막 프레임 자리에 게이트웨이가 자기 키로 서명한 프레임을 넣었다. 사슬과 세션은 그 프레임을 덮는다.",
                "프레임 서명이 그 장치의 프레임 키로 맞지 않아 그 투표함이 HOLD_REVIEW(UplinkFrameInvalid).",
            ),
            hold(&[H::UplinkFrameInvalid]),
            Vec::new(),
        ));
    }
    // A nonzero byte after the data (the padding proof, VC-078).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Fill {
                device: scanner,
                slot: open + 3,
            },
        );
        out.push(bld.scenario(
            "fault-uplink-padding",
            q,
            a,
            (
                "0이 아닌 채움",
                "한빛초등학교 체육관 스캐너가 넷째 슬롯 마지막 프레임의 데이터 뒤 채움에 0이 아닌 바이트를 넣고 그대로 서명했다. 프레임이 말한 것보다 많이 실은 모양이다.",
                "공표한 데이터 잎과 0 잎으로 다시 만든 탑재부 루트가 서명된 루트와 달라(채움 증명 실패) 그 투표함이 HOLD_REVIEW(UplinkFrameInvalid).",
            ),
            hold(&[H::UplinkFrameInvalid]),
            Vec::new(),
        ));
    }
    // One frame more in a slot than the manifest allows (VC-078).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Extra {
                device: scanner,
                slot: open + 2,
            },
        );
        out.push(bld.scenario(
            "fault-uplink-extra-frame",
            q,
            a,
            (
                "슬롯당 수를 넘은 프레임",
                "한빛초등학교 체육관 스캐너가 셋째 슬롯에 일반 프레임을 연결 목록의 16개보다 하나 더(번호 16) 보냈다.",
                "번호가 슬롯당 수를 넘어 그 투표함이 HOLD_REVIEW(UplinkFrameInvalid).",
            ),
            hold(&[H::UplinkFrameInvalid]),
            Vec::new(),
        ));
    }
    // Normal frames after the close (VC-078).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(&mut bld, st, None, Fault::AfterClose { device: scanner });
        out.push(bld.scenario(
            "fault-uplink-after-close",
            q,
            a,
            (
                "마감 뒤에도 보낸 스캐너",
                "한빛초등학교 체육관 스캐너가 마감 구간 다음 슬롯이 지난 뒤에도 한 슬롯 동안 일반 프레임 16개를 더 보냈다.",
                "마감 뒤의 일반 프레임이라 그 투표함이 HOLD_REVIEW(UplinkFrameInvalid).",
            ),
            hold(&[H::UplinkFrameInvalid]),
            Vec::new(),
        ));
    }
    // Records of a batch out of record-hash order (VC-079).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(&mut bld, st, None, Fault::Unordered { device: scanner });
        out.push(bld.scenario(
            "attack-uplink-batch-order",
            q,
            a,
            (
                "배치 순서를 어긴 기록",
                "한빛초등학교 체육관 스캐너가 마감 배치의 기록을 기록 해시 내림차순으로 보냈다. 보내는 순서가 투입 순서를 드러낼 수 있는 모양이다.",
                "배치 안의 기록이 해시 오름차순이 아니라 그 투표함이 HOLD_REVIEW(UplinkObjectInvalid).",
            ),
            hold(&[H::UplinkObjectInvalid]),
            Vec::new(),
        ));
    }
    // A frame lost on the line, declared (VC-080).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Lose {
                device: scanner,
                slot: open + 5,
                index: 0,
            },
        );
        out.push(bld.scenario(
            "fault-uplink-lost-frame",
            q,
            a,
            (
                "잃어버린 프레임",
                "한빛초등학교 체육관 스캐너의 첫 세션 마지막 슬롯 첫 프레임이 회선에서 사라졌다. 게이트웨이는 그 슬롯을 빠진 슬롯으로 정직하게 적었지만, 그 프레임이 나르던 진행 기록은 다시 오지 않았다(진행 기록은 자기 슬롯에 한 번만 보낸다).",
                "세션은 받는다. 그러나 장부의 그 진행 기록들이 장치의 받은 프레임 어디에도 없어 그 투표함이 HOLD_REVIEW(UplinkObjectOutside).",
            ),
            hold(&[H::UplinkObjectOutside]),
            Vec::new(),
        ));
    }
    // A frame of the closing batch lost, declared, and brought again by the
    // close resend (honest line loss, VC-078–080).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let close = e.link_slots(scanner).1;
        uplink_fault(
            &mut bld,
            st,
            None,
            Fault::Lose {
                device: scanner,
                slot: close,
                index: 1,
            },
        );
        out.push(bld.scenario(
            "fault-uplink-recovered-loss",
            q,
            a,
            (
                "되찾은 프레임",
                "한빛초등학교 체육관 스캐너의 마감 슬롯에서 마감 배치(배치 증명, 기록, 봉인 share 패키지)를 실은 프레임이 회선에서 사라졌다. 게이트웨이는 그 슬롯을 빠진 슬롯으로 정직하게 적었고, 같은 슬롯의 마감 재전송이 그 배치를 다시 실어 왔다.",
                "CRYPTO_TALLY_VERIFIED. 보류 없음. 흐름은 잃은 프레임만큼 건너뛰고(그 자리의 번호는 받지 못했다), 잃은 범위 뒤의 기록은 증명을 잃은 배치의 꼬리로 읽히며, 모든 기록이 재전송의 받은 프레임 안에 있고 그 덩어리가 장부의 객체로 다시 계산된다.",
            ),
            expected(Status::CryptoTallyVerified, &[]),
            Vec::new(),
        ));
    }
    // Bytes that are no object, next to a silent slot (ADR-0041 decision 3).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Covert {
                device: scanner,
                slot: open + 3,
            },
        );
        out.push(bld.scenario(
            "attack-uplink-covert-bytes",
            q,
            a,
            (
                "건너뛴 슬롯 옆의 숨은 바이트",
                "한빛초등학교 체육관 스캐너가 넷째 슬롯 첫 프레임에 어느 객체도 아닌 3,000바이트를 싣고 객체 목록에는 아무것도 적지 않은 채 서명했다. 다음 슬롯에는 아무것도 보내지 않고, 그다음 슬롯은 그 바이트보다 한 바이트 뒤에서 이어 갔다. 게이트웨이는 빈 슬롯을 빠진 슬롯으로 정직하게 적었다.",
                "프레임의 서명된 목록이 데이터를 덮지 않아 그 투표함이 HOLD_REVIEW(UplinkObjectInvalid). 건너뛴 한 바이트는 받지 못한 자리를 넘지 않으므로 위반이 아니다.",
            ),
            hold(&[H::UplinkObjectInvalid]),
            Vec::new(),
        ));
    }
    // The gateway's own list for a frame the device signed (VC-078, VC-080).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        uplink_fault(
            &mut bld,
            st,
            Some(0),
            Fault::Relist {
                device: scanner,
                slot: open + 5,
            },
        );
        out.push(bld.scenario(
            "attack-uplink-relisted-object",
            q,
            a,
            (
                "게이트웨이가 바꿔 적은 객체",
                "한빛초등학교 체육관 게이트웨이가 첫 세션 마지막 슬롯의 데이터 프레임을 기록하면서 장치가 적은 객체 목록의 첫 객체를 다른 해시로 바꿔 적고, 그 머리로 사슬을 이었다.",
                "장치의 서명은 장치가 적은 목록의 해시를 덮으므로 그 프레임은 서명이 맞지 않아 받은 프레임이 아니다. 그 투표함이 HOLD_REVIEW(UplinkFrameInvalid), 그 프레임이 나르던 진행 기록이 받은 프레임 어디에도 없어 UplinkObjectOutside.",
            ),
            hold(&[H::UplinkFrameInvalid, H::UplinkObjectOutside]),
            Vec::new(),
        ));
    }
    // A record that reached the ledger without travelling the link (VC-080).
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let record = cast_of(e, hb, 3);
        uplink_fault(
            &mut bld,
            st,
            None,
            Fault::Withhold {
                event: ityv_crypto::object_hash(record.event),
            },
        );
        out.push(bld.scenario(
            "attack-hidden-path-record",
            q,
            a,
            (
                "링크를 거치지 않은 기록",
                "한빛초등학교 체육관 투표함의 세 번째 기록은 장부에 있지만 스캐너의 업링크로 오지 않았다(숨은 경로). 배치 증명은 그 기록을 그대로 센다.",
                "장치 출처 객체가 어느 세션의 받은 프레임에도 없어 그 투표함이 HOLD_REVIEW(UplinkObjectOutside, VC-080).",
            ),
            hold(&[H::UplinkObjectOutside]),
            Vec::new(),
        ));
    }
    // Incidents (VC-083).
    let committee_and_observers = |s: usize| {
        let mut who = vec![e.committee_person()];
        who.extend(
            e.people(s)
                .into_iter()
                .filter(|p| p.role == ityv_encoding::EventRole::Observer),
        );
        who
    };
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let (_, last) = e.link_slots(Device::Unit(nr));
        let event = e.connectivity_incident(
            Some(nr),
            None,
            IncidentKind::RollLineOutsideWindow,
            (last + 1, last + 6),
            false,
            &committee_and_observers(nr),
        );
        before_last_checkpoint(
            &mut bld.plan.steps,
            Step::event(SCHEMA_WITNESSED_EVENT, event),
        );
        out.push(bld.scenario(
            "fault-roll-line-incident",
            q,
            a,
            (
                "투표 시간 밖의 명부 회선",
                "통신사 기록(compare_carrier)에서 누리구 사전투표소의 명부 전용회선에 마감 뒤의 통신이 나왔다. 위원회와 그 투표소의 두 참관인이 연결 사건(RollLineOutsideWindow)을 서명해 실었다.",
                "그 투표소 모든 투표함의 전자 층이 HOLD_REVIEW(ConnectivityIncident). 종이 결과는 그대로다.",
            ),
            hold(&[H::ConnectivityIncident]),
            Vec::new(),
        ));
    }
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let event = e.connectivity_incident(
            Some(st),
            Some(hb),
            IncidentKind::CaptureMismatch,
            (open, open + 5),
            true,
            &e.people(st),
        );
        before_last_checkpoint(
            &mut bld.plan.steps,
            Step::event(SCHEMA_WITNESSED_EVENT, event),
        );
        out.push(bld.scenario(
            "fault-capture-mismatch",
            q,
            a,
            (
                "참관인 캡처와 다른 프레임",
                "한빛초등학교 체육관 참관인의 탭 캡처가 게이트웨이가 공표한 첫 시간의 프레임과 달랐다(compare_capture). 사무원 둘과 참관인 둘이 커밋먼트 유닛이 걸린 연결 사건(CaptureMismatch)을 서명해 실었다.",
                "그 투표함의 전자 층이 HOLD_REVIEW(ConnectivityIncident). 보고는 그 투표함을 종이와 전수 대조할 대상으로 적는다(아직 대조하지 않음).",
            ),
            hold(&[H::ConnectivityIncident]),
            Vec::new(),
        ));
    }
    {
        let mut bld = Builder::new(e, Until::Tallied);
        let mut who = e.people(st);
        let other = who
            .iter()
            .filter(|p| p.role == ityv_encoding::EventRole::Observer)
            .nth(1)
            .unwrap()
            .key
            .clone();
        if let Some(p) = who
            .iter_mut()
            .find(|p| p.role == ityv_encoding::EventRole::Observer)
        {
            p.key = other;
        }
        let event = e.connectivity_incident(
            Some(st),
            Some(hb),
            IncidentKind::CaptureMismatch,
            (open, open + 5),
            true,
            &who,
        );
        before_last_checkpoint(
            &mut bld.plan.steps,
            Step::event(SCHEMA_WITNESSED_EVENT, event),
        );
        out.push(bld.scenario(
            "attack-incident-forged",
            q,
            a,
            (
                "서명이 맞지 않는 연결 사건",
                "한빛초등학교 체육관 투표함에 대한 연결 사건에 한 참관인의 서명을 다른 참관인의 키로 만들어 붙였다.",
                "사건은 받지 않는다. 누가 무엇을 주장했는지 확인할 수 없으므로 장부 전체가 HOLD_REVIEW(ConnectivityIncidentRefused).",
            ),
            hold(&[H::ConnectivityIncidentRefused]),
            Vec::new(),
        ));
    }
}
