# ityv-verify

> English summary: The ityv public verifier (ADR-0029, PROTOCOL §14). `no_std` with `alloc`, `unsafe`-free, panic-free Rust with no clock, no I/O and no unordered collections. Stage 1, `verify_genesis`, checks a genesis whole against a pin the caller obtained out of band: signatures verified here into tokens and sealed through `ityv-state`, every entry of every set re-decoded, re-sorted, re-counted and re-rooted, the sets checked against each other (references, station box lists, policies, reporting-unit counts, appointments and no appointment shared, module chambers and one device per module, trustee counts, observer tokens against roster, station and check key, distinct device identifiers, valid keys, no key half shared within a genesis state), and every amendment's state checked the same way. Stage 3, `build_index`, reads the frame stream against the verified genesis: frame chain, events by hash, canonical decoding, frames of restricted events by hash alone, the event's election, who each event concerns (against every genesis state), that a genesis, amendment or legal authorization on the ledger is the pinned one, replayed events (VC-101) and records (cast records, challenge openings) after a box's close (VC-039; a later batch attestation is a late batch close); a refused frame becomes a finding and a hold on its box, its station's boxes or the whole ledger. Stage 2, `verify_checkpoints`, checks each witness checkpoint (quorum and diversity from the genesis witness set, successor rules, covering only earlier frames, and the tree root, box-close root and open-dispute root recomputed from the ledger) and ends the chain at the first one that breaks a rule; `verify_timestamps` (ADR-0039) verifies every `TimestampRecord`'s RFC 3161 token through `ityv-tsa` under the pins of the genesis's timestamp authorities, a token that backdates a checkpoint beyond the clock tolerance ends the chain, and each checkpoint's anchoring counts authority kinds and operators within the anchor window; the ledger's anchor deadline is decided from the last checkpoint's tokens. `authorize_ledger` verifies the legal authorization the ledger carries (`SignedLegalAuthorization`, schema `0x0042`) under the genesis keys; without it the whole ledger is held. Stage 4, `verify_boxes`, drives `ityv-state`'s ballot-box machine for every expected box with the box's events, every signature verified here under the key the genesis registers, and reports each box's phase, holds and refused events; a box without a close is held (completeness). The box stage follows genesis amendments: each event is checked under the keys and roster of the state in force at its frame, and a device replaced while the box is open needs a `BoxUnitSwap` witnessed on site. Stage 5, `verify_records`, checks every cast record's ballot style, OR proof and device and module record signatures, every batch attestation (signatures, unique index, per-module counter ranges, member count, records root), lists unattested records, checks the close's record set root, and reconstructs every challenge opening from its published values (VC-028). `verify_progress` runs each station's voting progress record (device streams in slot order, swaps, alarms suspended only by accepted fallback and swap events, on-site checks, close comparisons). Stage 6, `verify_participation`, checks party key ceremonies, pinned module provisioning records, participation sets and the station identities; `verify_roll` (ADR-0040) checks the voter roll's source extracts, the freeze as their merge, the custodians' receipts against the genesis's custody quorum with the court administration and the Ministry of the Interior, the amendments' sources and chain, and, for a caller with access, the restricted contested check-ins. Stage 7, `verify_tally`, recomputes every ballot style and reporting unit's tally scope from the record states, receipt resolutions and legal tally effects, compares the trustees' scope with it, checks each aggregate opening against the real sum of the included records' commitments after a checkpoint covers its scope, and compares the opened counts with the paper count the unit's commission chair signed. Stage 8, `verify_audit`, runs each ballot style's comparison audit: the freeze against the recomputed frame, the commit that fixes the dice record, the beacon and the freezes, the seed recomputed against the binding checkpoint (the first valid checkpoint covering the commit) and the beacon output the caller observed, both timed before the beacon's publication, the sample redrawn, opening references only for the records the audit calls for, restricted openings a caller with access supplies reconstructed against the commitments, comparisons and their follow-ups (escalation, full comparison and findings, custody holds), and the units' hand counts. Stage 9, `verify_disputes`, lists every dispute with its status and shows each legal decision a registered authority signed beside the dispute it names. `verify_ledger` runs every stage over one ledger and maps the outcomes to one status (`UNVERIFIED`, `LOG_CONSISTENT`, `SOURCE_COMPLETENESS_CHECKED`, `CRYPTO_TALLY_VERIFIED`, `PAPER_AUDITED`, `HOLD_REVIEW`) through `ityv_state::status::evaluate`; the caller supplies its current time bucket and the board deadline, through `verify_ledger_with` the observed beacon value and any restricted openings, and through `verify_ledger_full` any restricted contested check-ins. Verification: V1 (integration tests with real hybrid signatures, one per rule; cargo-mutants), V2 (Kani harnesses).

## 무엇인가

공개 검증기의 TCB 크레이트다. 호출자가 대역 외로 받은 genesis 핀만 믿고, 나머지는 모두 공표된 데이터에서 다시 계산한다. 명세는 `docs/spec/PROTOCOL.md` §4, §5.1, §7, §12, §14와 `docs/adr/ADR-0029-verifier-crate.md`부터 `docs/adr/ADR-0036-audit-stage.md`까지이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 단계 | 명세 |
|---|---|---|
| `genesis` | 1. 핀, 서명, 모든 항목 집합 전체, 집합 사이 일치, 변경 | §4, §14 1항, ADR-0028, VC-005, VC-009, VC-014, VC-067, VC-104, VC-105 |
| `checkpoint` | 2. 체크포인트 사슬: 증인 정족수·다양성, 후속 규칙, 장부에서 다시 계산한 세 root, 시점확인 토큰의 역산 금지, 체크포인트마다의 앵커와 장부의 앵커 기한 | §5.3–§5.5, §14 2항, VC-011..014, VC-115, VC-116 |
| `timestamp` | 시점확인: genesis 기관 규칙, 모든 `TimestampRecord`의 토큰을 기관의 핀으로 대상 이벤트에 대해 검증(`ityv-tsa`), 가장 늦은 순간과 구간 비교, 기관·운영 주체 단위 계수 | §5.5, ADR-0034, ADR-0037, ADR-0039, VC-114..118 |
| `index` | 3. 프레임 고리, 이벤트 해시, 정규 이벤트, 재수록, 마감 뒤 기록 | §5.1, §14 3항, VC-010, VC-039, VC-101 |
| `authority` | 장부의 법적 승인(`SignedLegalAuthorization`)과 두 기관 서명 | §4.4, VC-006..008 |
| `boxes` | 4. 예상 투표함마다 상태 기계, genesis 변경을 따라감: 개시, 기록, 대체 상태, 장치 교체, 마감과 늦은 마감, 늦은 배치 마감, 보관 사슬, 완전성 | §4.3, §7, §10, §14 4항, VC-037..040, VC-100, VC-105, VC-106 |
| `records` | 5. 투함 기록: 투표양식, OR 증명, 기록 서명, 배치, 카운터 연속성, 기록 집합 root, `UNATTESTED`, 검증 공개 재구성 | §7.2.1, §7.5, §7.6, §8, §14 5항, VC-025..028, VC-053, VC-057 |
| `progress` | 투표 진행 기록: 장치 흐름(슬롯 순서), 장치 교체, 투표소 경보와 현장 확인, 마감 대조 | §7.10, §14 4항, ADR-0027, VC-102, VC-103, VC-106 |
| `participation` | 6. 참여 장부: 정당 열쇠 절차, 모듈 발급 기록, 참여 집합, 투표소 등식, 가명 중복 | §6.4, §6.5, §14 6항, VC-018, VC-084, VC-092, VC-093, VC-095 |
| `roll` | 6. 선거인명부: 출처 추출, 그 병합인 동결, 보관 영수증과 보관 정족수, 출처 서명과 사슬이 있는 변경, 이의 투표 기록(열람 권한), 항목 commitment와 포함 증명 | §6.1, §6.2, §14 6항, ADR-0033, ADR-0040, VC-107..111 |
| `tally` | 7. 집계: 수령 대조, 법적 집계 효과, 다시 계산한 집계 범위와 대조, 실제 커밋먼트 합에 대한 합계 열기, 보고 단위별 종이 대조 | §10.6, §11, §14 7항, VC-024, VC-042..044, VC-057, VC-063, VC-075, VC-099 |
| `audit` | 8. 감사: 재계산한 프레임과 동결 대조, 약정(주사위 기록·비콘 지정·동결 root를 비콘 공표 전에 고정), 시드 재계산(고정 체크포인트 = 약정을 덮는 첫 유효 체크포인트, 약정의 주사위 기록과 회차, 호출자가 본 비콘 출력에서 계산한 값, 공표 시각 구간보다 앞선 고정 체크포인트), 표본 다시 뽑기, 감사가 부르는 기록만의 열기 흔적, 제한 본문의 커밋먼트 재구성, 대조와 사유 코드별 후속(확대, 전수 대조와 발견, 투표함 보류), 단위별 수검표 | §12, §14 8항, VC-045..047, VC-059, VC-074 |
| `disputes` | 9. 분쟁 목록(상태, 결과, 이벤트)과 그 옆의 법적 결정 | §13, §14 9항, VC-049 |
| `report` | 모든 단계를 한 장부에 돌리고 상태 사다리로 상태 하나 | §14 끝, VC-049, VC-050 |
| `error` | genesis 단계의 거부(상태, 집합, 항목 위치, 규칙) | — |

## 쓰는 법

```text
pin (관보·위원회·지정 검증자·인쇄물에서)          공표된 genesis와 모든 집합, 변경들
          │                                                │
          └──────────────▶ verify_genesis ◀────────────────┘
                                 │  Err(Error { state, set, index, rule }) → 아무것도 진행하지 않음
                                 ▼
                         VerifiedGenesis ──▶ box_entry / station_entry / roster … (상태 기계용 증명된 항목)
                                 │
     프레임 스트림, 이벤트 객체 ──▶ build_index
                                 ▼
                           LedgerIndex: events(), box_events(), findings(), box_holds(), ledger_holds()
                                 │
              ┌──────────────────┼──────────────────────┐
              ▼                  ▼                      ▼
     verify_checkpoints   authorize_ledger ──▶ verify_boxes ──▶ verify_records ──▶ verify_participation
     CheckpointChain      AuthorityStage   │    BoxStage           RecordStage        ParticipationStage
                                           │         └──▶ verify_progress: ProgressStage(투표소·투표함마다 흐름, 경보, 마감 대조)
                                           ├──▶ verify_roll(참여 단계에서, + RollInput { contested }): RollStage(추출, 동결, 영수증, 변경, 이의 투표 판정)
                                           ├──▶ verify_disputes: DisputeStage(분쟁 목록, 법적 결정)
                                           └──▶ verify_tally(체크포인트·투표함·기록·분쟁 단계에서): TallyStage(단위별 범위·열기·종이 대조)
                                                    └──▶ verify_audit(+ AuditInput { beacon: 회차·출력·공표 구간, openings }): AuditStage(투표양식별 동결·표본·열기·대조·확대·수검표)

verify_ledger(genesis, 프레임, 이벤트, Publications { now, board })  위 단계를 모두 돌림(감사 입력 없음); 앵커 기한은 장부의 시점확인 토큰으로
verify_ledger_with(…, &AuditInput { beacon: 본 비콘 공표(회차, 출력, 공표 구간), openings: 제한 본문 })
verify_ledger_full(…, &AuditInput, &RollInput { contested: 제한 본문 `ContestedCheckin` })
     ▼
Report: status() → UNVERIFIED | LOG_CONSISTENT | SOURCE_COMPLETENESS_CHECKED | CRYPTO_TALLY_VERIFIED | PAPER_AUDITED | HOLD_REVIEW(사유)
```

보장하는 것:
- `no_std`와 `alloc`, `unsafe` 없음, 패닉 없음, 시계·입출력·무작위 순서 자료구조 없음(워크스페이스 lint 집합).
- `VerifiedGenesis`는 1단계의 모든 규칙이 통과했을 때만 있고, `LedgerIndex`는 그 위에서만 만들어진다. 상태 기계용 항목은 검증기가 전체를 확인한 집합에서만 증명된다.
- 공표된 데이터의 서명은 여기서만 검증해 토큰으로 만든다. 호출자는 토큰을 넘길 수 없다.
- 장부의 문제는 조용히 사라지지 않는다. 거부한 프레임마다 발견이 남고, 그 투표함·그 투표소의 투표함·장부 전체가 `HOLD_REVIEW`가 된다. 고리가 끊긴 곳에서만 색인이 멈춘다.
- 거부한 집계·감사 이벤트가 장부에 남기는 보류는 `TallyEvent::hold`·`AuditEvent::hold`로 공개한다. 단계의 `holds()`가 쓰는 바로 그 표이며, 보고서를 읽는 쪽(검증 콘솔)이 장부 수준의 보류를 가려낼 때 쓴다(ADR-0038 개정 1).

보장하지 않는 것:
- 핀이 관보에 실린 그 값이라는 것. 호출자가 genesis와 다른 출처에서 받아야 한다.
- genesis가 고정한 문서(정책, 법적 승인, 연결 목록, 릴리스 목록)의 내용, 항목이 현실과 맞는지(투표함이 실제로 있는지, 등록된 키를 그 사람이 쥐고 있는지).
- 분기·연결·소프트웨어 단계(10–12). ROADMAP M5의 다음 단계다. `PAPER_AUDITED`는 호출자가 본 비콘 값이 있을 때만 나오므로 `verify_ledger`(감사 입력 없음)의 가장 높은 상태는 `CRYPTO_TALLY_VERIFIED`다.
- 감사에서: 고정 체크포인트와 약정이 비콘 공표보다 앞서는지는 증인 시각 구간과 고정 체크포인트의 시점확인 토큰으로 본다(ADR-0039). 증인 정족수와 두 구분의 기관이 함께 속이면 막지 못한다. 선언된 표본 크기와 상한이 공식 문서에서 나온 값인지, 주사위 기록과 비콘 값이 사실인지(비콘은 호출자가 보증), 감사인의 판정이 옳은지, §12.5의 다른 전수 대조 사유(스키마 없음), 장치 모델별 비율, 열람 원본의 파기(ADR-0036 한계).
- 집계에서: 정족수의 share가 기록마다 커밋먼트와 맞는지(열기가 실패하면 어떤 기록의 share가 틀렸다는 것만 안다, §11.3), 증인의 시계가 맞는지, 위원장이 실제 그 선관위 사람인지(명부의 조직으로만 안다), 수령 선관위의 라벨 수(VC-060)(ADR-0035 한계).
- 참여 장부의 `ParticipationRestriction`(VC-094), `DuplicateIdentification`(VC-076), 유닛 교체 때 순번 연속(VC-073), 명부 가명 집합 부분집합 검사. 사람이 서명한 사건(현장 확인, 비상 투입)의 시간 구간이 사실인지(ADR-0032 한계).
- 명부에서: 추출이 등록부와 맞는지, 병합이 주는 항목, 기준일이 같은지, 구·시·군의 장이 관할 투표구에만 서명하는지, 명부 가명 root를 계산한 절차(보관 기관이 증언), 인원수 표와 통계의 대조, 동결·영수증의 시점확인 기한(ADR-0040 한계). 명부 단계의 효과는 상태 사다리(6단계)뿐이고 명부의 법적 효력은 판정하지 않는다.
- 시점확인 기관의 시각이 참이라는 것, 인증서가 폐지되지 않았다는 것(ADR-0034 5항). 앵커 기한은 장부의 토큰으로 정하지만, 마지막 체크포인트의 토큰이 모자랄 때 창이 열려 있는지는 호출자의 지금 시각으로 가르고, 게시판 공표 기한은 호출자가 판정해 넘긴다.

## 검증

- V1: `tests/genesis.rs`(규칙마다 그 규칙만 어긴 genesis를 실제 하이브리드 서명으로 만들어 거부 확인, 변경의 사슬·번호·다양성·집합), `tests/index.rs`(발견 종류와 보류 범위마다), `tests/checkpoint.rs`(사슬 규칙과 세 root, 실제 증인 서명), `tests/timestamp.rs`(시점확인: 시험 시점에 OpenSSL로 만든 실제 토큰으로 앵커·창·역산의 경계, 받지 못한 기록마다, 회전된 인증서, 운영 주체 계수; `tests/common/tsa.rs`, PATH의 `openssl` 3.0 이상 필요, 개인키는 남기지 않음), `tests/boxes.rs`(승인과 투표함의 생애, 변경과 장치 교체, 거부와 보류마다, 실제 하이브리드 서명), `tests/records.rs`(기록·배치 규칙마다, 실제 OR 증명과 서명, 검증 공개 재구성과 변조), `tests/tally.rs`(범위·열기·종이·수령 대조·법적 효과의 규칙마다, 실제 OR 증명·커밋먼트·합계 열기·정족수 서명, 깨끗한 선거의 `CRYPTO_TALLY_VERIFIED`), `tests/audit.rs`(동결·시드·표본·열기·재구성·대조·확대·수검표·전수 대조·보관 보류의 규칙마다, 실제 기록과 서명, 깨끗한 감사의 `PAPER_AUDITED`, 두 투표양식 중 하나만 감사하면 `CRYPTO_TALLY_VERIFIED`; 두 파일이 쓰는 선거 세계는 `tests/world`), `tests/progress.rs`(흐름·경보·확인·교체·마감 규칙마다), `tests/participation.rs`(절차·발급 기록·참여 집합·등식·중복), `tests/roll.rs`(명부: 효력과 정족수, 거부마다, 값이 다른 영수증, 변경 사슬, 이의 투표 판정, 항목 commitment, 실제 하이브리드 서명; `tests/common/roll.rs`), `tests/disputes.rs`(분쟁 목록과 법적 결정), `tests/report.rs`(상태 사다리의 칸마다), cargo-mutants.
- V2: `kani/proofs.rs`(집합 순서 규칙, 투표함·카운터·가명 유닛의 모듈 챔버 규칙, 토큰 시각과 구간 시작의 비교). `cargo kani -p ityv-verify`.
