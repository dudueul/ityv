# ityv-state

> English summary: The ledger-side state machines of ityv (ADR-0025). `no_std`, allocation-free, `unsafe`-free, panic-free Rust: legal-scope capabilities from a doubly signed `LegalAuthorization` (VC-006..008), the record status machine and its tally disposition, the ballot-box life cycle as typestate (provisioned, open, fallback, closed, counted, audited) with the close invariants of VC-038 as sticky `HOLD_REVIEW` reasons and the two resolving events (late box close, late batch close), the custody chain (VC-040), the issuance and participation identities, the tally gates (VC-057, VC-063), the dispute life cycle, and the verifier status vocabulary with no machine path to `LEGAL_CERTIFIED` (VC-049, VC-050). It consumes `ityv-crypto`'s `Verified` tokens and `ityv-ledger`'s deadline results; it verifies nothing itself. Verification: V1 (unit, integration with real hybrid signatures, property tests against independent reference rules, cargo-mutants), V2 (Kani harnesses), `compile_fail` doctests for typestate misuse.

## 무엇인가

장부에 실린 이벤트로 보아 각 기록·투표함·인계·분쟁이 어느 상태이고 다음에 무엇이 허용되는지를 정하는 TCB 크레이트다. 명세는 `docs/spec/PROTOCOL.md` §4.4, §7.2.1, §10, §11, §13, §14, §17과 `docs/adr/ADR-0025-state-crate.md`이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `auth` | 법적 승인 객체의 두 서명 토큰 확인, 범위 전제(단계 건너뛰기 금지), `Authorization::grant`만 만드는 `Cap<'a, S>` | §4.4, ADR-0002, VC-006..008 |
| `record` | `UNATTESTED`·`CAST_COMMITTED`·`CHALLENGED_SPOILED`·`QUARANTINED`·수령 대조 다섯 결과, `SHARE_MISSING`·`TEST_BALLOT` 깃발, 집계 처분 | §7.2.1, §8, §10.6, §11.1 |
| `close` | 마감 수량 불변식(`count_verdict`), 모듈 카운터 틈, 등록된 독립 서명자 | §10.1, §10.2, VC-037, VC-038 |
| `boxes` | `BallotBox<'a, S>` typestate, 마감·수동 마감·늦은 마감·늦은 배치, 개표, 감사 | §10, VC-039 |
| `custody` | 인계 사슬(순번, 이전 인계, 조직, 경로, 양쪽 서명), 봉인 변경 | §10.3, VC-040 |
| `issuance` | 교부 회계와 참여 장부 등식 | FAILURE_CASES §0 |
| `tally` | `TallyScope`·`AggregateOpening` 관문 | §11.1, §11.2, VC-057, VC-063 |
| `dispute` | 분쟁 접수(두 기관), 앞으로만 가는 상태 | §13, VC-048 |
| `status` | 검증기 상태 어휘, 공표 기한 결과의 반영, `LegalReference` | §14, VC-049, VC-050 |
| `hold` | 끈끈한 `HOLD_REVIEW` 사유 집합 | §10.2, §14 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음(워크스페이스 lint 집합, Kani 하네스).
- 상태는 타입이다. 상자를 바꾸는 전이는 상자를 소비하고, 거부되면 바뀌지 않은 상자를 돌려준다(`Transition::Refused`). 마감된 상자에는 기록 메서드가 없고, 연 상자에는 다시 여는 메서드가 없다(`compile_fail` doctest).
- 법이 막는 연산은 그 범위의 capability를 요구한다. capability는 두 기관이 서명한 승인 객체를 확인한 `Authorization`만 효력 기간 안에서 만들 수 있다.
- 어긋남은 거부가 아니라 끈끈한 보류다. 사유는 쌓이기만 하고, 사람이 센 수가 같은 늦은 마감(수동 마감의 판정을 대체)과 모든 기록을 증명한 늦은 배치(`OpenBatches` 제거)만 특정 사유를 지운다.
- 상태 어휘는 `evaluate`만 정하고, `Status`에는 `LEGAL_CERTIFIED`가 없으며 상태 사이 변환이 없다. 법적 결과는 권한 기관 서명이 확인된 `LegalReference`로만 옆에 표시된다.

보장하지 않는 것:
- 서명의 유효성. 이 크레이트는 `ityv-crypto`의 토큰을 받아 purpose·객체·키가 맞는지만 본다. 스키마가 아직 없는 인계·봉인 변경·분쟁 접수의 서명은 호출자가 검증 결과를 깃발로 넘긴다(ADR-0025 M5 인코딩 과제).
- 장부의 정합성(`ityv-ledger`), 객체의 정규성(`ityv-encoding`), 장부를 읽어 `Evidence`를 만드는 검증 파이프라인(M5).
- 수량이 같다는 것은 같은 수의 교체가 없었다는 증명이 아니다. 보고서의 `count_only`가 이를 표시한다.

## 투표함 상태

```text
Provisioned ──open──▶ Open ◀──end_fallback── Fallback
                       │  └──declare_fallback──▶ │
                       └──────close──────────────┴──▶ Closed ──count──▶ Counted ──audited──▶ Audited
```

| 전이 | 입력 | 거부 | 보류 |
|---|---|---|---|
| `provision` | genesis의 투표함 정보, `Cap<PublicBoard>` | 다른 선거, 경로 2곳 미만 | — |
| `open` | `BoxOpening` | 다른 상자, 미등록·중복 모듈, 7개 초과, 서명자 부족·미등록 | 봉인 불일치, 초기 수량 0 아님 |
| `record` (Open, Fallback) | `CastRecordBody`, `Cap<BallotMark>` | 다른 선거·상자, 열지 않은 모듈 | — |
| `challenge` (Open, Fallback) | `ChallengeOpeningBody` | `RECEIPT_SCAN`, 다른 상자 | — |
| `batch` (Open, Fallback) | `BatchAttestBody` | 다른 상자 | — |
| `declare_fallback`, `end_fallback` | `FallbackEvent` | 다른 상자, 서명자 | — |
| `close` (Open, Fallback) | `BoxClose`, 장치 서명 토큰, 격리 봉투 수, `IssuanceCount` | 다른 상자, 서명자, 토큰 불일치 | VC-038 각 등식, 장부 관찰과의 차이, 수동 마감 |
| `late_close` (Closed, Counted) | 장치 서명이 있는 `BoxClose`, purpose `late-box-close` 토큰 | 수동 마감이 아님, 토큰 불일치 | 사람이 센 수가 다르면 `LateCloseDiffers` |
| `late_batch` (Closed, Counted) | `LateBatchClose` | 장부의 기록 수 초과, 서명자 | 모든 기록 증명 시 `OpenBatches` 해소 |
| `seal_change`, `handoff` (Closed) | `SealChange`, `CustodyHandoff` | 순번, 이전 인계, 같은 조직, 경로 이탈, 한쪽 서명 | 수량 불일치, 설명 없는 봉인 변경 |
| `count` (Closed) | `ImprintAudit` | 다른 상자, 서명자 | 각인 없음·중복, 인계 미완 |
| `audited` (Counted) | `Cap<Rla>` | 다른 선거의 capability | — |

## 기록 처분

| 우선순위 | 조건 | 처분 |
|---|---|---|
| 1 | 시험용 투표양식(`TEST-`) | 제외 `TEST_BALLOT` |
| 2 | `CHALLENGED_SPOILED`, `QUARANTINED`, `CAST_NOT_RECEIVED`, `RECEIVED_LATE` | 제외(같은 이름) |
| 3 | `SHARE_MISSING` | 제외 |
| 4 | 배치 증명 없음 | 제외 `UNATTESTED`(늦은 마감 기한 뒤 확정) |
| 5 | 관외 기록이 아직 수령 대조 전 | 대기 |
| 6 | `RECEIVED_DAMAGED`, `WRONG_DISTRICT` | 법적 판정 대기(기계가 정하지 않음) |
| 7 | 그 밖 | 포함 |

## 검증

| 단계 | 수단 | 내용 |
|---|---|---|
| V1 | 단위 테스트(`src/`) | 모든 모듈의 전이표, 오류 표시, 보류 집합 |
| V1 | 통합 테스트(`tests/boxes.rs`, `tests/auth.rs`) | 실제 하이브리드 서명으로 만든 마감·늦은 마감·승인·법적 참조 객체, 투표함 전 생애, 관외 함, 인계, 개표·감사 |
| V1 | 속성 테스트(`tests/proptests.rs`) | 무작위 이벤트열의 기록·분쟁 단조성, 128비트 참조 규칙과의 마감·교부 판정 일치, 상태 어휘 규칙(ITYV-BEH-063, ITYV-BEH-101) |
| V1 | cargo-mutants | 놓친 변이 0 |
| V2 | Kani(`kani/proofs.rs`) | 보류 집합, 512개 범위 집합의 전제 규칙, capability 부여, VC-038 수량 등식, 교부·참여 등식, 기록 기계, 분쟁 전진, 상태 어휘, 인계 첫 고리 |
| — | `compile_fail` doctest | 마감된 상자에 기록, 재개봉, capability 위조, `LEGAL_CERTIFIED` 생성·변환 |

```sh
cargo test -p ityv-state
cargo kani -p ityv-state
cargo mutants -p ityv-state
```
