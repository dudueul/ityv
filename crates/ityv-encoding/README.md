# ityv-encoding

> English summary: The canonical fixed-width binary encoding for every object ityv hashes or signs, implemented as a `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate whose only dependency is `zeroize` (default features off), used to wipe the schema values that hold secrets. It implements `docs/spec/ENCODING.md` exactly, ships published test vectors, and is the exemplar for the verification ladder: V1 (property tests, mutation testing) and V2 (Kani harnesses) are in the tree and run in CI.

## 무엇인가

ityv가 해시하거나 서명하는 모든 객체의 유일한 바이트 표현을 만든다. `docs/spec/ENCODING.md`가 명세이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

보장하는 것:
- 같은 값은 항상 같은 바이트열. 디코딩 후 재인코딩하면 원래 바이트열과 같다.
- 정규 형식이 아닌 입력은 첫 위반 오프셋에서 거부된다. 자동 정규화나 기본값 채우기가 없다.
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음, 재귀 없음. 의존성은 `zeroize` 하나(기본 기능 끔).
- 비밀을 담는 값(`Scalars`, `MemberShare`, `ModuleOpening`, `ChallengeOpeningBody`)은 `Clone`·`Copy`가 없고, `Debug`는 공개 필드만 찍으며, drop될 때 `zeroize`로 지운다(ADR-0017 개정 15). 사본이 필요하면 `duplicate()`로 명시하고 그 사본도 drop 때 지운다. 디코더는 값을 제자리에서 채우므로 디코딩 오류가 나면 읽은 부분이 함께 지워진다. `tests/zeroize.rs`와 `Scalars`의 단위 테스트가 소거를 직접 확인한다(`impl Drop` 본문은 변이에서 빠지므로 `Drop`은 시험된 `zeroize`만 부른다).

보장하지 않는 것:
- 객체 내용의 진실성, 서명의 유효성, 스칼라·점의 대수적 유효성. 이 크레이트는 길이만 검사한다.

## API

```rust
use ityv_encoding::{
    ElectionId, Hash512, LedgerFrame, SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, SchemaId, Seq,
    decode_object, encode_object,
};

let frame = LedgerFrame::new(
    ElectionId::new(b"KR-2030-PRES").ok_or("bad id")?,
    Seq::new(1).ok_or("seq must be >= 1")?,
    Hash512::ZERO,
    SchemaId::new(0x0005),
    Hash512([0xaa; 64]),
);
let mut buf = [0u8; 256];
let len = encode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut buf)?;
let decoded: LedgerFrame<'_> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &buf[..len])?;
assert_eq!(decoded, frame);
# Ok::<(), Box<dyn core::error::Error>>(())
```

- `Writer`, `Reader`: 호출자 버퍼 위의 경계 검사 인코더·디코더.
- `Encode`, `Decode`: 모든 객체가 구현하는 트레이트.
- `encode_object`, `decode_object`: 16바이트 헤더를 포함한 최상위 진입점.
- 기본형 newtype: `Hash512`, `Scalar32`, `Point32`, `Token192`, `Ident`, `ElectionId`, `LedgerId`, `KeysetId`, `SchemaId`, `Seq`(1 이상), `TreeSize`, `TimeBucket`, `Day`.
- 식별자 newtype: `ElectionId`, `LedgerId`, `KeysetId`, `BoxId`, `BallotStyleId`, `StationId`, `ModuleId`, `TrusteeId`, `ObserverId`, `OrgId`, `SignerId`(모두 `Ident<64>`).
- 공유 배열형: `Commitments`(`Array<Point, 8>`, 1개 이상), `Scalars<N>`, `ModuleCounters`·`ModuleIds`(`module_id` 오름차순, 중복 없음, 6 이하).

모든 생성자는 파싱한다. `Seq::new(0)`은 `None`이고, `CheckpointBody::new`는 "첫 체크포인트일 때만 이전 해시가 0"이라는 불변식이 깨지면 `None`이다. 잘못된 객체는 타입으로 존재할 수 없다.

## 스키마

| `schema_id` | 타입 | 명세 | 비고 |
|---|---|---|---|
| 0x0001 | `LedgerFrame` | ENCODING §8.1 | |
| 0x0003 | `LegalAuthorizationBody`, `Scope`, `ScopeSet` | §8.2 | |
| 0x0004 | `CheckpointBody`, `CheckpointParts` | §8.3 | |
| 0x0005 | `CastRecordBody`, `CastRecordParts`, `ProofHeader` | §8.6 | 증명 머리부의 `chunk_count`·길이 공식 검사 |
| 0x0016 | `CastRecord`, `ModuleRecordSig` | §8.7 | 본문 + 장치·모듈 Ed25519 기록 서명 |
| 0x0006 | `ChallengeOpeningBody`, `ChallengeOpeningParts`, `ModuleOpening` | §8.8 | |
| 0x0018 | `ChallengeOpening` | §8.9 | 본문 + 장치 하이브리드 서명 |
| 0x000B | `SharePackage`, `ShareEntry`, `ChamberCode`, `Transport` | §8.10 | 서명 없음(기록의 `share_package_hash`가 결속). 챔버 코드 1–4 P1–P4, 5 J, 6 A, 7 C, 8 N(ADR-0019) |
| 0x0015 | `MemberShare` | §8.11 | 암호문 안의 구성원 평문 |
| 0x0012 | `BatchAttestBody`, `BatchAttestParts`, `ModuleRange` | §8.12 | |
| 0x0017 | `BatchAttest`, `ModuleBatchSig` | §8.13 | 서명자 집합 = 구간 − 거부 |
| 0x0013 | `ScanCountAttestBody` | §8.14 | |
| 0x001B | `ScanCountAttest`, `ObserverSig` | §8.15 | 참관인 2 이상, 조직 2 이상 |
| 0x0007 | `BoxCloseBody`, `BoxCloseParts`, `CloseCounts` | §8.16 | 마감 불변식(VC-038)은 인코딩 규칙이 아니다 |
| 0x001A | `BoxClose`, `Attestation`, `SignerRole` | §8.17 | 장치 서명 선택, 사무원 2·참관인 2(조직 2) |
| 0x0019 / 0x000A | `SlipBody` / `Slip` | §8.18 | 방문당 하나, 추적코드 1–8개(중복 없음) |
| 0x0023 / 0x0024 | `DeviceAttestationBody` / `DeviceAttestation` | §8.28–§8.29 | 장치 종류 1–10, 도전 경로 1·2, 구성 요소 1–16개(식별자 순, 중복 없음), 모듈 진술 0–7개(같은 모듈 두 번 없음). 구성 해시는 다시 계산하지 않는다(검증기의 일) |
| 0x0025 | `AttestationSummary` | §8.30 | 서명 대상은 1–7번 필드(`SummaryParts`) |
| — | `ChallengeMessage`, `ModuleStatementMessage` | §4, §8.19, §8.28 | 헤더 없는 서명 입력(참관인 도전값, 모듈 진술) |
| 0x0008 | `CustodyHandoffBody`, `CustodyHandoffParts` | §8.33 | 순번 1부터, 이전 해시는 첫 인계만 0, 두 조직이 다름 |
| 0x000E | `DisputeEventBody`, `DisputeEventParts`, `DisputeAction`, `DisputeType` | §8.34 | 접수 해시는 접수만 0, 결과 해시는 해결·회부만 0 아님, 기록은 투표함과 함께 |
| 0x000F | `LegalDecisionRefBody`, `LegalDecisionRefParts`, `LegalOutcome`, `TallyEffect` | §8.35 | 대상 분쟁 해시 0 아님 |
| 0x0029 | `BoxOpenedBody`, `BoxOpenedParts` | §8.36 | |
| 0x002A | `FallbackBody`, `FallbackParts`, `FallbackKind`, `FallbackReason`, `MarkerRange` | §8.37 | 사유 0은 종료일 때만, 표지 범위는 앞으로 |
| 0x002B | `IssuanceCountBody`, `IssuanceCountParts`, `EnvelopeIssuance` | §8.38 | 등식은 인코딩 규칙이 아니다 |
| 0x002C | `ImprintAuditBody`, `ImprintAuditParts` | §8.39 | |
| 0x002D | `SealChangeBody`, `SealChangeParts`, `SealChangeReason` | §8.40 | 새 봉인 해시는 앞과 다름 |
| 0x002E | `LateBatchCloseBody`, `LateBatchCloseParts`, `LateBatchReason` | §8.41 | 배치 본문 해시 0 아님 |
| 0x0028 | `WitnessedEvent`, `EventSig`, `EventRole` | §8.42 | 위 본문 9종의 봉투. 서명자 오름차순, 본문별 역할 조합(`roles_satisfied`), purpose는 `purpose_of` |
| — | `GenesisBox`, `CustodyRoute`, `RosterSigner`, `CaptureProfile`, `RosterRole` | §8.43 | genesis(0x0002) 안의 필드형. 경로는 2–8곳이고 이웃이 다름, 임명 해시 0 아님 |

0x0010·0x0011은 `ityv-ledger`가, 0x0014·0x0101·0x0103·0x0104·0x0105는 `ityv-cunit`가 구현한다(ENCODING §6).

**본문 + 서명 묶음 규칙(ADR-0017 §2).** 자기 서명을 담는 이벤트는 본문 객체와 래퍼 객체로 나뉜다. 래퍼의 `body` 필드는 인코딩된 본문 객체 바이트 전체(헤더 포함)이고 서명 메시지는 정확히 그 바이트다. 래퍼 디코더는 본문을 그 스키마의 규칙으로 다시 디코딩하며, 본문 안의 오류 오프셋은 바깥 객체 기준으로 옮겨 보고한다(헤더 16 + 길이 접두 4 + 안쪽 오프셋). 서명과 본문은 입력에서 빌려 쓰며 복사하지 않으므로 4,691바이트 서명이나 22KB 본문이 스택에 복제되지 않는다.

**오류 종류와 오프셋(ENCODING §8.20).** 디코더는 필드를 읽는 즉시 그 필드의 규칙을 검사하고 첫 위반에서 멈춘다. 개수에 하한이 있는 배열은 하한 미달을 `ValueOutOfRange`(개수 접두사 오프셋)로 보고한다: `CastRecordBody`·`SharePackage`의 커밋먼트(1 이상), `ChallengeOpeningBody`의 `rand`(1 이상), `MemberShare`의 `shares`(1 이상), `CastRecordBody`의 `module_counters`(1 이상), `ScanCountAttest`의 `observer_sigs`(2 이상). 집합 수준 불변식은 배열 전체를 읽은 뒤 그 배열의 개수 접두사 오프셋에서 `InvariantViolation`으로 보고한다: `CastRecord`·`BatchAttest`의 서명자 집합 불일치(거부 모듈의 서명 포함), `BatchAttestBody`의 구간에 없는 거부 모듈, `ScanCountAttest`의 참관인 조직 다양성, `BoxClose`의 사무원 2·서로 다른 조직의 참관인 2. 배열 안의 위반(`NotSorted`·`Duplicate`·범위)이 먼저 발견되면 그것이 우선한다. 필드 하나의 규칙은 그 필드 오프셋에서 보고한다: 숫자 범위(`proof_system_id`, `option_index > 63`, `transport_flags`, `chamber`, `transport`, KEM 항목의 0 아닌 `pad_id`·`pad_index`, `record_count`, `counter_first > counter_last`, `role`)는 `ValueOutOfRange`, 증명 머리부 불일치(`option_count ∈ 2..=64`, `chunk_count = ⌈option_count/9⌉`, 길이 공식, `chunk_count` = 커밋먼트 수), 모듈별 `rand` 개수 불일치, `MemberShare`의 모듈 없는 경우 0 아닌 `cid`·`tag`나 존재하는 `lab`은 `InvariantViolation`이다. 생성자(`new`)는 같은 규칙을 검사하되 집합 수준 오류와 개수 하한 미달을 오프셋 0의 `InvariantViolation`으로(`Option`을 돌려주는 생성자는 `None`으로) 보고한다.

**최대 길이(헤더 포함, 모듈 7개·챔버 8개·추적코드 8개 기준, ADR-0019·ADR-0021).** `CastRecordBody` 21,570 · `CastRecord` 22,582 · `ChallengeOpeningBody` 3,094 · `ChallengeOpening` 7,805 · `SharePackage` 269,088 · `MemberShare` 1,942 · `BatchAttestBody` 1,366 · `BatchAttest` 39,394 · `ScanCountAttestBody` 248 · `ScanCountAttest` 19,580 · `BoxCloseBody` 961 · `BoxClose` 44,301 · `SlipBody` 676 · `Slip` 5,387 · `DeviceAttestationBody` 37,063(구성 요소 16·모듈 7; 현장 증명 스키마의 변이 80개 중 잡힘 55, 빌드 불가 25, 놓침 0) · `DeviceAttestation` 41,774 · `AttestationSummary` 388.

## 검증

```bash
cargo test --locked -p ityv-encoding                  # V1: 단위·속성·골든 벡터 테스트
ITYV_UPDATE_VECTORS=1 cargo test --locked -p ityv-encoding --test vectors --test m3_vectors   # 벡터 재생성
cargo kani -p ityv-encoding                           # V2: Kani 하네스 20개
cargo mutants -p ityv-encoding                        # V1: 변이 테스트
```

속성 테스트는 모든 스키마에 대해 왕복, 모든 단일 바이트 변이가 거부되거나 다른 값으로 디코딩되고 그 재인코딩이 변이 바이트열과 같음(정규성), 모든 진접두사의 거부, 임의 바이트에 대한 모든 디코더의 무패닉을 검사한다. Kani 하네스는 정수 왕복, 불리언·존재 태그 엄격성, 식별자 알파벳의 정확성, 헤더 거부, 임의 입력에 대한 리더·라이터의 무패닉, `LedgerFrame`·`ScanCountAttestBody` 왕복, `SlipBody` 생성자의 추적코드 규칙(1–8개, 중복 없음, 위치 순서 유지), 투함 기록 증명 머리부 검사의 정확성(PROTOCOL §7.5 공식을 독립적으로 적은 식과 대조), 유한 영역 교차 필드 검사의 정확성(`transport_flags` 마스크, 칸·운반·역할 코드, `record_count` 범위, KEM 항목의 0 패드 필드)을 유계 모델 검사로 증명한다. 배열 필드를 가진 본문(`BoxCloseBody`·`BatchAttestBody`·`MemberShare`·`SharePackage`, 추적코드 배열이 생긴 `SlipBody`)의 객체 수준 왕복은 Kani 하네스로 두지 않는다: 이 도구 조합(Kani 0.68, CBMC 6.11)은 버퍼에 기호 바이트가 하나라도 들어가면 상수 전파를 멈추어 식별자·배열 길이로 도는 모든 루프가 하네스 한계까지 펼쳐지므로, 기호 값이 전혀 없는 `BoxCloseBody` 왕복조차 5분 안에 끝나지 않았다. 이 본문들의 왕복·정규성은 V1(속성 테스트 `check_canonical!`, 공개 벡터, 변이 테스트)이 담당한다.

변이 테스트에서 이 크레이트에 이름으로 제외한 변이는 없다. `proof_system_id`는 값이 항상 1이므로 저장하지도 접근자를 두지도 않는다(상수 `PROOF_SYSTEM_OR_REP_V1`만 있다). 상수를 돌려주는 접근자는 그 자체가 동치 변이(상수 1로 치환)를 낳으므로 두지 않았다.

`vectors/*.txt`는 공개 시험 벡터다(스키마마다 한 파일, 정상 벡터와 거부 벡터). 독립 2차 구현(V5)은 이 파일로 차분 테스트를 한다. 형식은 파일 머리의 주석에 있다. 래퍼 벡터의 서명은 패턴 바이트이며 실제 서명이 아니다: 인코딩 계층은 서명을 불투명한 고정폭 필드로만 다룬다.

## 테스트 코드의 lint 완화

`tests/` 아래 통합 테스트 크레이트는 TCB 밖이다. 각 파일 머리에 사유를 적고 `unwrap`, `expect`, `panic`, 인덱싱, 산술 부작용 lint를 완화하며, 거부 규칙을 하나씩 순서대로 밟는 `m3_records.rs`·`m3_events.rs`는 함수 길이와 유사 이름 스타일 lint(`too_many_lines`, `similar_names`)도 완화한다. `tests/common/mod.rs`는 모든 테스트 바이너리에 컴파일되므로 `dead_code`도 허용한다. `tests/zeroize.rs`는 `unwrap`, `expect`, 인덱싱, `missing_panics_doc`만 완화한다. TCB 크레이트(`src/`)에는 어떤 완화도 없다.
