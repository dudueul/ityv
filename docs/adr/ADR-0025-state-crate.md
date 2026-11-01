# ADR-0025: 상태기계 크레이트 `ityv-state`의 경계, typestate, capability, 상태 어휘

> English summary: `ityv-state` is the TCB crate that decides, from inputs other crates have already parsed and verified, which state each election object is in on the ledger side: the record status machine and its tally disposition, the ballot-box life cycle as typestate (provisioned, open, fallback, closed by `BoxClose`/`BoxCloseManual`/`LateBoxClose`, custody, counted, audited) with the close invariants of VC-038 as sticky `HOLD_REVIEW` reasons, the custody chain (VC-040), the issuance identities, the tally gates (VC-057, VC-063), the dispute life cycle, the verifier status vocabulary with non-substitution (VC-050) and no machine path to `LEGAL_CERTIFIED` (VC-049), and capability gates from the `LegalAuthorization` scopes (ADR-0002, VC-006..008). It is `no_std`, allocation-free, `unsafe`-free and panic-free, depends only on `ityv-encoding`, `ityv-crypto` and `ityv-ledger`, and consumes `Verified` tokens instead of verifying. M5 step 1 gave every human-signed event a canonical body and the common `WitnessedEvent` envelope, replaced the caller-set signature flags with tokens bound to the keys the genesis registers (no two signers of one event may share a key half), and settled the 18 specification gaps listed below in the normative documents.

- 상태: 채택(M5 1단계에서 명세 공백 결정 반영)
- 날짜: 2026-11-01
- 관련: ADR-0002, ADR-0007, ADR-0010, ADR-0011, ADR-0014, ADR-0016, ADR-0017, ADR-0021; `docs/spec/PROTOCOL.md` §4.4, §7.2.1, §7.3, §8, §10, §11, §13, §14, §17; `docs/spec/FAILURE_CASES.md` §0, §8; `docs/legal/LEGAL_ANNEX.md` §3; `CONSTITUTION.md` §1.4, §1.7; `docs/ROADMAP.md` M4

## 맥락

장부(M2)는 프레임과 체크포인트가 맞는지, 커밋먼트 유닛(M3)은 장치가 올바르게 기록했는지를 다룬다. 그 사이에 "장부에 실린 이벤트들로 보아 지금 이 기록·투표함·인계·분쟁은 어느 상태인가, 다음에 무엇이 허용되는가"를 정하는 층이 필요하다. 이 판정은 검증기(M5), 시뮬레이터(M6), 증인·참관인 도구가 같은 코드로 내려야 하고, 헌법은 상태기계를 typestate로(§1.4), 법적 게이트를 capability 타입으로(§1.7) 쓰라고 한다. 상태 어휘(GLOSSARY)는 자동 상호 전환을 금지하고, 어떤 기계 상태도 `LEGAL_CERTIFIED`를 만들지 않는다(VC-049).

## 결정

1. **범위와 경계.** `ityv-state`는 다음만 담는다: `auth`(법적 승인 객체의 두 서명 토큰 확인, 범위 전제, capability), `record`(기록 상태와 집계 처분), `close`(마감 불변식과 독립 서명자), `boxes`(투표함 typestate), `custody`(인계 사슬), `issuance`(교부·참여 등식), `tally`(집계 범위·합계 열기 관문), `dispute`(분쟁), `status`(검증기 상태 어휘), `hold`(끈끈한 보류 사유). 경계:
   - `ityv-ledger`: 프레임·체크포인트·증인 규칙과 공표 기한 계산. `ityv-state`는 기한 결과(`Status`, `Breach`)를 상태로 옮길 뿐 다시 계산하지 않는다(체크포인트 1시간 위반은 `UNVERIFIED`, 24시간 공표 위반은 `HOLD_REVIEW`, FAILURE_CASES §8).
   - `ityv-cunit`: 장치 쪽 typestate(표·방문·투표함)와 장치가 서명 전에 하는 같은 마감 검사. `ityv-state`는 장부 쪽에서 보이는 것만 본다. 장치 쪽 크레이트에 의존하지 않는다.
   - `ityv-encoding`: 스키마. 스키마가 있는 객체(`LegalAuthorizationBody`, `BoxClose`, `CastRecordBody`, `ChallengeOpeningBody`, `BatchAttestBody`)는 그 타입을 그대로 받는다. 없는 객체는 최소 입력 타입을 두고 M5 인코딩 과제로 남긴다(아래 목록).
   - `ityv-verify`(M5): 장부를 읽어 이 크레이트의 기계를 구동하고, 서명을 검증하고, 단계별 결과(`Evidence`)를 만든다.
2. **서명은 검증하지 않고 토큰을 받는다.** 법적 승인은 `ityv_crypto::verify_hybrid`가 만든 두 `Verified<HybridSigned>` 토큰을 받아 purpose `legal-auth`, 객체 바이트, 두 반쪽(ML-DSA-87, Ed25519)이 모두 다른 두 키(VC-006)를 확인한 뒤 본문을 디코딩하고 범위 전제를 검사한다. 마감은 장치 서명이 있으면 purpose `box-close`(늦은 마감은 `late-box-close`), 본문 바이트, 서명 바이트, 투표함 장치 키가 모두 맞는 토큰을 요구하고, 서명이 있는데 토큰이 없으면 거부한다. `LegalDecisionRef`는 purpose `legal-decision`과 권한 기관 키가 맞는 토큰으로만 `LegalReference`가 된다. 사람이 서명하는 이벤트(개시, 비상 투입, 교부 회계, 각인 판독, 인계, 봉인 변경, 늦은 배치 마감, 분쟁)는 모두 `WitnessedEvent`(0x0028)로 오고, 서명마다 토큰 하나를 받아 purpose, 본문 바이트, 서명 바이트, genesis 명부가 그 사람·역할·조직에 등록한 키를 모두 대조한다(`sig::check_event`). 마감의 사람 서명도 같다(`CloseTokens`). 한 이벤트의 서명자 키는 어느 반쪽도 겹치면 안 된다(VC-098). 불리언 서명 깃발은 없다(M5 1단계).
3. **capability.** `Authorization::grant::<S>(오늘)`만 `Cap<'a, S>`를 만든다(생성자 비공개, `Clone`·`Copy` 없음). 표지는 범위마다 하나(`PublicBoard` … `VoterCode`). 범위 전제: 0단계 위의 모든 범위는 `PUBLIC_BOARD`, 1단계 위는 `TRUSTEE_BODY`를 요구하고, `VOTER_CODE`는 `BALLOT_MARK`를 요구한다(VC-008, LEGAL_ANNEX §3.3 규칙 3). 쓰는 곳: 투표함 등록 `PUBLIC_BOARD`, 기록 수록 `BALLOT_MARK`(VC-007), 집계 범위·합계 열기 `CRYPTO_TALLY_AID`, 감사 완료 `RLA`, 포함 분쟁 `VOTER_CODE`, 그 밖의 분쟁 `PUBLIC_BOARD`.
4. **투표함 typestate.** `BallotBox<'a, S>`, `S ∈ {Provisioned, Open, Fallback, Closed, Counted, Audited}`. 상태를 바꾸는 전이는 상자를 소비하고 `Transition::{Done(다음), Refused(그대로, 오류)}`를 돌려주므로 잘못된 이벤트가 상태를 잃게 하지 않는다. 마감된 상자에는 `record`가 없다(VC-039, `compile_fail` doctest). 비상 투입 중인 상자는 기록·검증 열기를 받는다: 업링크는 저장 후 전달이므로(§5.8) 선언 전에 서명된 기록이 선언 뒤에 장부에 실릴 수 있다. 개시는 genesis에 없는 모듈(VC-037), 장치 서명 없음, 독립 서명자 부족을 거부하고(중복 모듈은 인코딩이 막는다), 봉인 불일치와 초기 수량 0 아님은 보류로 연다. 마감 서명자는 명부에 등록된 역할·조직과 일치해야 하고 같은 사람이 두 번 나올 수 없으며 사무원 2와 서로 다른 조직 참관인 2가 있어야 한다(같은 조직 두 사람은 한 명, ITYV-BEH-025).
5. **마감은 수록하고 어긋남은 끈끈한 보류로 남긴다.** VC-038의 각 등식은 `HoldReason` 하나다. 장부 쪽에서 보는 사실(수록된 기록·검증 열기·배치 증명 수)과 마감이 보고한 수가 다르면 `ObservedCountMismatch`(§14 4항의 기록 집합 root 일치가 수를 고정한다). 보류는 쌓이기만 하고, 명세가 해소 이벤트로 정한 두 경우만 특정 사유를 지운다: 사람이 센 수(종이·봉투·스티커)가 같은 `LateBoxClose`는 수동 마감의 판정을 자기 판정으로 바꾸고(`ManualClose` 제거), 다르면 이전 사유를 모두 두고 `LateCloseDiffers`를 더한다. `LateBatchClose`가 장부의 모든 기록을 증명하면 `OpenBatches`를 지운다. 늦은 마감과 늦은 배치는 개표 뒤(늦은 마감 기한 안)에도 받는다.
6. **기록 상태.** 장부에 나타난 기록은 `UNATTESTED`로 시작해 배치 증명으로 `CAST_COMMITTED`가 된다. 증명 전에만 검증 열기(`CHALLENGED_SPOILED`, `RECEIPT_SCAN`에서는 불가)나 격리(`QUARANTINED`)로 갈 수 있고 둘은 최종이다(배치는 넣은 표만 담으므로 카운터 등식이 성립). 관외 기록은 수령 대조로 다섯 결과 중 하나가 된다. `SHARE_MISSING`과 시험용 투표양식(`TEST-`)은 깃발이다. 처분 우선순위: 시험용 → 주 상태 제외(검증 열기, 격리, 미수령, 기한 후) → `SHARE_MISSING` → `UNATTESTED` → 대기(수령 대조 대기, 법적 판정 대기) → 포함. 훼손·오배송 기록은 기계가 결정하지 않는다(ITYV-BEH-140).
7. **집계 관문.** `TallyScope`는 모든 투표함 마감, (관외 기록이 있으면) 수령 대조, 마지막 마감 후 96구간(24시간)이 지난 뒤에만(VC-057), `AggregateOpening`은 그 범위가 체크포인트에 포함된 뒤에만(VC-063) 허용한다. 두 관문 모두 `CRYPTO_TALLY_AID` 권한이 같은 선거의 것인지 확인한다.
8. **분쟁.** 접수와 모든 상태 변경은 선관위와 위원회가 함께 서명한 `DisputeEvent`이고(두 키는 반쪽까지 달라야 함), 접수는 언제나 `OPEN`으로 시작한다. 뒤 이벤트는 접수 본문의 객체 해시로 접수를 가리키고 유형·대상·증거를 바꿀 수 없다. 전이는 앞으로만: `OPEN → INVESTIGATING`, `OPEN|INVESTIGATING → RESOLVED_TECHNICAL`, `OPEN|INVESTIGATING|RESOLVED_TECHNICAL → REFERRED_LEGAL`(기술 해결에 대한 이의 경로, ITYV-BEH-136). 기술 해결만 검증기의 미해결 목록에서 빠진다.
9. **상태 어휘.** `evaluate(&Evidence)`만 상태를 정한다. 실패·보류·미해결 분쟁·분기 증거·공표 위반이 하나라도 있으면 `HOLD_REVIEW`. 아니면 1–3단계, 4단계의 불변식, 5단계 통과와 앵커 충족 → `LOG_CONSISTENT`, 4단계 완전성까지 → `SOURCE_COMPLETENESS_CHECKED`, 6·7단계까지 → `CRYPTO_TALLY_VERIFIED`, 8단계 표본 대조가 규칙상 종료 → `PAPER_AUDITED`, 그 밖은 `UNVERIFIED`(기본값). `Status`에는 `LEGAL_CERTIFIED`가 없고 상태 사이 변환도 없다(VC-049, VC-050, `compile_fail` doctest). `BALLOT_MARK`가 없거나 `RECEIPT_SCAN` 기록이 있으면 보고서는 "수량만으로는 같은 수 교체를 탐지하지 못함"을 표시한다(ITYV-BEH-077·170·216).
10. **검증 사다리.** V1: 단위 테스트, 실제 하이브리드 서명으로 만든 모든 이벤트(마감·승인·개시·인계·봉인 변경·분쟁·법적 결정 등)의 통합 테스트(토큰 바꿔치기, 다른 키, 다른 purpose, 서명 바이트 변조, 키 반쪽 공유), 독립 참조 규칙(128비트 산술)과의 속성 테스트, cargo-mutants 놓침 0. V2: Kani 하네스(보류 집합, 512개 범위 집합 전부의 전제 규칙, capability 부여, VC-038 수량 등식, 교부·참여 등식, 기록 기계, 분쟁 전진, 상태 어휘, 인계 첫 고리). typestate 오용은 `compile_fail` doctest(마감된 상자에 기록, 재개봉, capability 위조, `LEGAL_CERTIFIED` 생성).

### M5 인코딩 과제 (닫힘, M5 1단계)

M4에서 최소 입력 타입으로 두었던 객체는 모두 캐노니컬 스키마를 얻었다: `CustodyHandoffBody`(0x0008), `DisputeEventBody`(0x000E), `LegalDecisionRefBody`(0x000F, 결과·집계 효과 필드 포함), 공통 서명 봉투 `WitnessedEvent`(0x0028), `BoxOpenedBody`(0x0029), `FallbackBody`(0x002A), `IssuanceCountBody`(0x002B), `ImprintAuditBody`(0x002C), `SealChangeBody`(0x002D), `LateBatchCloseBody`(0x002E), `BoxCloseBody`의 `spoil_envelope_count`, genesis 항목형 `GenesisBox`·`CustodyRoute`·`RosterSigner`(`ENCODING.md` §8.33–§8.43). 불리언 서명 깃발은 검증 토큰으로, 호출자가 계산하던 인계 해시는 본문 객체 해시로 바뀌었다. `BoxSpec::check_genesis`는 상태기계에 넘긴 명세가 genesis 항목과 같은지 확인한다.

### 명세 공백과 결정

M4에서 이 크레이트가 임시로 읽었던 18개 공백을 규범 문서에서 정했다. 원칙: 더 엄격한 쪽, 실패하면 닫히는 쪽(거부보다 보류와 증거 보존, 기계보다 사람·법의 판단).

| # | 공백 | 결정 | 이제 적힌 곳 |
|---|---|---|---|
| 1 | 3단계가 2단계의 어느 범위를 전제하는가 | `VOTER_CODE`는 2단계 범위 여섯 가지를 모두 전제한다. 추가로 `RLA`는 `CRYPTO_TALLY_AID`를 전제한다(공백 14) | PROTOCOL §4.4, LEGAL_ANNEX §3.3, VC-008; `auth::prerequisites` |
| 2 | `RECEIVED_LATE`가 §11.1 제외 목록에 없음, 훼손·오배송 판정의 코드 | 목록에 `RECEIVED_LATE`와 `LEGAL_EXCLUDED`를 더함. 훼손·오배송 기록마다 `POSTAL` 분쟁을 접수하고 그 `LegalDecisionRef`의 집계 효과(포함·제외)를 따른다. 판정이 다 수록되기 전에는 `TallyScope` 없음 | PROTOCOL §10.6 6항, §11.1, VC-099; `RecordEvent::LegalDecision`, `Exclusion::LegalExcluded`, `TallyReadiness::legal_resolved` |
| 3 | 제외 사유가 여럿일 때 | 정해진 순서의 첫 사유 하나만 적는다: `TEST_BALLOT`, `CHALLENGED_SPOILED`, `QUARANTINED`, `CAST_NOT_RECEIVED`, `RECEIVED_LATE`, `LEGAL_EXCLUDED`, `SHARE_MISSING`, `UNATTESTED` | PROTOCOL §11.1, VC-042; `RecordState::disposition` |
| 4 | `RECEIPT_SCAN` 함의 마감 불변식 | 투표소 함 규칙(종이 = 기록 + 비상 투입, 봉투·스티커 0) | PROTOCOL §10.2 |
| 5 | 격리 봉투 실물 수가 본문에 없음 | `BoxCloseBody`에 `spoil_envelope_count`(필드 12) 추가. 커밋먼트 유닛이 사람이 센 수를 싣는다 | PROTOCOL §10.2, ENCODING §8.16, VC-038; `ityv-cunit` 마감 |
| 6 | 봉인 변경·늦은 배치 마감의 사유 코드 | 봉인: 1 훼손(언제나 보류), 2 점검, 3 용기, 4 명령, 5 기타. 늦은 배치: 1 재기동, 2 전원, 3 모듈 교체, 4 기타. 정의되지 않은 값은 디코딩 거부 | PROTOCOL §7.2.1, §10.3, ENCODING §8.40·§8.41; `HoldReason::SealBroken` |
| 7 | 교부 회계의 인쇄 재고 등식 | `받은 용지 수 = 교부 수 + 미사용 수 + 인쇄 실패 용지 수`. 투표소 합계는 genesis에서 그 `station_id`를 가진 모든 함에서 더한다 | PROTOCOL §10.2, ENCODING §8.38; `HoldReason::IssuanceStockMismatch` |
| 8 | 법적 회부 분쟁과 `LegalDecisionRef`의 효과 | `RESOLVED_TECHNICAL`이 아닌 분쟁은 모두 미해결. `LegalDecisionRef`는 기계 상태를 바꾸지 않고 옆에 표시. 결정에 결과(인용·일부 인용·기각·각하·기타)와 집계 효과 필드 추가 | PROTOCOL §13 4항, §14 9항, ENCODING §8.35; `LegalReference::{outcome, tally_effect, concerns}` |
| 9 | `LateBoxClose`의 해소 조건 | 마감 뒤 96구간 안, 사람이 센 네 수(종이·봉투·스티커·폐기 봉투)가 같으면 해소, 다르면 보류 유지에 "늦은 마감 불일치" 추가 | PROTOCOL §10.2, VC-100 |
| 10 | `LateBatchClose`와 열린 배치 보류 | 배치 본문 해시로 그 배치를 지목하고, 기한 안에서 모든 기록이 증명되면 열린 배치 보류를 푼다 | PROTOCOL §7.2.1, VC-100 |
| 11 | 인계 사슬의 세부 | 첫 인계의 이전 해시 0(그 밖은 0이 아님), 이전 해시는 앞 인계 본문의 객체 해시, 관외 함은 봉투 수, 앞 수신자(사람·조직)가 다음 송신자, 서명자는 등록된 사무원이나 보관 담당자, 사슬이 끝나지 않은 개표는 보류 | PROTOCOL §10.3, ENCODING §8.33, VC-040 |
| 12 | 개시 때의 불일치와 장치 서명 | 봉인 불일치·초기 수량 0 아님은 거부 대신 보류(증거 보존). 장치 서명은 필수(purpose `box-open`) | PROTOCOL §10.1, ENCODING §8.36 |
| 13 | 격리마다 공개 이벤트가 있는가 | 없다. 격리 수는 모듈 카운터 등식과 `spoil_envelope_count`로만 대조 | PROTOCOL §10.2 |
| 14 | 4단계 읽기와 `RLA`만 있는 구성 | 4단계는 불변식과 완전성으로 나눈다. 사다리는 누적이며 `RLA`가 `CRYPTO_TALLY_AID`를 전제해 건너뛰는 구성이 생기지 않는다 | PROTOCOL §4.4, §14 |
| 15 | 0–2단계의 분쟁 | 포함 분쟁이 아닌 분쟁은 0단계부터 `PUBLIC_BOARD`로 받는다 | PROTOCOL §13, §17 표 |
| 16 | 이벤트 ID 재사용과 마감 뒤 기록 프레임 | 같은 객체 해시의 재수록과 마감 뒤 기록 프레임은 무효이며 `HOLD_REVIEW`. 장부 색인(M5 검증기)이 확인한다 | PROTOCOL §14 3항, VC-101 |
| 17 | 늦은 마감 기한의 기준 | 늦은 마감·늦은 배치는 그 투표함 마감의 `time_bucket`부터 96구간. 집계 범위는 그 투표양식의 마지막 마감부터 96구간 뒤 | PROTOCOL §7.2.1, §10.2, §11.1, ENCODING §8.16; `Error::LateWindow` |
| 18 | 비상 투입 뒤에 실린 기록 | 받는다(저장 후 전달). 비상 구간에 기록이 없었다는 사실은 마감 수량과 모듈 카운터로만 확인 | PROTOCOL §7.3 |

새 검증 조건: VC-098(서명과 등록 키의 결속, 키 반쪽 중복 금지), VC-099(법적 판정 전 집계 범위 금지), VC-100(늦은 마감 기한과 해소 조건), VC-101(이벤트 재수록과 마감 뒤 기록).

## 결과

- `crates/ityv-state` 추가, CI의 `no_std` 빌드·Kani·cargo-mutants 목록에 추가. 새 외부 의존성 없음(형제 TCB 크레이트만, 개발 의존성은 기존과 같은 고정 버전).
- BEHAVIOR_SPEC의 `ityv-state` 행 대응은 그 문서 §11에 둔다. trybuild 대신 `compile_fail` doctest를 쓴다(기존 크레이트와 같은 방식).
- M5 1단계에서 인코딩 과제와 명세 공백을 닫았다(위 표). M5의 다음 단계는 장부를 읽어 `Evidence`를 만드는 단계별 검사(genesis 전체 스키마, 장부 색인, 서명 검증과 토큰 생성)를 이 크레이트 위에 얹는다.
