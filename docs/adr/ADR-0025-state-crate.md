# ADR-0025: 상태기계 크레이트 `ityv-state`의 경계, typestate, capability, 상태 어휘

> English summary: `ityv-state` is the TCB crate that decides, from inputs other crates have already parsed and verified, which state each election object is in on the ledger side: the record status machine and its tally disposition, the ballot-box life cycle as typestate (provisioned, open, fallback, closed by `BoxClose`/`BoxCloseManual`/`LateBoxClose`, custody, counted, audited) with the close invariants of VC-038 as sticky `HOLD_REVIEW` reasons, the custody chain (VC-040), the issuance identities, the tally gates (VC-057, VC-063), the dispute life cycle, the verifier status vocabulary with non-substitution (VC-050) and no machine path to `LEGAL_CERTIFIED` (VC-049), and capability gates from the `LegalAuthorization` scopes (ADR-0002, VC-006..008). It is `no_std`, allocation-free, `unsafe`-free and panic-free, depends only on `ityv-encoding`, `ityv-crypto` and `ityv-ledger`, and consumes `Verified` tokens instead of verifying. Objects without a schema yet get minimal typed inputs, listed below as M5 encoding tasks; where the specification leaves a rule open, the crate's reading is listed as a spec gap.

- 상태: 채택
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
2. **서명은 검증하지 않고 토큰을 받는다.** 법적 승인은 `ityv_crypto::verify_hybrid`가 만든 두 `Verified<HybridSigned>` 토큰을 받아 purpose `legal-auth`, 객체 바이트, 서로 다른 두 키(VC-006)를 확인한 뒤 본문을 디코딩하고 범위 전제를 검사한다. 마감은 장치 서명이 있으면 purpose `box-close`(늦은 마감은 `late-box-close`), 본문 바이트, 서명 바이트, 투표함 장치 키가 모두 맞는 토큰을 요구하고, 서명이 있는데 토큰이 없으면 거부한다. `LegalDecisionRef`는 purpose `legal-decision`과 권한 기관 키가 맞는 토큰으로만 `LegalReference`가 된다. 캐노니컬 객체가 아직 없는 인계·봉인 변경·분쟁 접수의 서명은 호출자가 검증 결과를 불리언으로 넘긴다(M5에서 토큰으로 바꾼다).
3. **capability.** `Authorization::grant::<S>(오늘)`만 `Cap<'a, S>`를 만든다(생성자 비공개, `Clone`·`Copy` 없음). 표지는 범위마다 하나(`PublicBoard` … `VoterCode`). 범위 전제: 0단계 위의 모든 범위는 `PUBLIC_BOARD`, 1단계 위는 `TRUSTEE_BODY`를 요구하고, `VOTER_CODE`는 `BALLOT_MARK`를 요구한다(VC-008, LEGAL_ANNEX §3.3 규칙 3). 쓰는 곳: 투표함 등록 `PUBLIC_BOARD`, 기록 수록 `BALLOT_MARK`(VC-007), 집계 범위·합계 열기 `CRYPTO_TALLY_AID`, 감사 완료 `RLA`, 포함 분쟁 `VOTER_CODE`, 그 밖의 분쟁 `PUBLIC_BOARD`.
4. **투표함 typestate.** `BallotBox<'a, S>`, `S ∈ {Provisioned, Open, Fallback, Closed, Counted, Audited}`. 상태를 바꾸는 전이는 상자를 소비하고 `Transition::{Done(다음), Refused(그대로, 오류)}`를 돌려주므로 잘못된 이벤트가 상태를 잃게 하지 않는다. 마감된 상자에는 `record`가 없다(VC-039, `compile_fail` doctest). 비상 투입 중인 상자는 기록·검증 열기를 받는다: 업링크는 저장 후 전달이므로(§5.8) 선언 전에 서명된 기록이 선언 뒤에 장부에 실릴 수 있다. 개시는 genesis에 없는 모듈(VC-037), 중복 모듈, 독립 서명자 부족을 거부하고, 봉인 불일치와 초기 수량 0 아님은 보류로 연다. 마감 서명자는 명부에 등록된 역할·조직과 일치해야 하고 같은 사람이 두 번 나올 수 없으며 사무원 2와 서로 다른 조직 참관인 2가 있어야 한다(같은 조직 두 사람은 한 명, ITYV-BEH-025).
5. **마감은 수록하고 어긋남은 끈끈한 보류로 남긴다.** VC-038의 각 등식은 `HoldReason` 하나다. 장부 쪽에서 보는 사실(수록된 기록·검증 열기·배치 증명 수)과 마감이 보고한 수가 다르면 `ObservedCountMismatch`(§14 4항의 기록 집합 root 일치가 수를 고정한다). 보류는 쌓이기만 하고, 명세가 해소 이벤트로 정한 두 경우만 특정 사유를 지운다: 사람이 센 수(종이·봉투·스티커)가 같은 `LateBoxClose`는 수동 마감의 판정을 자기 판정으로 바꾸고(`ManualClose` 제거), 다르면 이전 사유를 모두 두고 `LateCloseDiffers`를 더한다. `LateBatchClose`가 장부의 모든 기록을 증명하면 `OpenBatches`를 지운다. 늦은 마감과 늦은 배치는 개표 뒤(늦은 마감 기한 안)에도 받는다.
6. **기록 상태.** 장부에 나타난 기록은 `UNATTESTED`로 시작해 배치 증명으로 `CAST_COMMITTED`가 된다. 증명 전에만 검증 열기(`CHALLENGED_SPOILED`, `RECEIPT_SCAN`에서는 불가)나 격리(`QUARANTINED`)로 갈 수 있고 둘은 최종이다(배치는 넣은 표만 담으므로 카운터 등식이 성립). 관외 기록은 수령 대조로 다섯 결과 중 하나가 된다. `SHARE_MISSING`과 시험용 투표양식(`TEST-`)은 깃발이다. 처분 우선순위: 시험용 → 주 상태 제외(검증 열기, 격리, 미수령, 기한 후) → `SHARE_MISSING` → `UNATTESTED` → 대기(수령 대조 대기, 법적 판정 대기) → 포함. 훼손·오배송 기록은 기계가 결정하지 않는다(ITYV-BEH-140).
7. **집계 관문.** `TallyScope`는 모든 투표함 마감, (관외 기록이 있으면) 수령 대조, 마지막 마감 후 96구간(24시간)이 지난 뒤에만(VC-057), `AggregateOpening`은 그 범위가 체크포인트에 포함된 뒤에만(VC-063) 허용한다.
8. **분쟁.** 접수는 선관위와 위원회의 접수 서명이 모두 있어야 하고 언제나 `OPEN`으로 시작한다. 전이는 앞으로만: `OPEN → INVESTIGATING`, `OPEN|INVESTIGATING → RESOLVED_TECHNICAL`, `OPEN|INVESTIGATING|RESOLVED_TECHNICAL → REFERRED_LEGAL`(기술 해결에 대한 이의 경로, ITYV-BEH-136). 기술 해결만 검증기의 미해결 목록에서 빠진다.
9. **상태 어휘.** `evaluate(&Evidence)`만 상태를 정한다. 실패·보류·미해결 분쟁·분기 증거·공표 위반이 하나라도 있으면 `HOLD_REVIEW`. 아니면 1–3단계, 4단계의 불변식, 5단계 통과와 앵커 충족 → `LOG_CONSISTENT`, 4단계 완전성까지 → `SOURCE_COMPLETENESS_CHECKED`, 6·7단계까지 → `CRYPTO_TALLY_VERIFIED`, 8단계 표본 대조가 규칙상 종료 → `PAPER_AUDITED`, 그 밖은 `UNVERIFIED`(기본값). `Status`에는 `LEGAL_CERTIFIED`가 없고 상태 사이 변환도 없다(VC-049, VC-050, `compile_fail` doctest). `BALLOT_MARK`가 없거나 `RECEIPT_SCAN` 기록이 있으면 보고서는 "수량만으로는 같은 수 교체를 탐지하지 못함"을 표시한다(ITYV-BEH-077·170·216).
10. **검증 사다리.** V1: 단위 테스트, 실제 하이브리드 서명으로 만든 마감·승인 객체의 통합 테스트, 독립 참조 규칙(128비트 산술)과의 속성 테스트, cargo-mutants 놓침 0. V2: Kani 하네스(보류 집합, 512개 범위 집합 전부의 전제 규칙, capability 부여, VC-038 수량 등식, 교부·참여 등식, 기록 기계, 분쟁 전진, 상태 어휘, 인계 첫 고리). typestate 오용은 `compile_fail` doctest(마감된 상자에 기록, 재개봉, capability 위조, `LEGAL_CERTIFIED` 생성).

### M5 인코딩 과제(최소 입력 타입으로 둔 것)

`BoxOpened`, `FallbackDeclared`/`FallbackEnded`, `IssuanceCount`, `ImprintAudit`, `CustodyHandoff`·`SealChange`(0x0008), `DisputeEvent`(0x000E), `LegalDecisionRef`(0x000F), `LateBatchClose`(사유 코드, 입회자 서명), 마감 때의 격리 봉투 실물 수, genesis의 투표함·모듈·명부·인계 경로. 이 객체들이 생기면 불리언 서명 깃발을 토큰으로, 호출자가 계산한 인계 해시를 객체 해시로 바꾼다.

### 명세 공백(이 크레이트의 해석)

1. **단계 건너뛰기.** LEGAL_ANNEX §3.3은 "2단계 범위 없이 3단계 범위만 서명하는 것은 무효"라고 하고 VC-008은 `VOTER_CODE ⇒ BALLOT_MARK ∧ TRUSTEE_BODY`만 명시한다. 2단계의 다른 다섯 범위를 3단계가 요구하는지는 정하지 않았다. 크레이트는 `BALLOT_MARK`만 요구하고, 0·1단계는 각각 하나뿐인 범위를 상위 단계의 전제로 둔다.
2. **기한 후 도착의 제외 사유.** §10.6 6항은 `RECEIVED_LATE`를 제외하지만 §11.1의 제외 목록에는 없다. 크레이트는 `Exclusion::ReceivedLate`를 따로 둔다. 훼손·오배송의 법적 판정이 `TallyScope`에 어떤 코드로 들어가는지도 정해지지 않았다.
3. **사유가 여럿일 때.** §11.1은 한 기록에 제외 사유가 둘 이상이면 무엇을 적는지 정하지 않았다. 크레이트의 우선순위는 결정 6과 같다.
4. **`RECEIPT_SCAN` 투표함의 마감 불변식.** §10.2는 투표소 함과 관외·재외 함만 정한다. 크레이트는 수령 스캐너 함에 투표소 규칙(종이 = 기록 + 비상 투입, 봉투·스티커 0)을 쓴다.
5. **격리 봉투 실물 수.** VC-038의 "격리 봉투 실물 수 = 검증 열기 + 격리"는 `BoxCloseBody`에 실물 수 필드가 없어 장부 쪽에서 확인할 수 없다. 크레이트는 호출자가 사람이 센 수를 넘기게 한다.
6. **사유 코드.** `SealChange`의 사유 코드와 `LateBatchClose`의 사유 코드 값은 정의되지 않았다. 크레이트는 0이 아닌 `u16`만 받는다.
7. **교부 회계의 미사용 수.** `IssuanceCount`의 미사용 수가 들어가는 인쇄 재고 등식(ITYV-BEH-089)은 정해지지 않았다. 싣기만 하고 검사하지 않는다. 투표소 하나에 투표함이 여럿이면 호출자가 합계를 넘긴다.
8. **법적 회부된 분쟁.** §14 9항의 "미해결 분쟁"에 `REFERRED_LEGAL`이 포함되는지, `LegalDecisionRef`가 분쟁을 닫는지 정하지 않았다. `LegalDecisionRef`에는 결정 내용 필드도 없다. 크레이트는 기술 해결만 해결로 보고, 법적 회부 분쟁은 기계 상태로는 계속 `HOLD_REVIEW`에 기여하며 법적 결과는 `LegalReference`로 옆에 표시된다.
9. **`LateBoxClose`의 해소 조건.** §10.2는 "해소될 수 있다"고만 한다. 크레이트의 조건은 결정 5.
10. **`LateBatchClose`와 투표함 보류.** 명세는 기록이 `CAST_COMMITTED`로 돌아온다고만 한다. 크레이트는 장부의 모든 기록이 증명되면 투표함의 `OpenBatches`를 지운다.
11. **인계 사슬의 세부.** 첫 인계의 `previous_handoff_hash`(크레이트: 0), 관외 함의 인계 수량(크레이트: 봉투 수), "앞 인계의 수신자가 다음 인계의 송신자"(크레이트: 요구), 인계 사슬이 끝나지 않은 채 개표에 도착한 경우(크레이트: `CustodyIncomplete` 보류)가 정해지지 않았다.
12. **개시 때의 불일치.** §10.1은 봉인 확인 결과와 초기 수량 0을 싣는다고만 한다. 크레이트는 거부하지 않고 보류로 연다. `BoxOpened`의 장치 서명은 스키마가 없어 아직 확인하지 않는다.
13. **격리 수.** 격리마다 공개 이벤트가 있는지(`ImprintFailure`, 재개 격리) 정해지지 않아 마감의 격리 수는 장부 관찰과 대조하지 않는다. 기록·검증 열기·배치 증명 수만 대조한다.
14. **4단계와 사다리.** §14는 "1–5 통과 → `LOG_CONSISTENT`, 4의 완전성까지 → `SOURCE_COMPLETENESS_CHECKED`"라고 한다. 크레이트는 4단계를 불변식과 완전성으로 나누어 읽는다. 사다리는 누적이므로 `CRYPTO_TALLY_AID` 없이 `RLA`만 있는 구성은 `PAPER_AUDITED`에 이르지 못한다. 명세가 그런 구성을 의도하는지 정해지지 않았다.
15. **분쟁의 단계.** §17 표는 0단계에서 §11–§13을 비활성으로 두고 3단계에 "§13 포함 분쟁"을 더한다. 0·1·2단계에서 포함 분쟁이 아닌 분쟁(보관, 수량 등)을 받을지는 정하지 않았다. 크레이트는 `PUBLIC_BOARD`로 받는다.
16. **이벤트 ID 재사용(ITYV-BEH-083)과 마감 뒤 기록 프레임.** 장부 색인(M5)이 담당한다. 이 크레이트는 마감된 상자에 기록 메서드를 두지 않는 것으로만 막는다.
17. **늦은 마감 기한의 기준.** "마감 후 24시간"의 마감을 크레이트는 그 투표양식의 마지막 투표함 마감으로 읽는다.
18. **장부 순서와 비상 투입.** 명세는 장부에 실리는 순서와 장치 시각의 관계를 투표함 단위로 정하지 않았다(마감 뒤 기록 금지 VC-039만 있다). 크레이트는 `FallbackDeclared` 뒤에 실린 기록도 받고, 비상 구간에 기록이 없었다는 사실은 마감 수량과 모듈 카운터로만 확인한다.

## 결과

- `crates/ityv-state` 추가, CI의 `no_std` 빌드·Kani·cargo-mutants 목록에 추가. 새 외부 의존성 없음(형제 TCB 크레이트만, 개발 의존성은 기존과 같은 고정 버전).
- BEHAVIOR_SPEC의 `ityv-state` 행 대응은 그 문서 §11에 둔다. trybuild 대신 `compile_fail` doctest를 쓴다(기존 크레이트와 같은 방식).
- M5는 위 인코딩 과제와 명세 공백을 먼저 닫고, 장부를 읽어 `Evidence`를 만드는 단계별 검사를 이 크레이트 위에 얹는다.
