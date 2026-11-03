# ADR-0032: 참여 장부, 진행 기록, 분쟁 단계, 검증 공개 재구성

> English summary: Step M5 2e adds four verifier stages. (1) Challenge openings are reconstructed (VC-028): an opening the device signed marks its record `CHALLENGED_SPOILED` as before, and its values must now open the record's commitments, the modules' contributions must sum to its randomness chunk by chunk and derive its cast id, and the modules and counters must be the record's; one that does not holds the box (`OpeningMismatch`, 47) without changing the record's status. (2) The dispute stage `verify_disputes` gives the public list of disputes (type, target, status, result, event frames) and shows each `LegalDecisionRef` next to the dispute it names, taken only under a roster legal authority's key and organisation and only for a dispute filed earlier; it never changes the dispute's status (VC-049), and a decision not taken holds like a refused dispute event. (3) The participation ledger: `ParticipationSet`, `ModuleProvisioned` and `PartyKeyCeremony` are encoded (their signed field groups borrowed, not re-encoded) and `verify_participation` checks every party's key ceremony, every module's pinned provisioning record, every station's set (signed by a check-in unit and its party modules in chamber order) and the identities (final observer count, issuance balance with the record stage's counts, no repeated pseudonym); hold reasons 48–51 (a station count that cannot be taken holds even when a valid one follows); what is not yet on the ledger leaves the stage incomplete instead of holding. §6.5's identity is corrected to check-ins = issued − voter-spoiled − challenged. (4) The progress stage `verify_progress` feeds each station's progress record (ADR-0027) to `ityv-state`'s evaluators in slot order: device streams from the opening window, keys of every state up to a tick's frame, swaps the box stage accepted and witnessed check-in swaps, alarms and on-site checks (a check counts in the last slot of its time bucket), and at close the box's last tick against its device-signed close and the check-in unit against the station's issuance count and observers' final count; only accepted fallback and swap events suspend alarms (a tick's own state does not), only the closing tick is taken after the close, and every refused event is listed and held, a box's stream on its box and the station's on all its boxes, with no new hold reason. The report runs the progress and participation stages; an independent review's findings are fixed (decision 6). The report wires the new stages in; CI splits the long mutation shards.

- 상태: 채택
- 날짜: 2026-11-03
- 관련: ADR-0027(진행 기록), ADR-0029(검증기 크레이트), ADR-0030(체크포인트·승인·투표함 단계), ADR-0031(기록 단계·상태 사다리); `docs/spec/PROTOCOL.md` §6, §8, §13, §14; `docs/ROADMAP.md` M5

## 맥락

M5 2d단계까지 검증기는 genesis부터 기록까지(§14 1–5항)와 분쟁의 미해결 수를 확인하고 `SOURCE_COMPLETENESS_CHECKED`까지 상태를 냈다(ADR-0031). 남은 것은 넷이었다. 검증 공개(`ChallengeOpening`)는 서명만 확인했고, 공개된 값이 기록을 정말 여는지(§8 3항, VC-028)는 보지 않았다. 분쟁은 미해결 수만 보류에 썼고, 공개해야 할 분쟁 목록과 그 옆의 법적 결정(§14 9항)이 없었다. 참여 장부(§14 6항)와 진행 기록(VC-102, VC-103)은 스키마나 단계가 없었다.

## 결정

1. **검증 공개 재구성(§8 3항, VC-028).** 장치가 서명한 `ChallengeOpening`이 가리키는 기록은 2d단계처럼 `CHALLENGED_SPOILED`이고 배치와 기록 집합에서 빠진다. 이제 그 공개 값도 기록을 재구성해야 한다.
   - 같은 투표양식이다(투표함과 선거는 색인이 이미 같게 묶었다).
   - 공개된 `r_0..r_{k−1}`과 모듈마다의 `r_c`는 각각 정확히 `k`개(그 투표양식의 덩어리 수)의 canonical 스칼라다.
   - 모듈 `r_c`를 덩어리마다 더하면 `r_j`다(장치가 더한 그대로, §7.3).
   - 모듈 순서의 `cid_c`가 `SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_1 ‖ …)[0..24]`로 공개된 `cast_id`를 준다.
   - 모듈과 카운터가 기록의 `module_counters`와 같은 순서로 같다.
   - 연 선택지·`cast_id`·`r_j`가 기록의 모든 커밋먼트를 연다(`ityv_crypto::verify_opening`).

   재구성되지 않는 검증 공개는 장치 결함이다. 목록(`failed_openings`)에 남기고 투표함을 보류한다(`OpeningMismatch`, 새 보류 사유 47). §8 5항이 그 장치를 격리하고 기록을 전수 대조한다. 기록은 그래도 `CHALLENGED_SPOILED`다. 장치가 서명해 연 기록은 유권자가 확인용으로 고른 투표지이고 투함되지 않았다. 재구성 실패를 이유로 그 기록을 투함 기록으로 되돌리면 기록 집합과 배치가 어긋나 더 많은 것을 보류하게 될 뿐이다.

2. **분쟁 단계(§13, §14 9항).** `verify_disputes`는 2c단계의 분쟁 처리(두 기관 서명, 그 날의 능력, 앞으로만 가는 전이)를 그대로 쓰고, 그 결과를 공개 목록으로 낸다.
   - 분쟁마다: 접수 본문 객체 해시(분쟁의 이름), 유형, 투표함·기록, 상태, 결과 문서 해시(해결·회부 이벤트의 마지막 값), 받은 이벤트의 프레임(접수가 처음), 그 분쟁을 가리키는 법적 결정. 목록은 접수 순서다.
   - 미해결은 `RESOLVED_TECHNICAL`이 아닌 모든 분쟁이다. 법적 회부도 기계에게는 미해결이다.
   - **법적 결정.** `LegalDecisionRef`(본문 0x000F)는 서명 하나(인코딩이 법정 권한 기관 역할 하나만 허용한다)가 genesis 명부에 그 서명자·조직의 법정 권한 기관으로 등록된 키로 검증되고(그 프레임에 시행 중인 상태, 없으면 그 앞의 상태), 본문의 결정 기관이 그 조직이며, 앞 프레임에서 접수된 분쟁을 가리킬 때만 받는다(`ityv_state::status::LegalReference::from_signed`와 `concerns`). 받은 결정은 그 분쟁 옆에 표시할 뿐 상태를 바꾸지 않는다(VC-049). `LEGAL_CERTIFIED`는 검증기가 판정하지 않는 표시다.
   - 받지 못한 분쟁 이벤트(서명이 맞지 않음, 능력 없는 접수, 같은 접수 본문의 재접수, 적용되지 않는 변경, 접수되지 않은 분쟁의 변경)와 받지 못한 결정은 프레임 목록에 남고 장부를 보류한다(`DisputeRefused`, 45). 위조된 결정이 조용히 사라지면 결정을 기다리는 사람은 그것이 위조였는지 알 수 없다.
   - 체크포인트 단계의 분쟁 root는 같은 실행의 전이에서 계산한다.

3. **참여 장부(§6.4, §6.5, §9.4.2, §14 6항).** `ParticipationSet`(0x0020), `ModuleProvisioned`(0x0026), `PartyKeyCeremony`(0x0027)를 명세대로 인코딩한다. 셋 다 서명 대상이 객체 앞부분의 헤더 없는 필드 묶음이므로, 디코더는 그 바이트를 그대로 빌려 두고 검증기는 다시 인코딩하지 않고 서명을 확인한다(참여 집합은 최대 약 4.2MB). 색인은 참여 집합을 그 투표소, 발급 기록과 열쇠 절차를 선거 전체로 묶는다. 발급 기록은 선거 전에 만들어져 그 장치를 더하는 변경보다 먼저 게시될 수 있는데, 투표함 단계는 그 투표함이 없는 상태의 프레임에 온 이벤트를 거부하기 때문이다. `verify_participation`은 세 번 읽는다.
   - **정당 열쇠 절차.** genesis 정당마다 하나. 챔버가 정당의 챔버이고, 몫 보관자는 그 챔버의 구성원이며 HSM 제품이 서로 다르고(§6.4 2항), 위원회(예약 `actor_id` `committee`, genesis 위원회 키), 모든 몫 보관자, 서로 다른 조직의 참관인 둘 이상이 서명한다(VC-092). 같은 정당의 다른 필드 절차는 충돌이다.
   - **모듈 발급 기록.** 모든 genesis 상태의 모든 모듈마다, 그 항목이 고정한 해시의 기록. 챔버·장치·구성원 수가 genesis와 같고(어느 장치에도 없는 예비 모듈은 기록이 적은 장치가 genesis의 투표함이나 카운터·가명 유닛이어야 한다), `entropy_commitment`가 0이 아니며(VC-095), 카운터·가명 유닛의 정당 모듈이면 보안 칩이 있고 `prf_key_check`가 그 정당 절차의 값과 같다(VC-093). 다른 모듈에는 확인값이 없다. 위원회, 그 챔버 구성원 한 명 이상, 서로 다른 조직의 참관인 둘 이상이 서명한다. 고정되지 않은 기록은 받지 않는다. 그 기록을 고정하는 상태 가운데 하나라도 모듈을 카운터·가명 유닛의 정당 모듈로 두면 보안 칩과 정당 절차의 확인값이 있어야 한다(VC-093). 그 기록을 고정하는 모든 상태는 같은 챔버를 줘야 한다. 참관인 서명은 그 프레임까지의 모든 genesis 상태에서 그 참관인이 가졌던 키를 최신 상태부터 차례로 대 보고 검증한다(변경이 참관인 키를 바꿔도 그 전에 서명한 기록을 받는다). 반쪽 공유는 실제로 검증한 키로 확인한다. 열쇠 절차의 참관인 서명도 같다.
   - **참여 집합.** 투표소의 카운터·가명 유닛(사용 중 또는 예비, 그 프레임까지의 genesis 상태)이 서명하고, 그 유닛의 정당 모듈이 정당마다 하나씩 챔버 순서로 서명한다(VC-084). 같은 투표소의 다른 가명 집합은 충돌이다. 등식(VC-018): `count`는 그 투표소 마지막 최종 `ObserverCountAttest`의 수와 같고, 그 투표소 마지막 `IssuanceCount`는 `ityv_state::issuance_verdict`로 투표함들과 맞춘다. 투함 기록과 검증 공개 수는 기록 단계가 받은 기록(서명과 증명이 맞은 것)에서, 기록 없는 투표지와 격리 수는 마감에서 온다. 모든 집합을 합쳐 같은 가명이 두 번 나오지 않는다(정렬된 집합의 k-way 병합, 복사 없음).
   - **투표소 수량.** 장부의 모든 `IssuanceCount`와 `ObserverCountAttest`(정기·최종)는 그 프레임에 시행 중인 상태의 명부 키로 서명이 맞고 서명자의 역할이 맞아야 한다(VC-016). 받을 수 없는 수량은 뒤에 받을 수 있는 수량이 와도 목록(`count_findings`)에 남고, 그 투표소와 장부를 `StationCountRefused`(51)로 보류한다. 등식은 받은 수량 가운데 마지막 것을 쓴다.
   - **보류와 완전성.** 받을 수 없는 집합은 `ParticipationSetInvalid`(48), 반복 가명은 `DuplicatePseudonym`(49, 그 투표소들과 장부), 받을 수 없는 발급·절차 기록은 `KeyProvisioningInvalid`(50), 등식 위반은 `ParticipationMismatch`(21)와 교부 사유, 받을 수 없는 투표소 수량은 `StationCountRefused`(51)다. 아직 장부에 없는 것(투표소의 집합·최종 참관인 수·교부 수·마감, 정당의 절차, 모듈의 발급 기록)은 보류가 아니라 미완성이다.
   - **명세 문장 정리.** §6.5 셋째 항목의 "= 해당 투표함들의 투함 기록 수 + 투입 전 검증 폐기 수"는 한 사람이 검증 공개 뒤 다시 받은 경우(교부 2, 검증 폐기 1, 투함 1, 확인 1)와 여러 장 투표에서 성립하지 않는다. `ityv-state`의 등식 `확인 수 = 교부 − 유권자 훼손 − 검증 폐기`가 맞다. 셋째 항목을 그렇게 고친다.

   아직 하지 않는 것: `ParticipationRestriction`(VC-094), `DuplicateIdentification`(VC-076), 유닛 교체 때 순번 연속(VC-073, 열람 권한), 명부 가명 집합 부분집합 검사(§6.5 넷째 항목), 절차의 `wrapped_module_count` 대조. 그 투표소를 더하는 변경보다 앞서 게시된 참여 집합은 거부된다(`SetProblem::Station`).

4. **진행 기록 단계(§7.10, VC-102, VC-103, VC-106).** `verify_progress`는 genesis 마지막 상태의 투표소마다 장부의 진행 기록을 `ityv-state`의 평가기에 넣는다. 커밋먼트 유닛과 카운터·가명 유닛의 진행 기록은 장치 흐름(`BoxStream`, `CheckinStream`)에, 흐름이 받은 누계는 투표소 평가기(`StationProgress`)에 슬롯 순서로 넣고, `ProgressCheck`는 그 슬롯을 닫은 뒤에 넣는다. 명세가 열어 둔 것은 이렇게 정했다.
   - **슬롯과 시간 구간.** 슬롯(10분)과 시간 구간(15분)은 같은 선거 epoch 날 0시부터 센다. 구간 `b`는 슬롯 `⌊3b/2⌋`부터 `⌊(3b+2)/2⌋`까지에 걸친다(`bucket_slots`).
   - **개시.** 장치 흐름의 첫 슬롯은 서명이 맞는 첫 진행 기록의 슬롯이되, 받아들여진 `BoxOpened`의 구간이 걸친 슬롯과 그다음 슬롯(개시 슬롯이든 개시 뒤 첫 슬롯이든) 안으로 맞춘다. 그보다 앞선 진행 기록은 개시 전이고, 더 늦게 시작하면 사이 슬롯이 빠진 것이다. 카운터·가명 유닛은 그 투표소의 첫 개시(프레임 순)와 함께 연다. 열리지 않은 투표함·투표소의 진행 기록, 교체 기록, 현장 확인은 받지 않는다.
   - **순서.** 장치마다 프레임 순서가 아니라 슬롯 순서(같은 슬롯은 프레임 순서)로 넣는다. 늦게 실린 진행 기록도 제 슬롯에서 센다(§7.10 4항). 교체 기록은 그 슬롯의 진행 기록보다 먼저다.
   - **키.** 진행 기록의 서명은 그 프레임에 시행 중인 상태까지의 모든 genesis 상태에서 그 장치의 키(투표함의 장치 키, 투표소의 사용 중·예비 유닛 키)로 확인하고, 흐름은 자기가 묶인 키의 토큰만 받는다. 그래서 교체된 장치가 교체 뒤에 낸 진행 기록과 변경 프레임 전에 실린 예비 장치의 진행 기록은 받지 않는다. 사람이 서명한 이벤트는 그 프레임 상태의 명부로 확인한다.
   - **교체와 정지.** 투표함 단계가 받은 `BoxUnitSwap`은 그 프레임 상태의 장치 키로, 명부가 서명한 `CheckinUnitSwap`은 투표소 항목의 예비 유닛으로 흐름을 옮기고 그 `at_slot`부터 투표소 경보를 멈춘다. 받아들여진 `FallbackDeclared`는 그 구간의 첫 슬롯부터 멈춘다(§7.10 5항). 그 밖에는 아무것도 멈추지 않는다. 진행 기록이 스스로 밝힌 상태는 멈추지 않으며, 선언이나 교체 없이 비상 투입 중·교체 뒤라고 밝힌 진행 기록은 받지 않는다(6항).
   - **현장 확인의 슬롯.** `ProgressCheck`는 그 시간 구간이 걸친 마지막 슬롯에 수록된 것으로 본다. 두 슬롯 기한은 구간 전체가 지켜야 하고, 판정 3은 수록되었을 수 있는 가장 늦은 슬롯의 다음 슬롯에서 판단한다(늦을 수 있는 쪽으로 본다).
   - **투표소 항목.** 평가기와 카운터·가명 유닛 흐름은 투표소의 첫 개시 프레임에 시행 중인 상태의 투표소 항목과 경보 기준을 쓴다.
   - **마감 대조.** 투표함 단계가 마감을 받은 투표함은 유효 마감(받아들여진 마지막 `BoxClose`, 기록 단계와 같다)에 장치 서명이 있을 때만 대조하고 수동 마감은 대조하지 않는다(§10.2의 보류가 있다). 투표소는 마지막 상태의 그 투표함이 모두 마감되면 마지막 `IssuanceCount`와 마지막 마감 `ObserverCountAttest`로 대조하고, 둘 중 하나가 없거나 받지 못하면 보류다. 기다리는 경보는 그때 미해결이 된다. 그 전에는 지금까지의 보류만 센다. 투표 중의 장부를 아직 오지 않은 것으로 보류하지 않는다.
   - **마감 뒤.** 장치는 마감 뒤 마감 진행 기록을 정확히 하나 낸다(ADR-0027 장치 쪽). 투표함의 첫 마감 프레임 뒤에는 마감 상태의 진행 기록만 받고, 카운터·가명 유닛은 그 투표소의 마지막 투표함이 마감된 프레임 뒤에 같다(6항).
   - **상한.** 투표소의 슬롯은 첫 슬롯부터 `MAX_PROGRESS_SLOTS`(31일, 4,464슬롯, 우편 수령 기간보다 길다)까지이며 그 뒤의 진행 기록과 교체 기록은 받지 않는다.
   - **보류.** 받지 않은 이벤트는 모두 목록에 남고 보류다. 진행 기록·교체 기록·마감 수는 `PROGRESS_STREAM`, 현장 확인은 `PROGRESS_UNRESOLVED`다. 투표함 흐름의 보류는 그 투표함에, 카운터·가명 유닛 흐름·경보·투표소 이벤트의 보류는 그 투표소의 모든 투표함에 걸린다(`ProgressStage::box_holds`). 변경이 없앤 투표소의 진행 이벤트는 받지 않고 보류한다. 새 보류 사유는 없다.

5. **보고서.** `verify_ledger`는 기록 단계 뒤에 진행 기록 단계와 참여 장부 단계를 돌리고 분쟁 단계의 공개 목록을 싣는다. 진행 기록의 보류는 투표함 불변식과 같이 `HOLD_REVIEW`로 간다(마감한 투표함에 진행 기록이 없으면 보류다). 참여 장부(6단계)는 모든 투표소·정당·모듈의 증거가 장부에 있으면 통과, 아직 없으면 실행 안 됨이고, 그 보류는 장부 전체의 보류다. 집계(7단계)가 아직 없으므로 가장 높은 상태는 여전히 `SOURCE_COMPLETENESS_CHECKED`다.

6. **독립 검토가 바로잡은 것.**
   - 장치가 스스로 경보를 끌 수 없다. 진행 기록의 상태(비상 투입 중, 교체 뒤)는 `ityv-state`에서 아무것도 멈추지 않는다. 받아들여진 `FallbackDeclared`, 투표함 단계가 받은 `BoxUnitSwap`, 명부가 서명한 `CheckinUnitSwap`만 멈춘다(§7.10 5항). 그 슬롯까지 그 투표함의 비상 투입 선언이 없는 비상 투입 중 진행 기록과, 받은 교체가 없는 교체 뒤 진행 기록은 받지 않고 보류한다(`Undeclared`).
   - 마감 뒤에는 마감 진행 기록 하나만 받는다. 투표함의 첫 마감 프레임 뒤, 카운터·가명 유닛은 그 투표소의 마지막 투표함이 마감된 프레임 뒤의 다른 진행 기록은 받지 않고 보류한다(`AfterClose`, §7.10 8항). 빠진 슬롯을 마감 대조 뒤에 채워 넣을 수 없다.
   - 투표소의 투입 누계 합은 `i128`로 정확하다. 장치가 `u64::MAX`를 보고해도 평가가 멈추지 않고, 그때까지의 보류와 교부표 요구가 사라지지 않는다.
   - 법적 결정은 그 프레임까지의 모든 genesis 상태에서 그 기관에 등록된 키로 확인한다. 변경이 기관의 키를 바꾼 뒤에도 이전 키의 결정을 받는다(§14 9항).
   - 장치 쪽 검증 공개 시험(`ityv-cunit` `tests/flow.rs`)이 검증기가 다시 계산하는 `cast_id` 유도와 모듈·카운터 순서도 확인한다. 두 쪽이 어긋나면 시험이 깨진다.

7. **보류 사유.** 47 `OpeningMismatch`(1항), 48 `ParticipationSetInvalid`, 49 `DuplicatePseudonym`, 50 `KeyProvisioningInvalid`, 51 `StationCountRefused`(3항). 진행 기록과 분쟁은 기존 사유(`ProgressStream`, `ProgressUnresolved`, `CarryOut`, `OpenDispute`, `DisputeRefused`)를 쓴다. 사유 코드는 빈틈없이 이어진다.

8. **CI.** ityv-verify의 변이 시험 조각 하나가 2시간 45분 걸렸다(GitHub 작업 한도 6시간). 조각을 ityv-state 둘, ityv-verify 셋으로 나눈다.

## 결과

- 검증 공개를 고른 유권자의 확인이 공개 데이터만으로 누구에게나 재현된다. 공개 값이 기록을 열지 않으면 장치가 보류된다.
- 분쟁과 법적 결정이 한 목록에 나온다. 결정은 등록된 기관이 서명했을 때만 보이고, 기계 상태는 결정이 바꾸지 못한다.
- 투표 중의 릴레이 투표·끼워 넣기 경보와 현장 확인이 공개 데이터만으로 재계산되고, 마감 대조가 장치의 마지막 누계를 마감 수와 맞춘다.
- 참여 장부의 서명, 정렬, 등식, 가명 중복이 공개 검증된다. 모듈 열쇠의 발급과 정당 열쇠 절차가 genesis에 묶인다.

## 한계

- 사람이 서명한 사건의 시간 구간은 그대로 믿는다. 사무원 2인과 서로 다른 조직 참관인 2인이 함께 늦게 수록하며 시간을 앞당긴 `ProgressCheck`나 `FallbackDeclared`는 경보를 뒤늦게 해소하거나 멈출 수 있다. 다조직 공모는 위협 모형 밖이지만, 체크포인트 시간과 프레임 위치로 늦은 수록을 표시하는 것은 다음 과제다.
- 한 분쟁에 결정이 여럿이면(집계 효과가 서로 달라도) 모두 표시할 뿐 보류하지 않는다. 집계 단계(VC-099)가 결정을 적용할 때 정한다.
- 카운터·가명 유닛의 개시는 그 투표소의 첫 `BoxOpened`(프레임 순)를 따른다. 프레임이 시간 순서와 다르면 정당한 이른 진행 기록이 개시 전으로 거부될 수 있다(보류 쪽으로 틀린다).
- 참여 장부에서 `ParticipationRestriction`(VC-094), `DuplicateIdentification`(VC-076), 유닛 교체 때 순번 연속(VC-073), 명부 가명 집합 부분집합 검사, 열쇠 절차의 `wrapped_module_count` 대조는 아직 없다. 진행 기록 단계는 투표소의 마지막 교부 수와 최종 참관인 수만 대조한다. 그 앞의 받을 수 없는 수량은 참여 장부 단계가 보류한다.

## 대안

- **재구성 실패 기록을 투함 기록으로 되돌리기.** 장치가 서명해 연 기록은 투입되지 않았다. 되돌리면 마감의 기록 수·기록 집합과 어긋나고, 결함 장치가 자기 실수로 기록을 투함 기록으로 만들 수 있다. 기각.
- **위조된 법적 결정을 무시하기.** 결정을 기다리는 쪽이 위조를 알 수 없다. 받을 수 없는 분쟁 이벤트처럼 보류한다.
