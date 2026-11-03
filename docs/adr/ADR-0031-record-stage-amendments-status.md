# ADR-0031: 기록 단계, genesis 변경을 따르는 투표함 단계, 상태 사다리 보고서

> English summary: Step M5 2d completes the verifier's path to `SOURCE_COMPLETENESS_CHECKED`. (1) The verifier keeps every genesis state (the genesis and the state after each amendment) and proves entries against any of them; the ledger index records the frame of each applied amendment, which applies from that frame on. An applied amendment missing from the ledger, or amendments out of order, hold the whole ledger (`AmendmentMissing`). (2) The box stage follows amendments: every event is checked under the keys and roster of the state in force at its frame, the machine follows the state (`BallotBox::follow`), and a device key changed while the box is open needs a `BoxUnitSwap` witnessed on site before the new device may close it; a replaced device cannot open or close the box after its amendment. (3) The record stage checks every cast record (ballot style, OR proof, device and module Ed25519 record signatures under the Ed25519 half of a key of a state up to the record's frame, no module counter used twice), every batch (hybrid signatures, unique batch index, per-module counter ranges contiguous from 1 and within the close, member count and records root), lists records in no valid batch as `UNATTESTED` without holding, and checks the effective close's record set root; new hold reasons 42–44. (4) `verify_ledger` runs every stage over one ledger and maps the outcomes to one status through `ityv_state::status::evaluate`. Box completeness is not a hold: a box still open keeps the status at `LOG_CONSISTENT`. The caller supplies the publication deadlines (the verifier has no clock).

- 상태: 채택
- 날짜: 2026-11-03
- 관련: ADR-0025(상태 크레이트), ADR-0028(genesis 정규 형식), ADR-0029(검증기 크레이트), ADR-0030(체크포인트·승인·투표함 단계); `docs/spec/PROTOCOL.md` §4.3, §7.2.1, §7.5, §7.6, §14; `docs/ROADMAP.md` M5

## 맥락

M5 2c단계까지 검증기는 체크포인트 사슬, 장부의 법적 승인, 투표함 단계를 갖췄다(ADR-0030). 남은 것은 셋이었다. 투표함 단계는 커밋먼트 유닛 교체(`BoxUnitSwap`)를 거부했다. 장치 키를 바꾸는 genesis 변경을 따라가지 못했기 때문이다. 기록(§14 5항)은 서명도 증명도 확인하지 않았다. 단계들의 결과를 상태 어휘 하나로 모으는 보고서가 없었다.

변경을 따라가려면 두 가지가 필요했다. 검증기는 genesis의 마지막 상태만 보관했으므로, 이전 상태의 항목(교체 전 장치 키, 바뀌기 전 명부)을 증명할 수 없었다. 그리고 장부의 어느 프레임부터 어느 상태가 적용되는지 정해져 있지 않았다.

## 결정

1. **모든 genesis 상태와 적용 프레임.** `VerifiedGenesis`는 genesis(상태 0)와 변경마다의 상태를 확인한 집합과 함께 모두 보관하고, 어느 상태에 대해서든 항목을 증명한다(`genesis_at`, `box_entry_at`, `route_entry_at`, `module_at`, `roster_at`). 변경은 장부의 이벤트다(§4.3). 장부 색인은 적용된 각 상태의 `SignedGenesis`가 처음 받아들여진 프레임을 기록한다. k번째 변경은 그 프레임부터 적용된다(`state_at(seq)`는 그 프레임 앞에 실린 변경의 수). 검증기가 적용한 변경이 장부에 없거나 순서가 바뀌어 실렸으면, 각 상태가 언제부터 적용되는지 알 수 없으므로 장부 전체를 보류한다(`AmendmentMissing`, 새 보류 사유 41). 장부에 순서대로 실린 변경까지만 적용 프레임이 정해진다.

2. **투표함 단계의 변경 추적(§4.3, §14 4항, VC-105, VC-106).** 투표함 단계는 이벤트마다 그 프레임에서 시행 중인 genesis 상태(`state_at`)로 확인한다. 서명자 키는 그 상태의 명부에서, 장치 키는 그 상태의 투표함 항목에서 온다. 시행 중인 상태가 더 뒤의 상태이면 상태 기계가 먼저 따라간다(`BallotBox::follow`, 준비 전이면 명세를 바꾼다). 투표함은 그것이 있는 첫 상태에서 시작하고, 시행 중인 상태에 투표함이 없는 이벤트는 거부한다(`Unexpected`).
   - **현장 입회 교체.** 시행 중인 상태가 열린(또는 대체 상태의) 투표함에 새 장치 키를 주면, 사무원 2인과 서로 다른 조직 참관인 2인이 서명한 `BoxUnitSwap`이 수록될 때까지 장치가 서명한 마감과 늦은 마감을 순서 위반으로 거부한다. `BoxUnitSwap`은 변경이 장치 키를 바꾼 열린 투표함에서만 받으며 서명은 시행 중인 상태의 명부로 확인한다(`ityv_state::BoxUnitSwap::check`). 키를 바꾼 변경 전, 준비·마감·개표 상태, 두 번째 교체는 순서 위반이다. 교체 기록의 슬롯과 누계가 진행 기록을 잇는지는 진행 단계가 본다.
   - 개시 전에 장치가 바뀌면 새 장치가 직접 개시하므로 교체 기록이 필요 없다. 마감 뒤의 변경은 그대로 따라간다.
   - **교체된 장치.** 상태 기계는 장치 토큰의 키를 자기 명세의 장치 키와 대조한다. 그래서 교체된 장치가 변경 프레임 뒤에 서명한 개시·마감은 받지 않는다(교체된 장치가 투표함을 닫아서는 안 된다). 교체된 장치가 늦게 올린 투함 기록과 배치는 이 단계가 서명을 보지 않으므로 그대로 세고, 그 서명은 기록 단계가 확인한다(3항). `Refusal::Unsupported`는 없어졌다.

3. **기록 단계(§14 5항, VC-025..027, VC-053, VC-057).** `verify_records`는 투표함 단계가 보고한 투표함마다, 투표함 단계가 거부하지 않은 그 투표함의 이벤트만 읽는다(같은 본문, 순서 위반, 예상 밖 투표함은 이미 빠진다).
   1. **기록.** 투표양식이 genesis에 있고 그 `choices + 2`가 선택지 수다. 커밋먼트가 유효한 점이고 OR 증명이 검증된다(VC-025, VC-026). 장치의 Ed25519 기록 서명(purpose `cast-record`)이 본문 객체 바이트에 대해, 모듈 카운터마다 그 모듈의 Ed25519 기록 서명(purpose `module-record`)이 `body_hash ‖ module_id ‖ counter`(커밋먼트 유닛이 서명하는 그 바이트)에 대해 검증되고, 그 모듈은 투표함의 모듈이다. 하나라도 어긋나면 기록을 거부한다(`RecordRejected`, 보류 사유 42). 같은 모듈 카운터를 가진 기록이 둘이면 둘 다 거부한다(모듈은 한 카운터에 본문 하나만 서명한다, VC-068).
   2. **배치.** 장치와 서명한 모듈의 하이브리드 서명(purpose `batch-attest`), 구간이 투표함의 모듈에만 있음, 같은 `batch_index`에 다른 본문이 없음(장치 이중 서명이면 그 배치들은 아무것도 증명하지 않는다), 모듈마다 `batch_index` 순서로 카운터 1부터 틈·겹침 없이 이어지고 마감의 최종 카운터를 넘지 않음, 구간에 카운터가 모두 들어가는 기록이 그 배치의 구성원이고 그 수가 `record_count`, 그 추적코드의 정렬 집합 root가 `records_root`다(`BatchInvalid`, 43). 두 배치에 걸친 기록은 증명되지 않는다. 구간에는 검증 폐기·격리 투표지의 카운터도 들어가므로 구간이 기록 수보다 넓을 수 있다.
   3. **증명 상태.** 받은 기록은 유효한 배치 하나에 들면 `CAST_COMMITTED`, 아니면 `UNATTESTED`다. `UNATTESTED`는 목록으로 공개하되 보류하지 않는다. 집계 범위가 제외하고, 투표함 단계가 열린 배치를 보류하며, 늦은 배치 마감이 아직 증명할 수 있다(VC-057).
   4. **기록 집합 root.** 투표함의 유효 마감(받아들여진 마지막 `BoxClose`. 늦은 마감이 수동 마감을 대신한다)의 `record_set_root`는 받은 기록 추적코드의 정렬 집합 root다(`RecordSetMismatch`, 44, VC-027).
   - **키.** 프레임 `seq`의 서명을 검증하는 키는 `seq`에 시행 중인 genesis 상태까지(0부터) 그 투표함(과 모듈)이 가진 키 가운데 하나다. 교체된 장치의 과거 기록은 그대로 유효하고(§4.3), 뒤에 등록된 키는 앞 프레임에 서명할 수 없다. 기록 서명은 등록된 하이브리드 키의 Ed25519 반쪽으로 검증한다(`ENCODING.md` §8.43, §8.51).
   - 검증 공개의 재구성(VC-028)은 이 단계가 아니다.

4. **상태 사다리 보고서.** `verify_ledger`는 한 장부에 대해 색인, 승인, 체크포인트 사슬, 투표함, 기록, 분쟁 단계를 차례로 돌리고, 그 결과를 `ityv_state::status::evaluate`에 넘긴다. 상태는 그 함수만 정한다(VC-050).
   - genesis(1단계): 통과(호출자가 `verify_genesis`로 확인한 값만 받는다).
   - 체크포인트(2단계): 사슬을 끊은 체크포인트가 있으면 실패. 마지막 유효 체크포인트가 그 뒤의 체크포인트 프레임을 뺀 모든 프레임을 덮으면 통과(체크포인트는 자기 프레임을 덮을 수 없다). 그 밖의 덮이지 않은 프레임이 있거나 체크포인트가 없으면 실행 안 됨. 증인이 보증하지 않은 프레임 위에서는 `LOG_CONSISTENT`를 말하지 않는다.
   - 프레임(3단계): 색인이 장부 전체를 보류하지 않으면 통과.
   - 투표함(4단계)은 둘로 나눈다. 불변식은 모든 투표함의 보류이고, 보류는 `HOLD_REVIEW`로 간다. 완전성은 모든 예상 투표함에 마감이 있는지이며, 보류가 아니라 단계 결과로만 쓴다. 그래서 투표 중(마감 전)의 장부는 다른 문제가 없으면 `LOG_CONSISTENT`이고, 모든 투표함이 닫히면 `SOURCE_COMPLETENESS_CHECKED`다.
   - 기록(5단계): 기록 단계의 보류를 더한다. `UNATTESTED` 기록은 보류가 아니라 목록이다(집계 범위가 제외한다, VC-057).
   - 분쟁(9단계): 장부의 모든 분쟁 이벤트를 적용한 뒤 미해결 분쟁이 있으면 `OpenDispute`로 보류한다.
   - 승인 범위는 장부의 법적 승인에서 온다. `BALLOT_MARK`가 없으면 보고서는 수량만이 결과를 뒷받침한다고 표시한다.
   - 검증기에는 시계가 없다. 체크포인트 앵커 기한과 게시판 공표 기한은 현재 시각과 앵커 영수증이 있어야 판정되므로, 호출자가 `ityv_ledger::check_anchor`·`check_board`로 계산해 `Publications`로 넘긴다. 앵커가 충족되기 전에는 `UNVERIFIED`다.
   - 참여·집계·감사·분기·연결·소프트웨어 단계(6–8, 10–12)는 아직 없으므로 보고서가 줄 수 있는 가장 높은 상태는 `SOURCE_COMPLETENESS_CHECKED`다.

## 결과

- 장치 교체가 있었던 투표함도 보류 없이 끝까지 검증된다(변경이 장부에 순서대로 실려 있을 때).
- 기록마다 정형성 증명과 서명이 확인되고, 배치와 마감 root가 장부에서 다시 계산된다.
- 한 함수가 장부 하나의 상태를 낸다. 단계별 결과와 보류 사유는 보고서에서 그대로 볼 수 있다.

## 대안

- **변경을 장부 밖 입력으로만 받기.** 상태의 적용 시점을 정할 수 없다. 기각.
- **완전성 미달을 보류로 다루기.** 투표 중인 모든 장부가 `HOLD_REVIEW`가 되어 사다리의 `LOG_CONSISTENT` 칸이 쓸모없어진다. 기각.
