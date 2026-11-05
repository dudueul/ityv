# ADR-0040: 명부 보관의 연결 — genesis 명부 기관, 명부 사건의 인코딩, 명부 단계

> English summary: Step M5 2h Part B wires ADR-0033's roll custody into the encoding and the verifier. The genesis gets a thirteenth entry set, fixed for the election: `RollAuthorityEntry` (0x0051), one per authority and function (a source: a district head's resident extracts, the Ministry of the Interior's national snapshot, the court administration's deaths, disqualifications, overseas voters, an appeal court; a custodian: the court administration, the Ministry, the committee, a party), with its organisation and hybrid key; the body gets `custody_quorum` (at least 3, the statutory floor), and `GenesisBody` goes to version 8. The genesis stage refuses two custodians of one organisation, fewer custodians than the quorum, no court administration or Ministry custodian, no district head, and not exactly one snapshot source. The roll's events are witnessed bodies (`WitnessedEvent` version 4, roles 11 source and 12 custodian): `RollSourceExtractBody` (0x0052, the source alone), `RollFreezeBody` (0x0053, commission and committee), `RollCustodyReceiptBody` (0x0054, the custodian alone), `RollAmendmentBody` (0x0055, commission, committee and the source the reason needs). The counts per precinct and age band travel as the hash of the published counts table, since a witnessed body holds 2,048 bytes and the table's form is the sub-regulation's. The roll stage takes extracts before the freeze (one per precinct, one snapshot, one list per kind and source), the freeze only as the merge of the extracts taken (sources root and count of their body hashes, every election-day station and the snapshot present: VC-107), receipts for a freeze or amendment taken earlier (once per custodian and subject; values that differ are a custody mismatch that does not count), and amendments chained from the freeze. A roll state takes effect when the distinct custodians whose receipts agree reach the quorum with the court administration and the Ministry among them (VC-108) and one of them gave the pseudonym root (VC-109). The participation step of the status ladder needs the freeze and every amendment in effect; that is the whole legal effect (LEGAL_ANNEX amendment 14, §44-3 ④ and ⑤). Refused roll events hold the ledger (`RollEventRefused`, 74), a disagreeing receipt holds it (`RollCustodyMismatch`, 75). `ContestedCheckin` (0x0056) is restricted: the public ledger carries its frame, the public verifier counts them, and a verifier with access supplies the bodies, which are checked like a participation set and looked up in the accepted sets (elsewhere, absent, undetermined); one that does not verify holds (`ContestedCheckinInvalid`, 76). The freeze and receipts are now stamped kinds for ADR-0039's timestamp records.

- 상태: 제안
- 날짜: 2026-11-04
- 관련: ADR-0028(genesis 형식, 버전 번호), ADR-0033(명부 보관), ADR-0034·ADR-0039(시점확인), ADR-0032(참여 장부 검증); `docs/spec/PROTOCOL.md` §4.1, §6.1, §6.2, §14 3·6항, 부록 A·B; `docs/spec/ENCODING.md` §6, §8.42, §8.54, §8.76–§8.81; 법령 개정안 14; VC-107..112

## 맥락

ADR-0033은 명부의 사실마다 출처 기관이 서명하고, 명부를 서로 다른 권력의 보관 기관이 각자 보관해 같은 값에 서명하게 했다. PROTOCOL §6.1과 §14 6항은 검증기가 동결을 출처 추출과, 법원행정처와 행정안전부를 포함한 셋 이상의 보관 기관 영수증이 같은 값을 말할 때만 받게 한다. 개정안 14는 정족수의 하한(셋)을 법률에, 수를 하위 규정에 두고, 효과를 전자적 검증 상태에 한정한다(제44조의3 ④·⑤).

정해지지 않은 것: genesis 안의 기관 목록과 정족수의 자리, 명부 사건의 필드와 서명자, 인원수 표를 싣는 방법, 투표구가 genesis의 무엇인지, 사건 사이의 순서와 반복·충돌, 값이 다른 영수증의 처리, 명부 가명 root를 누가 언제 확인하는지, 변경의 사슬, 이의 투표 기록의 공개 범위와 검증, 상태 사다리와의 관계.

## 결정

1. **genesis의 명부 기관(집합 13, 고정)과 정족수.** 기관마다 `RollAuthorityEntry`(0x0051, 열쇠 `authority_id`): 기관 ID, 조직, 기능 하나, 하이브리드 공개키(`ENCODING.md` §8.76).
   - 기능 코드는 출처 1–6(주민등록 추출, 전국 스냅숏, 사망, 선거권 제한, 재외선거인·국적 상실, 불복 결정 법원)과 보관 11–14(법원행정처, 행정안전부, 독립검증위원회, 정당)다. 출처와 보관을 코드 범위로 나눠, 기능을 잘못 읽어도 출처가 보관 기관으로 셀 수 없다.
   - 항목 하나는 기능 하나다. 행정안전부는 스냅숏 출처이자 보관 기관이고 법원행정처는 사망 출처이자 보관 기관이므로, 각각 항목 둘과 키 둘을 가진다. 한 키가 두 역할에 서명하면 영수증이 출처의 서명을 겸하게 된다.
   - 고정이다(9–13번 집합). 개정안 14 제44조의3 ①이 보관 기관을 법률로 정하고, 보관 기관 목록이 선거 중에 바뀌면 바꾼 쪽이 정족수를 고른다. 구·시·군의 장도 선거 전에 정해진다.
   - 정족수 `custody_quorum`은 본문의 필드다(3 이상, 아니면 `ValueOutOfRange`). 하위 규정이 수를 정하고(개정안 14 하위규정위임), 법률의 하한은 디코더가 지킨다. 변경 본문에는 필드가 없어 바꿀 수 없다.
   - 집합과 필드가 늘어 `GenesisBody`는 버전 8이다(ADR-0028). 버전 7 본문은 받지 않는다.

2. **genesis 규칙.** genesis 단계가 집합 전체를 본다.
   - `RollCustodians`: 두 보관 기관의 조직이 같거나(한 조직이 정족수에서 둘로 셀 수 있다, 둘째 항목에서), 보관 기관이 정족수보다 적거나, 법원행정처나 행정안전부 보관 기관이 없다(집합). 어떤 명부도 효력을 가질 수 없는 genesis를 처음부터 거부한다.
   - `RollSources`: 구·시·군의 장이 없거나 스냅숏 출처가 정확히 하나가 아니다(집합). 동결의 완전성(4항)을 채울 수 없거나, 스냅숏이 둘이면 어느 것이 기준인지 정해지지 않는다. 사망·선거권 제한·재외·불복 출처는 없어도 받는다.
   - 키는 genesis의 다른 모든 키와 함께 확인한다(유효한 키, 상태마다 반쪽 겹침 없음, `InvalidKey`·`SharedKey`).

3. **명부 사건(`WitnessedEvent` 버전 4).** 역할 11은 명부 출처 기관, 12는 명부 보관 기관이다. 서명자의 `signer_id`는 기관 ID, `org_id`는 그 조직이다.
   - `RollSourceExtractBody`(0x0052, `roll-source`, 출처 기관 하나): 출처 기관, 종류, 투표구(주민등록 추출에만), 기준일, 항목 수, 항목 commitment root(스냅숏이면 그 해시). ADR-0033 1항의 공개부 그대로다.
   - `RollFreezeBody`(0x0053, `roll-freeze`, 선관위·위원회): 명부 상태(항목 root와 수, 인원수 표 해시, 명부 가명 root), 병합한 추출 본문 객체 해시들의 정렬 집합 root와 수, 동결 시점.
   - `RollCustodyReceiptBody`(0x0054, `roll-receipt`, 보관 기관 하나): 보관 기관, 답하는 본문의 객체 해시, 다시 계산한 명부 상태(명부 가명 root는 선택), 동결에 답하면 출처 root.
   - `RollAmendmentBody`(0x0055, `roll-amendment`, 선관위·위원회·출처 기관 하나): 번호, 앞 본문 해시, 사유(1 이의신청 결정, 2 불복 결정, 3 사망, 4 선거권 제한, 5 재외·국적 상실), 출처 기관, 근거 문서 해시, 변경 뒤 명부 상태, 수록 시점.
   - **인원수는 표의 해시로 싣는다.** ADR-0033 4항과 PROTOCOL §6.1은 동결과 영수증에 투표구별·연령대별 인원수를 "싣는다". 사람이 서명하는 본문은 2,048바이트 이하이고(§8.42) 투표구는 전국에 만 단위이며, 표의 형식과 작은 칸 규칙은 하위 규정이다(개정안 14). 그래서 공표하는 표의 해시(`counts_hash`)를 싣고, 보관 기관은 표를 스스로 계산해 같은 해시에 서명한다. 누구나 공표된 표를 그 해시와, 행정안전부 통계와 대조한다.
   - 사유의 출처는 고정이다: 이의신청 결정은 그 결정 기관인 구·시·군의 장(주민등록 추출 기능), 불복 결정은 법원, 사망은 법원행정처, 선거권 제한은 검찰·법원, 재외·국적 상실은 외교부·법무부(ADR-0033 5항).

4. **명부 단계(`ityv-verify`의 `verify_roll`).** 프레임 순서로 읽는다.
   - **추출**: 서명자가 본문이 가리키는 출처 기관이고 그 기능이 추출의 종류다(`ityv_state::admit_extract`). 투표구는 그 프레임에 시행 중인 genesis 상태의 선거일 투표소다(사전투표소에는 투표구 명부가 없다). 동결 뒤의 추출은 받지 않는다(동결 뒤에는 변경만, ADR-0033 5항). 대상(투표구, 스냅숏, 종류·기관)마다 하나다.
   - **동결**: 선관위·위원회 서명. 선거에 하나다. 그 앞에 받아들여진 추출들이 동결 프레임에 시행 중인 상태의 모든 선거일 투표소와 스냅숏을 덮어야 하고(`Incomplete`), 본문의 출처 root와 수가 그 추출 본문 해시들의 정렬 집합 root와 수여야 한다(`Sources`, VC-107). 받지 못한 추출은 병합에 들어가지 않는다.
   - **영수증**: 서명자가 본문이 가리키는 보관 기관이다(`admit_receipt`). 대상은 앞 프레임에서 받아들여진 동결이나 변경이다. 동결에 답하는 영수증은 출처 root를 싣고 변경에 답하는 영수증은 싣지 않는다(`Subject`). 보관 기관마다 대상마다 하나다. 대체된 상태(변경 전의 동결)에 늦게 온 영수증도 그 상태에 센다.
   - **값이 다른 영수증**: 항목 root와 수, 인원수 표 해시, 출처 root, 실었다면 명부 가명 root 가운데 하나라도 대상과 다르면 `CustodyMismatch`로 남고 세지 않으며 장부를 보류한다(`RollCustodyMismatch`). 영수증 자체는 받아들인 것이므로 같은 기관의 둘째 영수증은 충돌이다. 고친 값은 분쟁에서 사본을 대조해 정한다(ADR-0033 2항).
   - **변경**: 선관위·위원회·사유의 출처 기관 서명(`admit_amendment`, VC-111). 동결 뒤, 다음 번호, 앞 본문 해시 사슬이어야 한다(`Chain`).
   - **효력**: 상태(동결, 변경마다)는 값이 같은 영수증의 서로 다른 보관 기관이 genesis의 `custody_quorum` 이상이고 법원행정처와 행정안전부를 포함하며(`ityv_state::custody_quorum`, VC-108), 그 가운데 하나 이상이 명부 가명 root를 실었을 때 효력이 있다(VC-109). 변경 뒤의 명부 가명 root도 보관 기관이 계산해야 부분집합 검사(§6.5)가 선관위의 값에 기대지 않는다. 단계는 동결과 모든 변경이 효력이 있을 때 완전하다.
   - 같은 대상의 같은 본문(다른 서명 바이트)은 반복(`Repeated`), 다른 본문은 충돌(`Conflict`)이다. 같은 객체를 다시 실은 프레임은 색인이 거부한다(VC-101).

5. **보류와 완전성.** 받을 수 없는 명부 사건은 모두 목록에 남고 장부 전체를 보류한다(`RollEventRefused`, 74). 값이 다른 영수증도 보류다(`RollCustodyMismatch`, 75). 효력 있는 동결이나 변경이 아직 없는 것은 보류가 아니라 완전성 미달이다. 14절의 "아직 없는 것은 완전성 미달"과 같고, 명부는 투표 전에 정해지지만 장부는 그 뒤에도 자란다.

6. **상태 사다리.** 14절 6단계(참여 장부)는 참여 단계의 완전성과 명부 단계의 완전성이 모두 있어야 통과한다. 명부가 효력을 얻지 못한 장부는 `SOURCE_COMPLETENESS_CHECKED`에 머물고 `CRYPTO_TALLY_VERIFIED`에 이르지 않는다. 이것이 명부 단계의 법적 효과 전부다. 제44조의3 ④·⑤는 그런 명부·변경이 있는 선거구의 전자적 검증 상태를 확정할 수 없다고 할 뿐, 명부나 변경의 법적 효력을 전자서명에 걸지 않는다. 검증기는 명부가 적법한지 판정하지 않는다. 장부 하나가 선거 하나이므로 선거구 단위가 아니라 장부 단위로 판정한다.

7. **이의 투표 기록(`ContestedCheckin`, 0x0056, restricted).** 선거, 투표소, 유닛, 가명, 봉투 라벨(필드 1–5)에 유닛과 정당 모듈이 서명한다(`contested-checkin`, `ParticipationSet`과 같은 방식). 순번과 시각은 싣지 않는다. 가명 옆의 시각은 확인 순서를 드러낸다(VC-084).
   - 공개 장부는 프레임(객체 해시)만 싣는다(`OPAQUE_SCHEMAS`). 공개 검증기는 프레임 수를 센다(투표소별 수는 열람 권한이 있는 검증기가 공표한다, VC-112).
   - 열람 권한이 있는 검증기는 본문을 `RollInput`으로 넘긴다(`verify_ledger_full`). 장부 프레임이 가리키는 본문마다 선거, 그 프레임의 genesis 상태의 투표소, 그 프레임까지의 상태에서 그 투표소의 유닛(본문이 가리키는 것, 사용 중 또는 예비)과 그 유닛의 정당 모듈(정당마다 하나, 챔버 순서)의 키를 확인한다. 검증되면 가명을 받아들여진 `ParticipationSet`에서 찾아 그 투표소(이중 투표 시도), 없음(모든 투표소의 집합이 들어온 뒤), 미정(아직 들어오지 않은 집합이 있을 때)을 보고한다.
   - 이의 투표는 메시지(가명, 봉투 라벨) 하나가 한 건이다. 같은 메시지를 다시 서명한 사본(하이브리드 서명은 매번 다르므로 다른 객체)은 첫 프레임의 것과 한 건이다(`Copy`). 첫 메시지들 가운데 한 가명이 라벨 둘 이상에 있으면 모두 `Repeated`, 한 라벨이 가명 둘 이상에 있으면 모두 `LabelReused`이고, 어느 쪽이든 그 봉투는 개표에서 빠지며 장부를 보류한다(`ContestedRepeated`, 77). 76과 나눈 까닭: 76은 본문이 검증되지 않는다(증거의 결함)는 뜻이고, 77은 검증된 기록이 한 선거권자의 거듭된 이의 투표나 두 사람의 한 봉투를 보인다(수사기관에 통보할 사실, 법령 개정안 14, 제44조의5 ②)는 뜻이라 대응하는 사람이 다르다. 투표소별 수(VC-112)는 사본을 한 번만 센다(`RollStage::contested_counts`).
   - 검증되지 않는 본문은 장부를 보류한다(`ContestedCheckinInvalid`, 76). 장부에 없는 본문은 보고만 하고 보류하지 않는다(넘긴 쪽의 착오이지 장부의 문제가 아니다).
   - 봉투를 여는 것은 법적 결정(`LegalDecisionRef`, 집계 효과)이다. 검증기는 그 결정의 근거가 되는 판정만 보고한다(ADR-0033 6항, VC-112).

8. **개인 확인(VC-110).** 검증기는 `roll_entry_commitment(salt, entry)` = `SHA3-512("ityv:roll:v1" ‖ 0x00 ‖ salt ‖ entry)`와 `roll_entry_included(root, count, index, commitment, proof)`(정렬 집합 root에 대한 RFC 9162 포함 증명)를 API로 낸다. 항목의 정규 형식은 하위 규정이다. 비교할 root는 효력이 있는 명부 상태의 것(`RollStage::roll`)이다.

9. **시점확인.** 동결과 보관 영수증은 ADR-0039의 시점확인 대상이다(ADR-0034 2항, 개정안 15 제278조의7 ①). 그 `WitnessedEvent`를 가리키는 `TimestampRecord`를 받는다. 추출과 변경은 대상이 아니다(`TimestampProblem::Target`). 토큰이 있어야 효력이 있다는 규칙은 두지 않는다(아래 한계).

10. **API.** `ityv-encoding`: 위 스키마, `RollState`, 코드들, `MIN_CUSTODY_QUORUM`, purpose 상수. `ityv-state`: `admit_extract`, `admit_freeze`, `admit_receipt`, `admit_amendment`, `custody_quorum`, 보류 74–76. `ityv-verify`: `verify_roll`, `RollStage`과 그 보고형, `RollInput`, `verify_ledger_full`, `Report::roll`, `ParticipationStage::pseudonym_station`, `VerifiedGenesis::roll_authorities`·`roll_authority`·`roll_authority_entry`.

## 결과

- 선관위 혼자서는 명부를 동결하거나 바꿀 수 없다는 것을 누구나 공개 장부에서 확인한다. 출처 없는 추출, 출처가 말하지 않은 병합, 두 부처가 빠지거나 정족수에 못 미친 동결, 출처 서명 없는 변경은 상태 사다리를 멈춘다.
- 값이 다른 영수증은 장부 안에서 드러나고, 어느 기관의 사본이 다른지 목록으로 남는다.
- 이의 투표의 판정이 열람 권한이 있는 검증기마다 같은 규칙으로 나온다.

## 한계

- 추출이 등록부와 맞는지(출처가 서명한다), 병합이 어떤 항목을 주는지(보관 기관이 다시 계산한다), 추출과 스냅숏의 기준일이 같은지, 구·시·군의 장이 자기 관할 투표구에만 서명하는지(genesis에 투표구와 장의 대응이 없다)는 검증기가 보지 않는다. 대응을 genesis에 둘지는 하위 규정과 함께 정한다.
- 명부 가명 root가 인증된 유닛과 모든 정당 모듈로 참관인 앞에서 계산되었다는 것은 보관 기관의 영수증이 증언한다. 검증기는 그 증언이 있다는 것만 본다.
- 인원수 표와 행정안전부 통계의 대조, 부분집합 검사(§6.5 넷째 항목), 투표소별 이의 투표 수의 공표, 참여자 실재 표본 감사(VC-113)는 이 단계에 없다.
- 동결과 영수증의 시점확인 토큰은 있으면 검증하지만 요구하지 않는다. 개정안 15가 기한을 규칙에 맡겼고, 그 기한이 정해지면 체크포인트의 앵커 기한(ADR-0039 7항)처럼 판정한다.
- 이의 투표 기록이 장부에 있어야 할 만큼 다 있는지는 공개 장부로 알 수 없다(본문이 비공개).

## 기각한 대안

- **인원수 표를 본문에 싣기.** 2,048바이트 한도와 만 단위 투표구 때문에 불가능하고, 표 형식이 하위 규정이라 인코딩에 고정하면 규정과 어긋난다.
- **보관 기관 목록을 변경할 수 있게 하기.** 법률이 정한 기관이고, 선거 중에 바꿀 수 있으면 정족수를 맞출 기관을 고를 수 있다.
- **정족수를 항목 수로 세기.** 같은 조직의 항목 둘이 둘로 센다. 조직이 서로 다르도록 genesis에서 막고, 영수증은 기관마다 하나로 센다.
- **모든 영수증에 명부 가명 root 요구.** 가명 계산은 모든 정당 모듈과 참관인이 필요한 절차라 보관 기관마다 요구하면 비용이 크다. ADR-0033은 하나 이상으로 정했다.
- **효력 없는 명부를 보류로.** 동결 전과 영수증이 모이는 동안의 장부도 정상이다. 보류는 잘못된 것이 있을 때만 쓴다.
- **값이 다른 영수증을 거부로.** 거부하면 같은 기관이 고친 영수증을 다시 낼 수 있어 불일치가 지워진다. 받아서 불일치로 남기고, 둘째 영수증은 충돌이다.

## 연결되는 검증

- `crates/ityv-encoding/tests/m5_roll.rs`: 모든 스키마의 왕복, 생성자와 디코더 규칙, 위치까지 적은 거부 벡터, 서명자 조합, 코드표, 속성 테스트. Kani `roll_codes_are_exact`, 역할 코드 1–12.
- `crates/ityv-state/src/roll.rs` 단위 테스트(실제 하이브리드 서명): 네 사건의 서명자·기능·조직·키. Kani `custody_quorum_is_exact`.
- `crates/ityv-verify/tests/roll.rs`(실제 서명): 효력, 정족수의 수와 두 부처와 명부 가명 root, 모든 거부, 값이 다른 영수증, 변경의 사슬, 이의 투표 기록의 판정, 항목 commitment 벡터와 포함 증명. `tests/genesis.rs`: genesis 규칙. `tests/tally.rs`: 상태 사다리와 보류. `tests/timestamp.rs`: 동결·영수증의 시점확인.
