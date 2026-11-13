# ADR-0033: 선거인명부의 출처 서명, 다기관 보관, 개인 확인

> English summary: The election commission (NEC) must not be the sole author or the sole keeper of any fact on the voter roll. (1) Every roll fact comes from the authority that owns it and is signed by it. These authorities are: the local government head compiling from resident registration, the court registry for deaths, and the prosecution or courts for disqualifications. The roll is a deterministic merge of those signed extracts. (2) At finalization the canonical roll file goes, encrypted, to custodians in at least two branches of government: a court, the Ministry of the Interior, the independent verification committee, and the parties already entitled to roll copies. Each custodian recomputes the commitment on its own and signs a receipt on the ledger. `RollFreeze` counts only when at least three custodians, the court administration and the Ministry of the Interior among them, agree on the same roots, so a roll swapped later disagrees with copies the NEC does not hold. (3) Each entry is committed with its own salt. A voter receives their entry and inclusion proof through the existing inspection channel and checks it against the custodian-countersigned root, so a wrongful removal or move shows before finalization. (4) Per-precinct roll counts by age band are published and reconciled with the Ministry's public resident statistics. (5) After freeze, an amendment needs the source authority's signature and fresh custodian receipts. (6) A voter wrongly marked "already voted" in the integrated roll can cast a sealed contested ballot. It counts only if their pseudonym appears nowhere else, and the number of contested marks per station is published. (7) After the election, a court-ordered, all-party sample audit maps a random sample of participating pseudonyms back to roll entries, through the custodians' copy, and checks that those voters exist and were alive. This catches phantom voting, which the pseudonym ledger alone cannot. Legislative amendment 14 gives these duties a legal basis.

- 상태: 제안
- 날짜: 2026-11-03
- 관련: ADR-0003(운영 주체와 감시), ADR-0009(자격 확인과 참여 장부), ADR-0020(장치 비용과 정확도: 카운터·가명 유닛), ADR-0024(모듈 키 보관: 정당 PRF 키), ADR-0032(참여 장부 검증); `docs/spec/PROTOCOL.md` §6; 위협 ITYV-THR-068, ITYV-THR-134, ITYV-THR-135

## 맥락

ADR-0009는 명부 동결 commitment와 추가 전용 변경으로 동결 뒤의 조작을 드러낸다. 그러나 두 가지가 남는다. 하나는 동결 전, 명부를 만드는 단계의 조작이다(ITYV-THR-068 "명부 작성 단계 조작"). 다른 하나는 commitment를 만들고 보관하는 쪽이 선관위 하나라는 점이다.

암호는 책상 앞의 사람이 그 사람인지, 명부에 유령 항목이 없는지를 증명하지 못한다. 할 수 있는 일은 둘이다. 하나는 명부의 사실마다 그 사실을 가진 기관의 서명을 붙이는 것이다. 다른 하나는 같은 명부를 서로 다른 권력 기관이 각자 보관하고 같은 값에 서명하게 하는 것이다. 그러면 선관위 혼자서는 명부를 만들 수도, 바꿀 수도, 다른 명부를 보여 줄 수도 없다.

공격은 다섯 가지다.
1. **유령 항목.** 사망자·전출자·없는 사람이 명부에 남거나 더해지고, 내부자가 그 이름으로 확인과 투표를 한다. 가명 장부는 가명마다 한 번만 보므로 이것을 잡지 못한다.
2. **부당 삭제·이동.** 특정 지역·연령의 선거권자를 빼거나 다른 투표구로 옮긴다.
3. **동결 뒤 바꿔치기.** 공표한 commitment와 다른 명부로 투표를 진행하거나, 분쟁 때 다른 명부를 내놓는다.
4. **거짓 투표 표시.** 통합선거인명부의 실시간 조회에서 투표하지 않은 사람을 "투표함"으로 표시해 막는다. 표시를 빠뜨려 이중 투표를 허용하는 것은 가명 장부가 사후에 잡는다.
5. **명부 가명 root 위조.** 부분집합 검사(§6.5 넷째 항목)에 쓰는 명부 가명 root를 공표 명부와 다른 명부로 계산한다.

현행법은 이미 일부를 나눠 놓았다. 명부는 구·시·군의 장이 주민등록을 기준으로 작성해 그 전산자료 복사본을 관할 선관위에 보낸다(공직선거법 제37조). 통합선거인명부는 중앙선관위가 전산조직으로 작성하며 이중 투표를 막는 기술적 조치를 해야 한다(제44조의2). 열람(제40조)·이의신청(제41조)·확정(제44조) 절차와, 지역구 후보자·선거사무장·선거연락소장에 대한 명부 사본 교부(제46조)도 있다. 정당과 비례대표 후보자는 사본을 받지 못한다. 이 ADR은 그 구조를 암호 commitment와 다기관 보관으로 묶는다.

## 결정

1. **출처 서명(명부 사실의 원천).** 명부는 서명된 출처 자료의 결정적 병합이다. 같은 입력이면 누가 병합하든 같은 바이트가 나온다.
   - 투표구의 선거권자: 구·시·군의 장이 공직선거법 제37조①에 따라 그 투표구에 대해 작성하는 선거권자 전부(주민등록 기준 선거권자와, 지방선거에서는 외국인등록대장의 외국인 선거권자(제15조②3)까지)를 투표구별로 서명한 추출(`RollSourceExtract`, 종류 1)로 낸다. "주민등록 추출"은 이 추출의 이름이고, 주민등록표에 있는 사람만이라는 뜻이 아니다(최종 리뷰 F6). 전국 기준 시점의 주민등록 스냅숏 해시는 행정안전부가 서명한다.
   - 사망: 가족관계등록 사무를 관장하는 법원(법원행정처)이 서명한 목록.
   - 선거권 제한(공직선거법 제18조): 그 사실을 관리하는 기관(검찰, 법원)이 서명한 목록.
   - 재외선거인·국적 상실: 외교부·법무부가 서명한 목록.

   각 추출의 공개부는 출처 기관, 기준 시점, 항목 수, 항목 commitment의 정렬 집합 root다. 원문은 개인정보이므로 공개하지 않고 보관 기관(2항)만 받는다. 출처가 서명하지 않은 사실로는 명부에 넣거나 뺄 수 없다.

2. **다기관 보관(명부 수탁).** 명부가 확정되면 선관위는 정규 명부 파일(항목마다 소금을 포함, 3항)과 그 출처 추출들을 보관 기관마다 그 기관의 공개키로 암호화해 넘긴다. 보관 기관은 셋 이상이며 법원행정처(사법)와 행정안전부(행정)를 반드시 포함한다.
   - 법원행정처(사법)
   - 행정안전부(행정)
   - 독립검증위원회
   - 해당 선거에 후보자를 추천한 정당 중 보관을 신청한 정당(보관만 하고 이용하지 못한다. 현행 제46조는 정당에 사본을 주지 않는다)

   보관 기관은 받은 파일에서 출처 추출의 병합을 다시 계산한다. 그다음 항목 commitment root, 투표구별·연령대별 인원수, 명부 가명 다중집합 root(5호)를 스스로 계산해 `RollCustodyReceipt`에 서명하고 공개원장에 수록한다. 검증기는 `RollFreeze`를 다음 조건이 모두 맞을 때만 받는다.
   - genesis가 고정한 보관 기관 목록의 정족수(셋 이상) 이상이 같은 root에 서명했다.
   - 서명한 기관에 법원행정처(사법)와 행정안전부(행정)가 함께 있다(개정안 14의 제44조의3 ④).
   - 그 root가 `RollFreeze`의 값과 같다.

   하나라도 다르면 명부 단계가 `HOLD_REVIEW`이고(`RollCustodyMismatch`), 분쟁이 된다. 분쟁에서는 보관 기관들의 사본을 대조한다. 선관위의 사본만으로는 어떤 명부도 확정되지 않는다.
   - **명부 가명 root.** 부분집합 검사의 명부 가명 다중집합 root는 선관위가 아니라 보관 기관 하나 이상이 계산한다. 인증된 카운터·가명 유닛에 모든 정당 모듈을 꽂고 서로 다른 조직 참관인 앞에서, 자기 사본의 모든 `voter_id`로 계산한다(ADR-0024의 절차와 같다). 다른 보관 기관이 같은 root를 얻는지는 선택적 재계산으로 확인한다.
   - **보관과 파기.** 사본은 봉인해 선거소송 제기 기간과 소송이 끝날 때까지 보관하고, 참관 아래 파기하며 파기 기록을 수록한다. 보관 기관은 선거소송·영장·이 ADR의 감사 말고는 사본을 열람하거나 쓰지 못한다(목적 제한, 위반은 처벌).

3. **항목 commitment와 개인 확인.** 항목 `e_i`(선거권자의 법정 식별자에서 유도한 안정 핸들, 투표구, 투표양식 묶음)마다 무작위 소금 `s_i`(32바이트)를 붙여 `C_i = SHA3-512("ityv:roll:v1" ‖ 0x00 ‖ s_i ‖ canonical(e_i))`를 만든다. `C_i`의 정렬 집합 root를 공표한다. 소금은 주민등록번호처럼 경우의 수가 작은 값을 대입해 항목을 알아내는 것을 막는다.
   - 선거권자는 현행 명부 열람 경로(본인 인증)에서 자기 항목, 소금, 포함 증명을 받는다. 자기 앱이나 누구의 검증기로도 공개원장의 root(보관 기관이 함께 서명한 값)에 대조할 수 있다. 선관위가 사람마다 다른 root를 보여 줄 수 없다.
   - 열람 기간에 확인하면 부당 삭제·이동을 이의신청 기한 안에 잡는다. 공개되는 것은 root와 수뿐이므로 남의 항목은 드러나지 않는다.
   - 확인 결과를 앱이 익명으로 보고하는 선택 기능은 두지 않는다. 확인 여부 자체가 정치 성향을 드러낼 수 있기 때문이다. 이의신청만 기록된다.

4. **공개 수량 대조.** `RollFreeze`와 보관 영수증에 투표구별 인원수와 연령대별 인원수(만 18–19, 20대 … 80대, 90대, 100세 이상)를 싣는다. 작은 칸 규칙은 하위 규정에 둔다(예: 5명 미만 칸은 이웃 연령대와 합친다). 누구나 행정안전부가 공표하는 읍·면·동 주민등록 인구 통계와 대조한다. 다음은 공개 경보다.
   - 명부 수가 그 지역 선거권자 수를 넘는다.
   - 100세 이상 비율이 통계와 다르다.
   - 열람 뒤 확정까지의 사유별 증감이 크다.

   경보는 증거가 아니라 조사의 출발점이다.

5. **동결 뒤 변경.** `RollAmendment`는 다음을 모두 담아야 받는다.
   - 사유 코드.
   - 그 사유의 출처 기관 서명: 이의신청 결정은 그 결정 기관, 법원의 불복 결정은 법원, 사망은 법원행정처.
   - 변경 뒤 root와 수.
   - 보관 기관 정족수의 새 영수증.

   선관위의 서명만으로는 바뀌지 않는다. 사유별 변경 수는 공개한다.

6. **거짓 투표 표시와 이의 투표.** 실시간 조회가 "이미 투표함"이라고 답했는데 선거권자가 부인하면, 투표지를 주지 않는 대신 이의 투표를 허용한다.
   - 카운터·가명 유닛이 가명을 계산하되 `ParticipationSet`에 넣지 않는다. 대신 restricted `ContestedCheckin`(가명, 봉투 라벨)을 남긴다.
   - 선거권자는 관외사전투표처럼 봉투에 넣은 투표지를 별도 함에 넣는다(ADR-0010).
   - 선거 뒤 그 가명이 어느 `ParticipationSet`에도(이의 투표를 한 투표소의 것 포함) 없고 같은 가명으로 한 다른 이의 투표(`ContestedCheckin`)도 없으면 표시가 거짓이었다는 뜻이다. 법적 결정(`LegalDecisionRef`, 집계 효과 1 포함)으로 봉투를 연다. `ParticipationSet`에 있으면 이중 투표 시도이므로 제외하고 수사에 넘긴다. 금요일에 사전투표소 A에서 투표하고 토요일에 다시 A에서 이의 투표를 한 선거인도 그렇다(최종 리뷰 F2: 종전 문언 "다른 투표소의"는 이 경우를 두 번 세게 했다). 같은 가명의 이의 투표가 둘 이상이면 그 가명의 봉투는 모두 제외하고 수사에 넘긴다(한 선거권자가 이의 투표를 거듭한 것이다). 이의 투표는 서명된 메시지(선거, 투표소, 유닛, 가명, 봉투 라벨)로 센다: 같은 메시지를 다시 서명한 사본은 한 건이다. 한 봉투 라벨이 서로 다른 두 메시지에 쓰였으면 어느 봉투가 어느 기록인지 알 수 없으므로 그 라벨의 봉투는 모두 제외한다(장치나 내부자의 잘못, 보류). 판정은 모든 투표소의 기록, 곧 전국의 이의 투표와 대조해서 한다. 선거구마다 자기 이의 투표만 보면 두 선거구에서 한 이의 투표가 둘 다 들어갈 수 있다(개정, 2026-11-05, ADR-0040 리뷰와 최종 리뷰).
   - 투표소별 이의 투표 수를 공개한다. 한 지역에 몰리면 표시 조작의 경보다.
   - 비밀: 이의 투표 봉투는 같은 선거구의 다른 봉투들과 섞어서만 연다. 섞을 봉투가 정족수(하위 규정)보다 적으면 종이 개표에 맡기고 전자 층에서는 수만 공개한다.

7. **참여자 실재 표본 감사.** 유령 항목으로 투표하면 가명 장부에는 정상 가명으로 보인다. 그래서 선거 뒤 다음 감사를 한다.
   - 공개 시드(ADR-0011)로 참여 가명을 표본 추출한다.
   - 법원의 결정과 모든 정당 챔버의 PRF 몫이 있을 때만(§6.6과 같은 절차) 보관 기관의 사본에서 그 가명의 명부 항목을 찾는다.
   - 출처 기관이 그 사람이 선거일에 살아 있었고 그 투표구에 주민등록이 있었는지 확인한다.
   - 출력은 투표구별 이상 수와, 수사기관에 넘기는 봉인 기록이다. 표본에 든 사람이 투표했다는 사실만 다루고 무엇을 찍었는지는 다루지 않는다(가명은 투함 기록과 연결되지 않는다, VC-019). 감사가 끝나면 대응표를 지운다.

8. **검증 조건(새로).**
   - VC-107: 명부는 출처 서명된 추출의 결정적 병합이다.
   - VC-108: `RollFreeze`는 법원행정처와 행정안전부를 포함한 셋 이상의 보관 기관이 같은 root에 서명할 때만 유효하다.
   - VC-109: 명부 가명 root는 보관 기관이 계산한다.
   - VC-110: 항목마다 소금 commitment가 있고 본인 확인 경로가 있다.
   - VC-111: 동결 뒤 변경에는 출처 서명과 새 보관 영수증이 필요하다.
   - VC-112: 이의 투표와 투표소별 수를 공개한다.
   - VC-113: 참여자 실재 표본 감사는 영장과 모든 정당 몫이 있을 때만 하고, 이상 수만 공개한다.

## 결과

- 선관위 혼자서는 명부를 만들 수도, 몰래 바꿀 수도, 사람마다 다른 명부를 보여 줄 수도 없다. 출처 기관, 둘 이상의 권력에 속한 보관 기관, 정당이 함께 공모해야 한다.
- 부당 삭제·이동은 확인한 선거권자 본인이 열람 기간에 잡는다. 유령 항목은 출처 서명과 수량 대조가 줄이고, 그것으로 한 투표는 실재 표본 감사가 잡는다.
- 거짓 투표 표시로 막힌 사람도 투표할 수 있고, 표시 조작은 수로 드러난다.

## 비용과 위험

- 개인정보가 담긴 명부 사본이 여러 기관에 있게 된다. 암호화 보관, 목적 제한, 열람 기록, 처벌로 줄이지만 유출면이 넓어진다. 명부 원문은 지금도 지역구 후보자 측에 사본으로 가지만(제46조) 정당에는 가지 않는다. 그래서 새로 늘어나는 보관처는 법원행정처, 독립검증위원회, 보관을 신청한 정당이다. 명부를 누구에게 어디까지 보이는지는 법령 부속서 개정안 19가 정한다.
- 출처 기관마다 서명 체계와 추출 형식이 필요하다(행정 비용).
- 이의 투표는 투표소 절차를 늘린다. 남용(근거 없는 이의)은 이중 투표 시도가 수사 대상이라는 점으로 억제한다.
- 실재 표본 감사는 표본에 든 사람의 참여 사실을 법원·정당 앞에서 다룬다. 영장, 전 정당 몫, 이상 수만 공개, 대응표 파기로 제한한다.

## 대안

- **명부 원문 공개.** 개인정보 침해가 크다. 기각.
- **선관위 단독 commitment(현행 설계).** 동결 뒤 조작만 드러내고, 작성 단계와 바꿔치기된 공표는 막지 못한다. 보강한다.
- **명부를 블록체인에 올리기.** 공개 commitment는 이미 공개원장에 있다. 문제는 누가 그 값을 보증하느냐이므로 기술이 아니라 보관 기관의 분산이 답이다.

## 구현 현황 (2026-11-04)

- 연결(M5 2h, ADR-0040): genesis 집합 13 `RollAuthorityEntry`와 본문의 보관 정족수(`GenesisBody` 버전 8), 명부 사건 `RollSourceExtractBody`·`RollFreezeBody`·`RollCustodyReceiptBody`·`RollAmendmentBody`(`WitnessedEvent` 버전 4, 역할 11·12)와 restricted `ContestedCheckin`, `ityv-state`의 서명자·정족수 규칙, `ityv-verify`의 명부 단계(1·2·3·5항의 검증 가능한 부분, 6항의 판정; VC-107..111). 4항의 인원수는 공표하는 표의 해시로 싣는다(ADR-0040 3항).
- 남은 것: 인원수 표와 통계의 대조 도구, 부분집합 검사(§6.5), 투표소별 이의 투표 수의 공표와 봉투 혼합(VC-112), 참여자 실재 표본 감사(7항, VC-113), 보관·파기 기록, 법령 개정안 14의 조문 대조.

## 개정 1 (2026-11-13, 정당 보관 기관의 근거 정정)

처음 판은 정당을 "명부 사본을 받을 권리가 있는 정당"으로 적었다. 현행 공직선거법 제46조①은 지역구 후보자·선거사무장·선거연락소장에게만 사본을 주고 정당과 비례대표 후보자는 뺀다(2026. 11. 12. 현행본 대조). 보관 기관인 정당은 해당 선거에 후보자를 추천하고 보관을 신청한 정당이며, 보관 사본은 법령 부속서 개정안 14 제44조의3⑥의 목적 외에는 쓰지 못한다. 결정(보관 기관 셋 이상, 법원행정처와 행정안전부 필수)과 genesis 형식은 바뀌지 않는다.
