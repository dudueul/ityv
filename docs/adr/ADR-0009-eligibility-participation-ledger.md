# ADR-0009: 자격 확인과 1인 1표, 서명된 가명 참여 장부

> English summary: Cryptography cannot prove the person at the desk is who they claim, nor that the roll has no phantom entries. It can make check-in counts, issuance counts and cast-record counts externally reconcilable and detect cross-channel double check-ins. Design: roll freeze commitment with append-only changes; check-in devices at every polling place (election day included) producing signed counter events co-signed periodically by observers of different parties; pseudonyms computed by combining PRF outputs of every party chamber module (ADR-0019); the pseudonym multiset published unordered after polls close; and an absolute rule that no record ever pairs a pseudonym or identity with a cast id or ballot.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0001, ADR-0004, ADR-0005; 위협 ST-16, ST-17, V7-001..006, TH-41

## 결정

1. 선거 전 명부 동결. 선관위는 명부의 Merkle commitment(가명 + 투표구)와 투표구별 총수를 게시한다. 이후 변경은 사유가 붙은 추가 전용 이벤트로만 허용한다.
2. 모든 투표소에 확인 장치를 둔다. 선거일 투표소도 포함한다. 장치는 신원 확인 유닛(불신), 카운터·가명 유닛(검증), 정당 모듈 P1…Pn(ADR-0019)으로 분할된다.
3. 확인마다 `CheckinCounter` 이벤트를 만든다. 필드: 선거 ID, 투표소 ID, 순번, 가명, 시간 구간(15분 단위), 장치 서명, 정당 모듈 P1…Pn 서명. 일정 건수(기본 50건) 또는 2시간마다(먼저 오는 쪽) 서로 다른 정당의 참관인 둘이 토큰으로 누적 수를 공동 서명한다.
4. 가명은 정당 모듈 P1…Pn 각각이 자기 선거별 키로 계산한 PRF 출력을 결합해 만든다(`docs/spec/PROTOCOL.md` §6.4). 선관위 소프트웨어는 키를 알 수 없고 정당 모듈이 하나라도 빠지면 가명을 계산할 수 없다. 키는 각 챔버가 보유하고 선거 후 파기한다.
5. 개표 종료 후 가명 다중집합을 시간 순서 없이 공개한다. 누구나 중복(교차 채널 이중 확인)과 수량 일치(확인 수 = 교부 수 − 훼손·반납 = 투함 기록 수)를 검증한다.
6. 절대 규칙: 교부 기록, 확인 기록, 장치 로그 어디에도 투함 ID·투표지·추적코드를 가명이나 신원과 함께 남기지 않는다. 이 성질은 카운터·가명 유닛의 V3 증명 대상이며, 해석 유닛과 신원 확인 유닛이 같은 물리 장치에 있지 않도록 한다.
7. 0단계에서는 장치가 없는 투표소를 수량 공개만으로 허용한다. 목표 상태는 전 투표소 장치다.

## 결과

- 유령 명부 항목이 "투표"하려면 참관인 앞에서 물리적 확인 행위가 필요하고, 한 정당의 참관인이 공모해도 다른 정당의 참관인이 서명하지 않으면 수량이 어긋난다.
- 참여 사실의 공개 비밀은 가명 모듈의 공급망에 의존한다. 선관위는 법적으로 이미 참여 사실을 알므로 이 모듈이 지키는 것은 공개 장부에서의 비밀이다.
- 시간 구간은 15분 단위로만 기록해 투함 기록과의 시각 상관을 줄인다. 투함 기록에는 시간을 기록하지 않는다.

## 기각한 대안

- 수량만 공개: 선관위가 수량을 만들어 내면 외부에서 알 수 없다.
- 익명 자격증명(눈먼 서명 토큰): 전 국민 디지털 자격 발급이 필요해 현 단계에 맞지 않는다. 장기 연구 항목.
