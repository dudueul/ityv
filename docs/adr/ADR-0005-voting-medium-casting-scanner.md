# ADR-0005: 투표 매체, 투함 스캐너, 투입 전 검증

> English summary: Hand-marked paper remains the sole legal record and the stamping procedure is unchanged. A casting scanner on the ballot box reads the marks, produces the cryptographic cast record and tracking code, imprints a random 192-bit cast id on the ballot as it passes through, and drops the paper into the sealed box. Voters and observers may demand a pre-cast challenge (Benaloh-style): the scanner reveals its randomness, the ballot is spoiled and reissued. The scanner is physically split into an untrusted interpretation unit, a minimal verified commitment unit, and chamber-supplied sealed modules (X and Y mandatory). Uniform across election-day and early voting. Ballot-marking devices only for accessibility; Scantegrity-style hidden codes kept as a research track for pre-printed ballots.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0001, ADR-0006, ADR-0010, ADR-0011; 위협 TH-15, ST-01, ST-05, V7-015, V7-023

## 맥락

같은 수량의 표갈이를 탐지하려면 표의 내용이 유권자의 손을 떠나기 전에 봉인되어야 한다. 후보 게재순위가 제150조로 고정되므로 순서 무작위화 방식은 쓸 수 없다. 사전투표용지는 발급기가 즉석 인쇄하므로 숨긴 잉크 층을 인쇄할 수 없다. 단일 구조를 위해 본투표와 사전투표에 같은 메커니즘이 필요하다.

## 결정

1. 기표 방식은 현행 도장 기표 그대로다. 종이가 유일한 법적 원본이다.
2. 투표함 위에 투함 스캐너를 둔다. 유권자는 기표한 투표지를 가림 봉투에 넣어 스캐너에 밀어 넣는다. 스캐너는 기표를 해석하고, 커밋먼트·정형성 증명·share·장치 서명을 만들고, 투함 ID를 투표지에 각인한 뒤 종이를 봉인된 함으로 떨어뜨린다. 3단계부터는 추적코드 슬립을 인쇄한다.
3. 투함 ID는 발급 시점이 아니라 **투함 시점**에 챔버 모듈들의 난수 기여를 해시해 생성해 각인한다. 발급기나 명부 장치가 투표지 식별자를 알 수 없게 하기 위함이다. 기존 일련번호(본투표 절취, 사전투표 미절취)는 기록에 넣지 않는다.
4. 투입 전 검증. 유권자나 참관인은 투입 전에 검증을 요구할 수 있다. 스캐너는 그 표의 커밋먼트 난수와 해석 결과를 공개하고, 해당 표는 폐기 봉투로 보내며 새 표를 교부한다. 공개값은 `ChallengeOpening` 이벤트로 장부에 남는다. 스캐너는 어느 표가 검증될지 알 수 없으므로 속이면 통계적으로 잡힌다.
5. 장치 구조는 CONSTITUTION.md §4를 따른다. 해석 유닛은 불신하고, 커밋먼트 유닛은 선택 인덱스와 투표양식 ID 몇 바이트만 받는다.
6. 투표지 인쇄기(BMD)는 장애인 접근성 전용으로만 허용하며, 그 출력도 같은 스캐너를 통과한다.
7. 사전인쇄 비밀 확인코드 방식은 본투표용 연구 트랙으로 유지하되 기본 설계가 의존하지 않는다.

## 결과

- 제157조·제158조 개정 범위에 "투입 전 스캔" 단계와 투함 ID 각인이 들어간다(LEGAL_ANNEX 1·2·3).
- 투표소마다 장치가 생기므로 P0-02(장치 인증)의 비중이 커진다. 분할 구조로 검증 대상을 커밋먼트 유닛으로 좁힌다.
- 스캐너는 표의 내용을 본다. 은닉 채널 저항을 요구사항으로 올린다(ADR-0006).
- 검증 실패(공개 난수가 커밋먼트와 불일치) 시 그 스캐너는 즉시 격리, 예비 장치로 교체, 그 장치가 만든 모든 기록은 전수 감사 대상이다(ADR-0011).
- 투표함 마감 때 종이 수, 각인된 투함 ID 수, 투함 기록 수가 정확히 같아야 하며 어긋나면 HOLD_REVIEW다.

## 기각한 대안

- BMD 기본 채택: 제159조 변경, 유권자의 인쇄 확인율 저조.
- Scantegrity II 기본 채택: 사전투표 발급기 환경 불가, 재료 연구 필요, 인쇄 신뢰 단계.
- 전자투표·인터넷투표: ADR-0001과 종이 원본 원칙에 반함.
