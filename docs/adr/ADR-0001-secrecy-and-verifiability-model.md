# ADR-0001: 비밀성과 검증성 모델

> English summary: ityv is an end-to-end verifiable system with receipt-freeness. Master invariant: the system can prove every vote was counted as cast, and can never reveal, even to itself, which voter cast which choice, for the lifetime of the records. Literal voter-choice linkage is rejected as unconstitutional; secrecy-only evidence (the K-Ballot design) is rejected because it cannot detect equal-count ballot substitution or let a voter confirm inclusion.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0005, ADR-0006, ADR-0011; K-Ballot P0-01, P0-16

## 맥락

"누가 누구에게 투표했는지를 유지한다"는 요구는 세 가지로 읽힐 수 있다. (A) 유권자와 선택을 문자 그대로 연결해 저장한다. (B) 시스템은 선택을 전혀 알지 못하고 자격·수량·보관만 추적한다. (C) 선택은 투함 시점에 암호학적으로 봉인되고, 유권자는 자기 표의 포함만 확인할 수 있으며, 누구도 제3자에게 자기 선택을 증명할 수 없고, 집계는 봉인된 표로부터 공개 검증된다.

(A)는 헌법 제41조①·제67조①의 비밀선거와 공직선거법 제167조에 반하고, 매표와 강요의 통로가 된다. 제167조③은 기표한 투표지를 공개하면 그 표를 무효로 하므로, 유권자가 들고 나가는 어떤 확인 수단도 선택을 드러낼 수 없어야 한다. (B)는 K-Ballot V9.1의 설계이며, 분리된 credential 스트립이 종이 내용과 무관하기 때문에 같은 수량의 표갈이를 탐지할 수 없고(P0-01) 유권자가 자기 표의 집계를 확인할 수 없다.

## 결정

(C)를 채택한다. 주 불변식: **시스템은 모든 표가 투표한 대로 집계되었음을 증명할 수 있어야 하며, 어떤 유권자가 어떤 선택을 했는지는 시스템 자신을 포함해 누구에게도, 기록이 존재하는 한 영원히 드러내지 않는다.**

세 성질을 분리해 각각 보장한다.
- 투표한 대로 기록됨(cast-as-intended): 투입 전 검증(ADR-0005)과 종이 감사(ADR-0011).
- 기록된 대로 보존됨(recorded-as-cast): 추적코드의 포함 검증과 증인 체크포인트.
- 보존된 대로 집계됨(tallied-as-recorded): 커밋먼트의 준동형 합계와 공개 검증(ADR-0006).

영수증 무증명성(receipt-freeness)은 법적 요건으로 취급한다. 추적코드는 선택에 관한 어떤 정보도 담지 않으며, 분쟁은 포함 여부에만 한정된다.

## 결과

- 공개원장에 올라가는 어떤 기록도 선택을 드러낼 수 없어야 하며, 이는 기록의 수명 전체에 걸쳐 성립해야 한다(ADR-0006의 영구 비밀성).
- 유권자 신원과 투함 기록을 잇는 어떤 로그도 존재해서는 안 된다(ADR-0009, ADR-0010).
- 종이 원본은 법적 결과이며 암호 기록은 검증 보조수단이다(ADR-0002, ADR-0011).

## 기각한 대안

- (A) 문자 그대로의 연결: 위헌, 강요 통로.
- (B) 비밀성 전용 증거 계층: P0-01·P0-16을 닫지 못함.

## 연결되는 검증

- Tamarin 모델(V4): 비밀성, 영수증 무증명성. `docs/assurance/VERIFICATION_LADDER.md` V4 항목.
- 요구사항 ITYV-REQ-BAL-002(확인증의 비연결성, KB-BAL-002 계승).
