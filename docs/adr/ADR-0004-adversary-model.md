# ADR-0004: 적대자 모델 T3

> English summary: Integrity must survive full collusion of the NEC, vendors, cloud providers and the postal service. Secrecy must survive that set plus any set of trustees below the structured threshold. Political parties are inside the adversary set: no party, alone or with the NEC, may decrypt; because every party chamber is mandatory (ADR-0019), a party's refusal can halt the cryptographic layer, but only that layer. Availability is not guaranteed but stoppage must be publicly visible. Eligibility cannot be protected cryptographically; it is made externally checkable through multi-party-signed counts and roll audits. T4 (everyone colludes, including paper substitution by all) is explicitly out of scope and stated as the undetectability condition.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0003, ADR-0009, ADR-0012; 위협 등록부 전체

## 결정

| 속성 | 견뎌야 하는 공모 | 남는 전제 |
|---|---|---|
| 정확성 | 선관위 전체, 공급사, 클라우드, 우정사업본부, 정당들(여럿이 함께해도) | 정직한 공개 검증자 1곳 이상, 독립 감사기구의 종이 감사, 3단계 이후 추적코드를 확인하는 유권자 일부 |
| 비밀 | 위 집합에 챔버 접근구조 미만의 신뢰기관 추가 | 접근구조는 "정당 챔버 전부(2–4개)와 J·A·C·N 중 셋 이상"(ADR-0012, ADR-0019). 선관위가 정당 챔버 하나라도 빠진 연합과 합쳐도 열 수 없음 |
| 자격 | 선관위의 명부 조작 | 암호로 막지 못함. 투표소별 확인 수를 서로 다른 정당 참관인이 서명해 공개하고 독립 명부 감사로 탐지(ADR-0009) |
| 가용성 | 보장하지 않음 | 선관위는 선거를 멈출 수 있으나 멈춤은 공개 상태로 드러남 |

정당은 적대자 집합에 포함한다. 어느 정당도 혼자서든 선관위와 손잡고서든 복호화하지 못한다. 정당 챔버는 모두 필수라 한 정당의 거부는 암호 검증 층을 멈출 수 있지만(ADR-0019), 멈추는 것은 그 층뿐이고 종이 개표는 진행되며 거부 사실은 공개된다.

## 결과

- 모든 현장 장치는 선관위 운영이므로 불신한다. 투입 전 검증, 종이 감사, 봉인 모듈 서명으로 견제한다.
- 신뢰기관·증인의 독립성은 자기 선언이 아니라 추천 기관이 서명한 임명 이벤트로 장부에 남긴다.
- 전원 공모(T4)는 "종이까지 바꿔치기되면 어떤 시스템도 탐지하지 못한다"는 조건으로 문서에 명시한다.

## 기각한 대안

- T1(외부 공격자만), T2(일부 내부자만): 문제 제기의 전제와 맞지 않는다.
