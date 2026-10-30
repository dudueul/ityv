# ADR-0003: 운영 주체와 감독 구조

> English summary: The National Election Commission (NEC) is the operator of record because only it may lawfully handle ballots, boxes and the roll. But the NEC is not trusted: result manipulation must be externally detectable and secrecy must be unbreakable by the NEC alone. Oversight organs are anchored in statute (ADR-0012): trustees outside the NEC, a new Independent Verification Committee, observers with signing roles, mandated public verifiers, and direct court access.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0004, ADR-0012

## 맥락

투표지·투표함·선거인명부를 다루는 법적 권한은 선관위에만 있고, 제278조의 전산화 경로도 선관위가 주체일 때만 열린다. 동시에 선관위에 대한 신뢰가 훼손되었다는 문제 제기가 있으며, 설계는 그 진위와 무관하게 성립해야 한다.

## 결정

선관위를 운영 주체로 두되, **선관위는 운영하되 신뢰받지 않는다**를 설계 원칙으로 삼는다.
- 선관위가 모든 서버와 장치를 운영해도 결과 변조는 선관위 밖에서 탐지된다.
- 선관위 단독으로는 어떤 표의 비밀도 열 수 없다.
- 선관위 서버의 응답은 증거가 아니다. 증거는 서명된 바이트와 종이뿐이며 검증기는 선관위 밖에서 돌아간다.
- 감독 구조는 ADR-0012의 네 층으로 법정화한다.

## 결과

- 봉인 모듈은 선관위가 아니라 신뢰기관이 공급한다.
- 장부의 공개 등급 이벤트는 기한 내 공표 의무가 법에 있으며, 미공표는 그 자체로 위반 사건이 된다.
- 선관위 내부자와 특정 정당의 공모를 적대자 모델에 포함한다(ADR-0004).

## 기각한 대안

- 선관위 밖 독립 기관이 병행 검증 시스템을 운영: 투표지와 투표함에 접근할 수 없어 0단계도 관찰 수준으로 축소된다.
- 혼합 운영: 책임 경계가 흐려지고 법적 근거가 없다.
