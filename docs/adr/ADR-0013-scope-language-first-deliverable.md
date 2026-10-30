# ADR-0013: 범위, 문서 언어, 첫 산출물

> English summary: Scope covers the full lifecycle (roll freeze, check-in, issuance, casting, custody, postal return, counting, tally, audit, dispute, publication) and all channels: election day, in-district and out-of-district early voting, overseas (IN_PERSON_SCAN), home and shipboard voting (RECEIPT_SCAN with explicitly lower assurance). Official documents are Korean with an English summary; code and machine-readable specs use English identifiers. First deliverable (D3): constitution and CI gates, 13 ADRs, protocol spec v0.1 with the one-time-pad chapter, legal annex, governance, use cases with ballot layout and processing flows, assurance harvest plan, and the first verified crate ityv-encoding.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: 전 ADR; `docs/ROADMAP.md`

## 결정

1. 범위: 명부 동결부터 공표까지 전 수명주기, 전 투표 경로. 거소·선상은 `RECEIPT_SCAN` 프로필로 보장 수준이 낮음을 명시한다.
2. 언어: 공식 문서는 한국어, 각 문서 머리에 영어 요약. 코드·식별자·기계가 읽는 명세는 영어.
3. 첫 산출물: 헌법과 CI, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, 정규 인코딩 크레이트(V1·V2).
4. 후속: 암호 래퍼, 장부, 커밋먼트, 상태기계, 검증기, 시뮬레이터 크레이트, TLA+·Tamarin 모델. `docs/ROADMAP.md`.
