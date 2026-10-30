# 보안 정책 / Security Policy

> English summary: Research-stage code. Never use with real voter data, real ballots or production keys. Report vulnerabilities privately to the maintainers; never post live-election data or exploitable details publicly. Every claim in this repository is scoped by the status vocabulary; `NO_GO` stands until all P0 gates close.

1. 이 저장소의 어떤 산출물도 실제 선거에 사용할 수 없다. 상태는 `NO_GO`다.
2. 실제 유권자 데이터, 실제 투표지, 운영 키를 이 저장소나 시험 환경에 넣지 않는다.
3. 취약점은 공개 이슈가 아니라 유지관리자에게 비공개로 보고한다. 실선거 데이터나 악용 가능한 세부를 공개하지 않는다.
4. 모든 보안 주장은 테스트·증명 ID에 연결되며, 연결 없는 주장은 결함으로 취급한다.
5. 상태 어휘(`UNVERIFIED`, `LOG_CONSISTENT`, `SOURCE_COMPLETENESS_CHECKED`, `CRYPTO_TALLY_VERIFIED`, `PAPER_AUDITED`, `HOLD_REVIEW`, `LEGAL_CERTIFIED`)를 서로 바꿔 쓰거나 자동 전환하는 코드와 문서는 결함이다.
