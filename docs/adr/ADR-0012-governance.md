# ADR-0012: 거버넌스, 네 층 구조와 챔버 접근구조

> English summary: Four tiers. (1) Witnesses sign checkpoints: at least 13, quorum 9, spread across NEC, parties, courts, academia, civil society, press, a citizen-jury chamber and international observers. (2) Trustees hold opening shares under a chamber access structure: every qualifying party chamber P1..Pn (two to four parties chosen by size; ADR-0019 superseded the original two-bloc rule "X and Y mandatory, 5 of 6") is mandatory plus at least three of {J, A, C, N}; inside a chamber k-of-n; per-election distributed key generation; destruction after the dispute window; refusal halts only the cryptographic layer, never the paper count, and is public. (3) A new independent statutory body, the Independent Verification Committee, co-signs genesis and legal authorization, appoints witnesses and trustees, runs ceremonies, co-receives disputes, can order audit expansion, publishes reports with dissent, and cannot change results; independence is anchored by appointment events signed by recommending bodies. (4) Public verifiers (at least three mandated independent organizations) and courts with direct access.

- 상태: 채택. 신뢰기관 접근구조(결정 2)는 ADR-0019로 대체(2026-11-01)
- 날짜: 2026-10-30
- 관련: ADR-0003, ADR-0004, ADR-0006; `docs/governance/GOVERNANCE.md`

## 결정

설계 원리: 어느 한 기관의 정직성도 정확성에 필요하지 않고, 어느 한 기관도 혼자서는 비밀을 열 수 없으며, 어느 기관의 거부도 선거를 멈추지 못한다.

1. **증인단.** 체크포인트 서명. 13곳 이상, 정족수 9, 조직 7 이상·공급자 4 이상·지역 3 이상의 다양성. 시민 배심 챔버와 국제 참관을 포함한다. 서명 키만 보유한다.
2. **신뢰기관.** 접근구조 Γ = { S : {P1, …, Pn} ⊆ S ∧ |S ∩ {J, A, C, N}| ≥ 3 }. 정당 챔버 P1…Pn(2 ≤ n ≤ 4)은 의석 규모 기준으로 genesis에 고정한다(ADR-0019. 원래 결정은 정당 블록 X·Y 필수, 여섯 중 다섯이었다). 챔버 내부는 `k_c`-of-`n_c`(기본 2-of-3). 선관위(N)는 챔버 하나를 갖지만 거부해도 나머지로 열리고, 정당 챔버가 하나라도 빠진 어떤 조합과 합쳐도 열리지 않는다. 키는 선거마다 분산 생성(DKG)하고 파기 절차에서 파기한다. 거부는 암호 검증 층만 멈추며 공개된다.
3. **독립검증위원회.** 제278조를 확장해 설치하는 신규 독립 법정기구. 위원은 국회 교섭단체, 대법원, 학계, 장애인단체, 개인정보 전문가가 각각 추천한다. 권한: genesis와 법적 승인 객체의 공동 서명, 증인·신뢰기관 지정과 키 생성·파기 절차 주관, 분쟁 공동 접수, 감사 확대 명령, 모든 증거 접근, 소수의견 포함 보고서 공표, 이해충돌 공시. 결과를 바꿀 권한은 없다.
4. **공개 검증자와 법원.** 누구나 검증기를 돌린다. 법으로 지정된 최소 3개 독립기관은 기한 내 검증 결과를 공표할 의무가 있다. 법원은 공개원장과 종이에 직접 접근하며 판결은 `LegalDecisionRef`로 참조된다.
5. **임명 이벤트.** 모든 증인·신뢰기관·위원의 독립성은 자기 선언 문자열이 아니라 추천 기관이 서명한 임명 이벤트로 장부에 남는다.

## 결과

- 제278조 확장, 위원회 권한 조항, 서명 거부·공모·키 유출 벌칙, 공익신고자 보호, 공표 기한 위반의 법적 효과, 제181조 참관인의 키 생성·파기 절차 참관권이 법령 부속서에 들어간다.
- 위원회가 부정직해도 정확성은 암호와 종이가, 비밀은 접근구조가 지킨다. 위원회에 요구되는 신뢰는 감독의 성실성뿐이다.

## 기각한 대안

- 선관위 중심 단일 위원회. 국회 산하(당파성) 또는 대법원 산하(선거소송 심판자가 운영자가 되는 충돌).
