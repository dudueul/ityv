# ADR-0011: 감사, 공개 난수, 분쟁

> English summary: Ballot-level comparison risk-limiting audit with record-first sampling: draw records from the board with public randomness, trustees open only those, auditors find the paper by cast id and compare. No public token tags exist, so no coercion channel is created. Initial risk limit recommendation 1% for national contests with escalation to full hand count; the hand count is the legal result. Seed = SHA3-512(dice ceremony transcript || public beacon round || final checkpoint hash) after the manifest is frozen. Tracking-code slips carry a hybrid device signature so inclusion disputes split into system failure (valid signature, record missing: HOLD the box) and forged slip (reject). Disputes are limited to inclusion because of receipt-freeness. Intake is joint NEC + Independent Verification Committee; outcomes are appended to the ledger; a failed pre-cast challenge quarantines the scanner and triggers 100% audit of its records.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0005, ADR-0006, ADR-0012; 위협 TH-47, TH-50, ST-37..41, V7-061..070

## 결정

### 감사
1. 표 단위 비교 감사, 기록 우선 표본추출. 순서: 명세 동결 → 시드 생성 → 기록 추첨 → 신뢰기관의 표본 열기(선택과 투함 ID) → 해당 투표함의 종이를 투함 ID로 찾아 기표 대조 → 불일치 수에 따라 확대.
2. 종이에서 기록을 찾는 방식은 쓰지 않는다. 공개 태그가 추적코드와 종이를 잇는 강요 통로가 되기 때문이다.
3. 위험 한도는 법령이 정하되 초기 권고는 전국 선거 1%다. 불일치가 누적되면 전면 수검표로 확대하고 수검표 결과가 법적 결과다. 기록은 바꿔치기 패턴을 입증하는 증거로 법원이 다룬다.
4. 검증 실패 스캐너의 기록은 전수 감사한다.

### 난수
시드 = `SHA3-512("ityv:seed:v1" ‖ 주사위 의식 기록 해시 ‖ 공개 분산 난수 비콘 회차 값 ‖ 최종 체크포인트 해시)`. 의식은 정당 참관 아래 공개 기록하고, 명세와 추출 규칙은 시드 생성 전에 동결·게시한다. 누구나 표본을 재계산할 수 있다.

### 분쟁
1. 슬립은 추적코드, 투표소 ID, 시간 구간과 커밋먼트 유닛의 하이브리드 서명을 담는다.
2. "내 코드가 게시판에 없다": 서명이 유효하면 시스템 장애다. 해당 투표함을 즉시 `HOLD_REVIEW`로 두고 종이 수와 기록 수를 대조하는 조사로 간다. 서명이 없거나 틀리면 위조 슬립으로 기각한다.
3. "내 표 내용이 다르다"는 주장은 영수증 무증명성 때문에 성립 자체가 불가능하며 접수하지 않는다. 분쟁은 포함 여부에 한정된다.
4. 접수처는 선관위와 독립검증위원회의 공동 관할이다. 처리 결과는 `DisputeEvent`로 장부에 남고 법적 결정은 `LegalDecisionRef`로 참조된다. 선거소청·소송으로 이어지는 기한을 법령에 둔다.
5. 어떤 기계 경고도 정상표를 자동 무효화하지 않는다.
