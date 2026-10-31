# ADR-0008: 클린룸 재설계와 K-Ballot 수확

> English summary: No code is copied from K-Ballot V9.1. Its document assets are harvested as specification: 202 threats and 153 requirements renumbered under ITYV IDs with original IDs preserved, 16 legal drafts and 18 policies as inputs, the status vocabulary and the never-auto-invalidate doctrine, the 16 P0 gates plus new gates, the 356 Python tests converted to behavioral specifications, the event dictionary, the postal triple reconciliation and the genesis diversity requirements. Project name is ityv.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0007; `docs/assurance/THREAT_HARVEST.md`, `docs/assurance/REQUIREMENTS_HARVEST.md`, `docs/assurance/BEHAVIOR_SPEC.md`

## 맥락

K-Ballot V9.1의 Rust는 컴파일된 적이 없고 헌법과 충돌한다(serde JSON 정규화, 서명 경로의 `expect`·`unwrap`, 밀리초 벽시계, 메모리 상태, HMAC 장치 인증). Python 참조 모델은 정책 논리가 훌륭하나 언어와 직렬화가 규칙 밖이다. 데이터 모델은 분리형 스트립에서 투함 시점 커밋먼트로 근본적으로 바뀐다.

## 결정

1. 코드는 한 줄도 복사하지 않는다.
2. 수확 목록: 위협·요구사항(재번호, 원 ID 보존), 법령 초안·정책(입력), 상태 어휘와 "기계 경고로 정상표를 자동 무효화하지 않는다"는 원칙, P0 게이트 16개와 신규 게이트(영수증 무증명성 형식 증명, 은닉 채널 저항, 패드 보관 사슬, 신뢰기관 접근구조 검증), Python 테스트 356개의 행동 명세화, 이벤트 사전, 관외 우편 3중 대조, genesis 구조적 다양성.
3. ID 체계: `ITYV-REQ-<도메인>-<번호>` ↔ `KB-<도메인>-<번호>`, `ITYV-THR-<번호>` ↔ `TH-/ST-/KR-/V7-` 원 ID. 추적 맵은 `docs/assurance/`에 둔다.
4. 프로젝트명은 ityv다. K-Ballot은 계보로만 인용하며, 인증 상태 혼동을 막기 위해 산출물 본문에서 K-Ballot 기능을 ityv의 기능처럼 쓰지 않는다.

## 기각한 대안

- 이식: 헌법 위반 패턴 제거 비용이 신규 작성보다 크다.
- 선별 복사: 서명 체계와 인코딩이 바뀌어 남는 것이 거의 없다.
