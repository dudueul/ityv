# ADR-0007: 공학 헌법과 검증 사다리

> English summary: Adopts CONSTITUTION.md in full. Rust for the entire TCB with forbid(unsafe), no panics, no_std device cores, typestate machines, newtypes, parse-don't-validate, capability-typed legal gates, no wall-clock or floats in the TCB, hand-written canonical encoding without serde, vendored and vetted dependencies. Verification ladder V1 (property/fuzz/mutation), V2 (Kani), V3 (Verus/Creusot), V4 (TLA+/Tamarin), V5 (independent second implementation). Pilot entry gate is V2; real elections require the maximum level.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: CONSTITUTION.md, ADR-0002, ADR-0013

## 결정

1. `CONSTITUTION.md`를 전부 채택한다.
2. 시범사업(비구속) 진입 조건은 V2까지 완료다.
3. 실제 구속력 있는 선거는 V3·V4·V5 전부와 모든 P0 게이트 통과를 요구한다.
4. 첫 크레이트인 정규 인코딩을 V1·V2를 갖춘 본보기로 완성해 이후 크레이트의 기준으로 삼는다.

## 결과

- 저장소 생성 시점부터 CI가 lint, 의존성 감사, 재현 빌드 설정, 속성 테스트, Kani를 강제한다.
- Kani·TLA+·Tamarin·Verus가 설치되지 않은 환경에서는 하네스와 모델을 작성해 두고 CI에서 실행한다.
