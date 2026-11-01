# 검증 사다리 / Verification Ladder

> English summary: For each component of the trusted computing base this document fixes the verification level required for a non-binding pilot (V2) and for a real binding election (the full ladder), the concrete tools, the exact properties that must be proven, and the CI job that evidences each level. A level is reached only when the named artifacts exist in the repository and run in CI; a claim without an artifact is a defect under CONSTITUTION §5.1.

상태: 초안 v0.1 (ADR-0007). 단계 정의는 CONSTITUTION §2를 따른다.

## 1. 도구

| 단계 | 도구 | 비고 |
|---|---|---|
| V1 | proptest, cargo-fuzz(libFuzzer), cargo-mutants | 변이 테스트는 살아남은 변이 0이 기준. 퍼징 타깃은 모든 파서와 검증 입구 |
| V2 | Kani | 유계 모델 검사. 하네스는 `crates/<name>/kani/` 또는 `#[cfg(kani)]` 모듈 |
| V3 | Verus(권장) 또는 Creusot | 연역 증명. 사양은 코드와 같은 저장소에 둔다 |
| V4 | Apalache 또는 TLC(TLA+), Tamarin | 분산 프로토콜 안전성·활성, 암호 프로토콜 비밀성·영수증 무증명성 |
| V5 | 독립 2차 구현, 차분 테스트 | 2차 구현 언어는 메모리 안전 언어 중 Rust가 아닌 것(권장: OCaml 또는 Go), 다른 팀이 명세만 보고 작성 |

## 2. 구성요소별 요구 단계와 증명 성질

| 구성요소 | 시범 | 실선거 | 반드시 증명할 성질 | CI 작업 |
|---|---|---|---|---|
| `ityv-encoding` | V2 | V3 | 왕복(decode∘encode = id), 정규성(canonical 입력에서 encode∘decode = id), 거부(ENCODING.md §5의 모든 위반 입력 거부), 패닉 없음, 힙 없음, 깊이 2 이하에서 스택 유계, 스키마 등록부 밖 ID 거부 | `encoding-v1`(proptest·fuzz·mutants), `encoding-v2`(kani), `encoding-v3`(verus) |
| `ityv-crypto` | V2 | V3 | 해시 도메인 분리(용도가 다르면 입력이 다름), 하이브리드 서명 AND 의미(한쪽 실패 시 실패), KEM 하이브리드 결합 정확성, Pedersen 커밋먼트 정확성과 준동형성, OR 증명 완전성·건전성(유계 모델)·알려진 답 벡터, 선형 비밀분산의 합계 복원 정확성과 접근구조 밖 복원 불가, 상수 시간 의존성 사용 | `crypto-v1`, `crypto-v2`, `crypto-v3`, `crypto-kat`(벡터) |
| `ityv-ledger` | V2 | V3 + V4 | 추가 전용(기존 프레임 불변), 순번 연속·이전 해시 결속, Merkle root 결정성, 포함·일관성 증명 완전성·건전성, 체크포인트 사슬 단조성, 찢긴 프레임 거부·비복구, 외부 앵커 불일치 거부 | `ledger-v1`, `ledger-v2`, `ledger-v3`, `ledger-tla` |
| `ityv-cunit`(커밋먼트 유닛) | V2 | V3 | 상태기계 전이 유효성(`DURABLE` 전 각인·슬립 불가), 커밋먼트가 해석 입력과 모듈 난수에만 의존, share 분할이 접근구조와 일치하고 합이 여는 값과 같음, 패드 인덱스 단조·재사용 불가·고갈 시 대체 경로 표기, 선택·투함 ID·난수의 무보존(처리 후 소거, 영속 저장 호출 부재), 힙 없음·패닉 없음 | `cunit-v1`, `cunit-v2`, `cunit-v3` |
| `ityv-state`(typestate) | V2 | V3 | 잘못된 전이 컴파일 불가(trybuild), capability 토큰 없이 L1 객체 생성 불가, 상태 어휘 자동 전환 경로 부재, 투표함·보관·체크포인트·분쟁 상태의 불변식 | `state-trybuild`, `state-v2` |
| `ityv-verify`(공개 검증기) | V2 | V3 + V5 | 명세 대비 완전성(정상 공개원장 수락)과 건전성(ENCODING·PROTOCOL 위반 거부), 체크포인트·정형성 증명·집계 재계산 정확성, 독립 2차 구현과 판정 일치, 표본 검증 모드가 전수 모드의 부분집합 | `verify-v1`, `verify-v2`, `verify-v3`, `verify-diff`(V5) |
| 카운터·가명 유닛 | V2 | V3 | 카운터 단조, 참관인 공동 서명 주기 강제, 가명이 모듈 키에만 의존, 가명과 투함 ID·추적코드의 동시 기록 경로 부재, 15분 구간 외 시각 미기록, 무보존 | `checkin-v1`, `checkin-v2`, `checkin-v3` |
| 신뢰기관 집계 | V2 | V3 + V4 | share 합산 정확성, 접근구조 밖 복원 불가, 봉인 모듈 난수 해시 대조, 관외 라벨 대조와 `CAST_NOT_RECEIVED` 제외 정확성, 자릿수 넘침 불가, 열기 이벤트 없는 복원 경로 부재 | `trustee-v1`, `trustee-v2`, `trustee-v3` |
| 프로토콜 모델 | V4(모델 존재) | V4(증명 완료) | TLA+: 장부 추가 전용·체크포인트 단조·증인 1헤드·분기 불가(≤4 비잔틴), 활성(정족수 가용 시 진행). Tamarin: 비밀성(접근구조 미만), 영수증 무증명성(투입 전 검증 포함), 은닉 채널 저항 가정의 명시 | `models-tla`, `models-tamarin` |
| 시뮬레이터 `tools/ityv-sim` | V1 | V1 | 모든 HOLD 경로 재현, 공격 주입(표갈이·중복·되감기·분기·은닉 채널·수령 누락) | `sim-scenarios` |

## 3. CI 작업과 통과 기준

| 작업 | 실행 내용 | 통과 기준 |
|---|---|---|
| `lint` | `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` | 경고 0 |
| `deny` | `cargo deny check` | 라이선스·취약점·출처 위반 0 |
| `vet` | `cargo vet` | 감사 기록 없는 의존성 0 |
| `build-locked` | `cargo build --locked --workspace` (no_std 크레이트는 `--target thumbv7em-none-eabihf` 추가) | 성공 |
| `test` | `cargo test --locked --workspace` | 실패 0 |
| `fuzz-smoke` | 각 퍼징 타깃 60초 | 크래시 0 |
| `mutants` | `cargo mutants --workspace` | 살아남은 변이 0 |
| `kani` | `cargo kani --workspace` | 하네스 전부 통과 |
| `verus` | Verus 검사 | 증명 전부 통과 |
| `models` | Apalache, Tamarin | 성질 전부 증명 |
| `diff-verify` | 2차 구현과 벡터·공개원장 차분 | 판정 불일치 0 |
| `repro` | 두 빌드 기반 해시 비교 | 일치 |

## 4. 단계 판정 규칙

- 구성요소가 어떤 단계에 있다고 말하려면 그 단계의 CI 작업이 저장소의 해당 커밋에서 통과해야 한다.
- 시범(비구속) 진입: `ityv-encoding`, `ityv-crypto`, `ityv-ledger`, `ityv-cunit`, `ityv-state`, `ityv-verify`, 카운터·가명 유닛, 신뢰기관 집계가 모두 V2, 프로토콜 모델이 존재.
- 실선거: 위 전부가 "실선거" 열의 단계에 도달하고 P0_GATES.md의 모든 게이트가 `PROVEN`.
- 어느 단계의 통과도 `NO_GO`를 바꾸지 않는다. 게이트만이 바꾼다.
