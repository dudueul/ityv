# ityv 저장소 헌법 / Repository Constitution

> English summary: Non-negotiable engineering rules for every crate in the trusted computing base (TCB), the verification ladder each component must climb, supply-chain and build rules, field-device architecture, and process rules. CI enforces what can be enforced mechanically; the rest is enforced by review. Adopted by ADR-0007. Pilot entry requires V2; real binding elections require the full ladder plus every P0 gate.

상태: 채택 (ADR-0007, 2026-10-30). 이 문서를 바꾸려면 새 ADR이 필요하다.

## 0. 적용 범위

신뢰 기반(TCB)에 속하는 크레이트: 정규 인코딩, 암호 래퍼, 커밋먼트와 영지식 증명, 장부와 Merkle, 상태기계, 공개 검증기, 커밋먼트 유닛, 카운터·가명 유닛, 신뢰기관 집계. 이 크레이트들은 `crates/` 아래에 있고 `Cargo.toml`의 `[workspace.lints]`를 그대로 상속한다.

TCB 밖(UI, 대시보드, 미러, 전송 계층, 시뮬레이터)에서는 무엇이 틀려도 증거가 바뀌지 않아야 한다. TCB 밖 코드는 `apps/`와 `tools/` 아래에 두며, TCB 크레이트에서 TCB 밖 크레이트를 의존하는 것을 금지한다.

## 1. 언어 규칙 (TCB 전 크레이트)

1. `#![forbid(unsafe_code)]`. unsafe는 검증된 암호 의존성 안에만 존재하며, 그 의존성은 해시로 고정하고 cargo-vet 감사 기록을 둔다.
2. 패닉 금지. `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`, 인덱싱, 암묵적 산술을 clippy 오류로 막는다. 모든 산술은 `checked_*` 또는 명시적 `saturating_*`/`wrapping_*`를 쓰고, 선택 이유를 주석으로 남긴다. 릴리스 프로필에서도 `overflow-checks = true`, `panic = "abort"`.
3. 현장 장치 코어(커밋먼트 유닛, 카운터·가명 유닛)는 `#![no_std]`이고 힙이 없다. 모든 버퍼는 호출자가 제공하거나 고정 용량이다. 정규 인코딩 크레이트도 `no_std`, `alloc` 없음.
4. 상태기계는 전부 typestate로 쓴다. 상태는 타입, 전이는 값을 소비하는 함수. 잘못된 전이는 컴파일 오류다.
5. 모든 식별자, 해시, 수량, 인덱스는 newtype이다. 공개 API에 날것의 정수나 문자열이 나타나지 않는다.
6. 생성자는 파싱하고 검증하지 않는다. 불완전하거나 잘못된 객체는 타입으로 존재할 수 없다. `Default`를 보안 타입에 구현하지 않는다.
7. 법적 게이트(ADR-0002)는 capability 타입이다. L1 연산은 genesis 검증기만 만들 수 있는 토큰 값을 인자로 요구한다. 토큰 타입의 생성자는 비공개이며, 시뮬레이터용 생성자는 별도 크레이트의 feature가 아니라 별도 바이너리에서만 연결된다.
8. TCB 로직에 벽시계, 부동소수점, 순서가 무작위인 자료구조(`HashMap` 등)를 쓰지 않는다. 시간은 데이터로 전달되고 `u64` 구간 값으로만 다룬다. 순서가 필요하면 정렬된 벡터나 `BTreeMap`을 쓴다.
9. 정규 인코딩에 serde를 쓰지 않는다. 인코더·디코더는 손으로 쓰고 `docs/spec/ENCODING.md`를 유일한 명세로 삼으며, 왕복과 정규성에 증명을 붙인다.
10. 의존성은 vendoring하고 `Cargo.lock`을 커밋하며, 각 의존성에 cargo-vet 감사 기록을 둔다. TCB 크레이트에 `build.rs`와 검증되지 않은 proc-macro를 두지 않는다. 의존성 추가는 ADR이 아니라 PR 설명에 근거를 적고 서로 다른 소속의 리뷰어 둘이 승인한다.
11. 모든 공개 항목에 문서 주석을 둔다(`missing_docs = deny`). 모든 보안 관련 함수의 문서에는 "무엇을 증명하지 않는가"를 적는다.

### 1.1 CI가 강제하는 lint

`Cargo.toml`의 `[workspace.lints]`가 아래를 `deny`로 두며, 크레이트는 완화할 수 없다.

- rust: `unsafe_code = forbid`, `missing_docs`, `unused_must_use`, `unreachable_pub`, `trivial_casts`, `trivial_numeric_casts`.
- clippy: `all`, `pedantic`, `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`, `indexing_slicing`, `arithmetic_side_effects`, `float_arithmetic`, `cast_possible_truncation`, `cast_possible_wrap`, `cast_sign_loss`, `cast_lossless`, `wildcard_enum_match_arm`, `exit`, `std_instead_of_core`, `alloc_instead_of_core`, `missing_panics_doc`, `missing_errors_doc`, `undocumented_unsafe_blocks`.

예외는 항목 단위 `#[allow]`에 사유 주석을 붙이고 리뷰어 둘이 승인한 경우에만 허용한다. 크레이트 단위 `allow`는 금지한다. 단, TCB 밖인 통합 테스트(`tests/`)와 Kani 하네스는 파일 머리에 사유 주석을 붙인 `#![allow]`로 unwrap·expect·panic·인덱싱·산술 lint를 완화할 수 있다. Kani 하네스 모듈은 `crates/<크레이트>/kani/`에 두고 `#[cfg(kani)] #[path]`로 포함하며 `cargo kani`에서만 컴파일된다. `src/` 아래에는 어떤 완화도 없다.

## 2. 검증 사다리

| 단계 | 수단 | 적용 대상 | 통과 기준 |
|---|---|---|---|
| V1 | 속성 기반 테스트(proptest), 퍼징(cargo-fuzz), 변이 테스트(cargo-mutants) | 전 TCB 크레이트 | 모든 공개 함수에 속성 테스트, 모든 파서에 퍼징 타깃, 살아남은 변이 0 |
| V2 | Kani 유계 모델 검사 | 파서·인코더 왕복과 정규성, 산술, Merkle, 상태 불변식 | 하네스가 CI에서 통과 |
| V3 | Verus 또는 Creusot 연역 증명 | 검증기 핵심 알고리즘, 집계, share 복원, 커밋먼트 유닛 전체 | 사양과 증명이 저장소에 있고 CI에서 검사 |
| V4 | TLA+(Apalache/TLC) 모델 검사, Tamarin 프로토콜 분석 | 장부·증인·신뢰기관 프로토콜의 안전성, 비밀성, 영수증 무증명성 | 모델이 저장소에 있고 CI에서 검사 |
| V5 | 다른 언어의 독립 2차 구현과 차분 테스트 | 공개 검증기 | 같은 입력에 같은 판정 |

게이트: 시범사업(비구속) 진입은 V2까지 완료. 실제 구속력 있는 선거는 V3·V4·V5 전부와 `docs/assurance/P0_GATES.md`의 모든 게이트 통과. 어느 단계든 통과했다는 주장은 테스트·증명 ID로 연결되어야 한다.

## 3. 공급망과 빌드

1. 재현 빌드. `rust-toolchain.toml`로 툴체인을 고정하고 `cargo build --locked`만 허용한다. 서로 다른 두 빌드 기반에서 해시가 같아야 릴리스한다.
2. SBOM(CycloneDX)과 in-toto 증명을 릴리스마다 생성하고 하이브리드 서명(ML-DSA-87과 Ed25519) 릴리스 매니페스트를 둔다.
3. 빌드 중 네트워크를 차단한다. 의존성은 vendoring된 소스만 쓴다.
4. 릴리스 빌드에 디버그 모드, 우회 환경변수, 데모 플래그가 없다. 시뮬레이션과 합성 데이터는 별도 크레이트(`tools/`)에서만 만든다.
5. `cargo deny`로 라이선스·취약점·중복 버전·출처를 검사한다. 출처는 crates.io와 vendoring 디렉터리만 허용한다.

## 4. 현장 장치 구조

1. 투함 스캐너는 물리적으로 셋으로 나눈다. 해석 유닛(불신), 커밋먼트 유닛(검증, `no_std` Rust), 챔버 모듈(챔버 공급, X·Y 필수). 해석 유닛에서 커밋먼트 유닛으로는 좁은 단방향 링크만 존재한다.
2. 확인 장치도 같은 구조다. 신원 확인 유닛(불신), 카운터·가명 유닛(검증), 봉인 모듈.
3. 무선 없음. 서명 펌웨어, 롤백 방지, 측정 부팅, 물리 봉인. 허가된 주변장치와 포트만 활성화.
4. 커밋먼트 유닛과 카운터·가명 유닛은 투표 선택, 가명, 투함 ID를 처리 후 즉시 소거하며, 어떤 영속 저장소에도 쓰지 않는다. 이 성질은 V3 증명 대상이다.

## 5. 절차

1. 모든 보안 주장은 테스트·증명 ID에 연결한다. 연결 없는 주장은 문서에 쓸 수 없다.
2. 결정마다 ADR을 둔다. ADR 없이 설계를 바꾸는 PR은 거부한다.
3. 상태 어휘의 정직성을 지킨다. `LOG_CONSISTENT`를 `PAPER_AUDITED`나 `LEGAL_CERTIFIED`처럼 보이게 하는 UI·문서·API는 결함이다.
4. TCB 변경은 서로 다른 소속의 리뷰어 둘이 승인한다.
5. 어떤 산출물도 실선거 사용 가능으로 표기하지 않는다. `docs/assurance/P0_GATES.md`에 미해결 게이트가 하나라도 있으면 상태는 `NO_GO`다.
