# ityv

> English summary: ityv is a research-stage design and reference implementation for a Korean election evidence and verification ecosystem. Hand-marked paper remains the sole legal record; an end-to-end verifiable cryptographic layer with receipt-freeness and everlasting privacy is layered on top; the election commission operates the system but is not trusted; oversight is anchored in statute. Nothing in this repository is certified for any real election. Status: `NO_GO`.

## 상태

**연구·설계 단계. 실제 선거 사용: NO_GO.** `docs/assurance/P0_GATES.md`의 미해결 게이트가 하나라도 있으면 이 상태는 바뀌지 않는다. 어떤 시험 통과도 인증이 아니다.

## 한 문단 요약

ityv는 손기표 종이 원본 위에 끝단 간 검증(E2E) 암호 계층을 얹는 한국 선거 증거·검증 생태계다. 투표함 위의 스캐너가 표의 선택을 정보이론적으로 숨겨지는 커밋먼트로 봉인하고, 유권자는 선택을 드러내지 않는 추적코드를 받으며, 집계는 봉인된 표로부터 누구나 검증한다. 선관위가 운영하되 신뢰받지 않도록, 키는 의석 규모로 정한 정당 2–4곳과 사법·학계·시민·선관위의 챔버에 분산되고 감독은 신규 독립 법정기구가 맡는다. 주 불변식: **시스템은 모든 표가 투표한 대로 집계되었음을 증명할 수 있어야 하며, 어떤 유권자가 어떤 선택을 했는지는 시스템 자신을 포함해 누구에게도 영원히 드러내지 않는다.**

## 읽는 순서

1. `GLOSSARY.md` 용어. 모든 문서가 이 용어를 쓴다.
2. `docs/adr/` 결정기록 14건. 왜 이렇게 설계했는지.
3. `CONSTITUTION.md` 공학 규칙과 검증 사다리.
4. `docs/spec/PROTOCOL.md` 프로토콜 명세. `docs/spec/ENCODING.md` 정규 인코딩. `docs/spec/FAILURE_CASES.md` 장애·공격 경우의 수.
5. `docs/legal/LEGAL_ANNEX.md` 법령 개정 권고와 단계 활성화. `docs/governance/GOVERNANCE.md` 거버넌스.
6. `docs/usecases/`, `docs/ballot/`, `docs/processing/` 사용례, 투표지 모양, 처리 흐름.
7. `docs/assurance/` 위협·요구사항 수확, P0 게이트, 검증 사다리, 행동 명세.
8. `crates/` 신뢰 기반 크레이트. 첫 크레이트는 `ityv-encoding`.
9. `docs/ROADMAP.md` 다음 단계.

## 빌드와 검사

```bash
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Kani 하네스는 `cargo kani -p ityv-encoding`으로 실행한다(Kani 설치 필요). CI 구성은 `.github/workflows/ci.yml`을 본다.

## 계보

K-Ballot V5–V9.1 연구물(NO-GO)의 위협 등록부, 요구사항, 법령 초안, 상태 어휘를 명세로 수확했다(ADR-0008). 코드는 복사하지 않았다.

## 라이선스

Apache-2.0. `LICENSE` 참조.
