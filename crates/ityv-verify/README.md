# ityv-verify

> English summary: The ityv public verifier (ADR-0029, PROTOCOL §14). `no_std` with `alloc`, `unsafe`-free, panic-free Rust with no clock, no I/O and no unordered collections. Stage 1, `verify_genesis`, checks a genesis whole against a pin the caller obtained out of band: signatures verified here into tokens and sealed through `ityv-state`, every entry of every set re-decoded, re-sorted, re-counted and re-rooted, the sets checked against each other (references, station box lists, policies, reporting-unit counts, appointments and no appointment shared, module chambers and one device per module, trustee counts, observer tokens against roster, station and check key, distinct device identifiers, valid keys, no key half shared within a genesis state), and every amendment's state checked the same way. Stage 3, `build_index`, reads the frame stream against the verified genesis: frame chain, events by hash, canonical decoding, frames of restricted events by hash alone, the event's election, who each event concerns (against every genesis state), that a genesis, amendment or legal authorization on the ledger is the pinned one, replayed events (VC-101) and records (cast records, challenge openings) after a box's close (VC-039; a later batch attestation is a late batch close); a refused frame becomes a finding and a hold on its box, its station's boxes or the whole ledger. Verification: V1 (integration tests with real hybrid signatures, one per rule; cargo-mutants), V2 (Kani harnesses).

## 무엇인가

공개 검증기의 TCB 크레이트다. 호출자가 대역 외로 받은 genesis 핀만 믿고, 나머지는 모두 공표된 데이터에서 다시 계산한다. 명세는 `docs/spec/PROTOCOL.md` §4, §5.1, §14와 `docs/adr/ADR-0029-verifier-crate.md`이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 단계 | 명세 |
|---|---|---|
| `genesis` | 1. 핀, 서명, 모든 항목 집합 전체, 집합 사이 일치, 변경 | §4, §14 1항, ADR-0028, VC-005, VC-009, VC-014, VC-067, VC-104, VC-105 |
| `index` | 3. 프레임 고리, 이벤트 해시, 정규 이벤트, 재수록, 마감 뒤 기록 | §5.1, §14 3항, VC-010, VC-039, VC-101 |
| `error` | genesis 단계의 거부(상태, 집합, 항목 위치, 규칙) | — |

## 쓰는 법

```text
pin (관보·위원회·지정 검증자·인쇄물에서)          공표된 genesis와 모든 집합, 변경들
          │                                                │
          └──────────────▶ verify_genesis ◀────────────────┘
                                 │  Err(Error { state, set, index, rule }) → 아무것도 진행하지 않음
                                 ▼
                         VerifiedGenesis ──▶ box_entry / station_entry / roster … (상태 기계용 증명된 항목)
                                 │
     프레임 스트림, 이벤트 객체 ──▶ build_index
                                 ▼
                           LedgerIndex: events(), box_events(), findings(), box_holds(), ledger_holds()
```

보장하는 것:
- `no_std`와 `alloc`, `unsafe` 없음, 패닉 없음, 시계·입출력·무작위 순서 자료구조 없음(워크스페이스 lint 집합).
- `VerifiedGenesis`는 1단계의 모든 규칙이 통과했을 때만 있고, `LedgerIndex`는 그 위에서만 만들어진다. 상태 기계용 항목은 검증기가 전체를 확인한 집합에서만 증명된다.
- 공표된 데이터의 서명은 여기서만 검증해 토큰으로 만든다. 호출자는 토큰을 넘길 수 없다.
- 장부의 문제는 조용히 사라지지 않는다. 거부한 프레임마다 발견이 남고, 그 투표함·그 투표소의 투표함·장부 전체가 `HOLD_REVIEW`가 된다. 고리가 끊긴 곳에서만 색인이 멈춘다.

보장하지 않는 것:
- 핀이 관보에 실린 그 값이라는 것. 호출자가 genesis와 다른 출처에서 받아야 한다.
- genesis가 고정한 문서(정책, 법적 승인, 연결 목록, 릴리스 목록)의 내용, 항목이 현실과 맞는지(투표함이 실제로 있는지, 등록된 키를 그 사람이 쥐고 있는지).
- 이벤트 서명의 유효성과 이벤트별 상태 규칙(투표함·기록·참여·집계 단계), 체크포인트 사슬, 장부의 완전성. ROADMAP M5의 다음 단계다.

## 검증

- V1: `tests/genesis.rs`(규칙마다 그 규칙만 어긴 genesis를 실제 하이브리드 서명으로 만들어 거부 확인, 변경의 사슬·번호·다양성·집합), `tests/index.rs`(발견 종류와 보류 범위마다), cargo-mutants.
- V2: `kani/proofs.rs`(집합 순서 규칙, 투표함·카운터·가명 유닛의 모듈 챔버 규칙). `cargo kani -p ityv-verify`.
