# ityv-ledger

> English summary: The evidence-ledger crate of ityv (ADR-0016). `no_std`, allocation-free, `unsafe`-free, panic-free Rust implementing the RFC 9162-shaped SHA3-512 Merkle tree with an incremental accumulator and fixed-size inclusion and consistency proofs, the frame chain rules and the on-disk frame stream with torn-tail isolation, the `SignedCheckpoint` object (schema 0x0010) with successor validation and the witness's signing state machine (the `HonestSign` rule of the TLA+ model), the witness quorum and diversity policy, and the publication-deadline arithmetic. Hashing and signatures go through `ityv-crypto`; the crate owns no storage, network or clock. Verification: V1 (independent RFC 9162 known answers computed with Python, property tests, regression vectors, mutation testing), V2 (Kani harnesses on the tree algorithms, the policy rule, the deadlines and the parser), V4 (`docs/models/LedgerWitness.tla`). V3 for the Merkle algorithms is an open item.

## 무엇인가

증거 장부(PROTOCOL.md §5)의 순수 규칙을 담는 TCB 크레이트다. 명세는 `docs/spec/PROTOCOL.md` §5, `docs/spec/ENCODING.md` §8.1·§8.3·§8.4, `docs/adr/ADR-0016-ledger-crate.md`이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `merkle` | RFC 9162 트리 모양의 SHA3-512 Merkle 트리, 누산기(봉우리 ≤ 40), 포함·일관성 증명의 생성과 검증, 정렬 집합 root | PROTOCOL.md §5.3, ADR-0016 §2 |
| `frame` | 프레임 사슬 규칙(`link`, `next_frame`, `ChainState`), 디스크 스트림 파서(`FrameStream`)와 찢어진 꼬리 격리, 재전송 분류 | PROTOCOL.md §5.1, ADR-0016 §3 |
| `checkpoint` | `SignedCheckpoint`(0x0010), 후속 체크포인트 검증(`validate_successor`), 증인 기억과 서명 전 판정(`WitnessMemory::may_sign`) | PROTOCOL.md §5.4, ENCODING.md §8.4, ADR-0016 §4–5 |
| `policy` | 정족수 프로필(`2q − n > f`), 명부, 정족수·다양성 판정(`evaluate`) | PROTOCOL.md §5.4 VC-014, ADR-0012, ADR-0016 §6 |
| `publication` | 앵커 기한(+4 구간)과 게시판 공표 기한(+96 구간) | PROTOCOL.md §5.5, ADR-0016 §7 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음(워크스페이스 lint 집합, Kani 하네스).
- 모든 검증은 `bool`이 아니라 이 크레이트만 만들 수 있는 `Verified<T>` 토큰을 돌려주며, `T`는 검증 입력을 참조한다(`Included`, `Consistent`, `Linked`, `Successor`, `Signable`, `Published`).
- 고정 용량: 잎 2^40, 포함 증명 길이 40, 일관성 증명 길이 41, 누산기 봉우리 40, 증인·서명 64. 입력 크기에 따라 커지는 것이 없다.
- 증인 규칙 `may_sign`은 `docs/models/LedgerWitness.tla`의 `HonestSign`과 같다: 마지막으로 서명한 순번의 다음이고, 서명한 트리를 확장하며(일관성 증명), 이전 해시·genesis·두 집합 root가 맞을 때만 서명 가능 토큰이 나오고, 토큰을 쓰면 기억이 전진한다(VC-012, VC-013).
- 공표된 `SignedCheckpoint`는 모든 서명이 명부 키로 검증되고 명부 밖·중복 ID가 없으며 정족수와 다양성을 만족할 때만 유효하다. 하나라도 틀리면 객체 전체가 무효다(닫힌 실패).
- 모든 공개 객체는 `ityv-encoding`의 `Encode`/`Decode`를 구현한다.

보장하지 않는 것(미증명 항목):
- 저장·입출력·내구성·상호배제는 호스트의 책임이다(단일 작성자 계약, P0-13). 증인은 서명을 내보내기 전에 `WitnessMemory`를 영속 저장해야 한다; 기억을 잃은 증인은 같은 순번의 분기에 서명하도록 유도될 수 있다.
- 이벤트 본문의 진실성, 마감 이후의 상태 전이(M4), genesis 파싱, 검증기 파이프라인(M5)은 범위 밖이다.
- 빈 트리에서 출발하는 일관성 증명은 비어 있고 새 root를 제약하지 않는다(RFC 9162). 첫 체크포인트의 root는 외부 핀과 검증기의 전체 재계산이 보증한다.
- Merkle 알고리즘의 연역 증명(V3)은 아직 없다.

## 해시 규칙

| 노드 | 입력 |
|---|---|
| 리프 | `SHA3-512(0x00 ‖ 리프 입력)` (리프 입력 = 프레임 해시 또는 이벤트 해시) |
| 내부 노드 | `SHA3-512(0x01 ‖ 왼쪽 ‖ 오른쪽)` |
| 빈 트리 | `SHA3-512("")` = `EMPTY_ROOT` |
| 정렬 집합 root | 리프 입력을 바이트 오름차순으로 정렬(중복 거부)한 트리의 root; 빈 집합은 `EMPTY_ROOT` |

트리 모양은 RFC 9162 §2.1(왼쪽 부분 트리가 `n`보다 작은 가장 큰 2의 거듭제곱). 포함 증명은 §2.1.3, 일관성 증명은 §2.1.4의 알고리즘 그대로이며, 같은 크기 사이의 증명은 비어 있고 root가 같아야 하고, 크기 0에서 출발하는 증명은 비어 있다.

## 바이트 배치

모두 `ityv-encoding` 고정폭 규칙이다.

| 객체 | 인코딩 |
|---|---|
| `Accumulator` | `size: u64` ‖ `peaks: Array<Hash512, 40>`(정확히 `popcount(size)`개, 큰 부분 트리부터) |
| `InclusionProof` | `Array<Hash512, 40>`(아래에서 위로) |
| `ConsistencyProof` | `Array<Hash512, 41>` |
| `ChainHead` | `election_id: Ident<64>` ‖ `seq: u64` ‖ `hash: Hash512` |
| `ChainState` | `head: Option<ChainHead>` ‖ `accumulator: Accumulator`(머리 순번 = 누산기 크기) |
| 디스크 스트림 레코드 | `u32_be len` ‖ `LedgerFrame` 객체 바이트(161 ≤ len ≤ 224) |
| `SignedCheckpoint`(0x0010) | `body: Bytes<4096>`(인코딩된 `CheckpointBody` 객체) ‖ `signatures: Array<{witness_id: Ident<64>, signature: [u8; 4691]}, 64>`(ID 오름차순, 중복 없음) |
| `LastSigned` | `seq: u64` ‖ `tree_size: u64` ‖ `root_hash: Hash512` ‖ `body_hash: Hash512` |
| `WitnessMemory` | `Option<LastSigned>` |

## API

```rust
use ityv_ledger::{ChainState, inclusion_proof, verify_inclusion};
# fn frames() -> Vec<Vec<u8>> { Vec::new() }

let mut state = ChainState::new();
let mut hashes = Vec::new();
for bytes in frames() {           // canonical LedgerFrame objects, in order
    hashes.push(state.append(&bytes)?);
}
let root = state.accumulator().root();
if let Some(first) = hashes.first() {
    let proof = inclusion_proof(&hashes.as_slice(), hashes.len() as u64, 0)?;
    let included = verify_inclusion(&root, hashes.len() as u64, 0, first, &proof)?;
    assert_eq!(included.get().index(), 0);
}
# Ok::<(), ityv_ledger::Error>(())
```

- 증인 도구: `WitnessMemory::may_sign(body_bytes, consistency, box_close_hashes, dispute_hashes, genesis)` → 토큰 → `sign_hybrid(..., PURPOSE_CHECKPOINT, body_bytes)` → `advance(&token)` → 기억 영속 저장 → 서명 공개.
- 운영자: `SignedCheckpointParts::new(body_bytes, entries)` → `encode_object(SCHEMA_SIGNED_CHECKPOINT, …)`.
- 검증기: `decode_object::<SignedCheckpoint>` → `validate_successor` → `policy::evaluate(roster, profile, diversity, &signed)`.

## 의존성

`ityv-encoding`, `ityv-crypto`뿐이다. 알고리즘 크레이트를 직접 import하지 않는다(ADR-0015 §1). 개발 의존성은 `proptest =1.12.0`, `rand_chacha =0.10.0`.

## 검증

```bash
cargo test --locked -p ityv-ledger                 # V1: 독립 KAT(Python RFC 9162)·속성·회귀 벡터
ITYV_UPDATE_VECTORS=1 cargo test --locked -p ityv-ledger --test vectors   # 회귀 벡터 재생성(vectors/regression.txt만)
cargo kani -p ityv-ledger                          # V2: Kani 하네스
cargo mutants -p ityv-ledger --timeout 300         # V1: 변이 테스트
cargo build --locked -p ityv-ledger --target thumbv7em-none-eabihf   # no_std 빌드
```

독립 벡터(`vectors/ledger.txt`): 빈 root, 리프·노드 해시, 잎 0..8개의 root, 포함 경로 5건, 일관성 경로 6건, 정렬 집합 root를 Python `hashlib.sha3_512`와 RFC 9162 정의로 따로 계산했다. 회귀 벡터(`vectors/regression.txt`)는 이 구현의 인코딩 출력이며 독립 출처가 아니다.

Kani 하네스(`kani/proofs.rs`, 10개): 분할점(가장 큰 2의 거듭제곱), 깊이 상한, 잎 ≤ 4·기호적 인덱스의 포함 증명 왕복, 잘못된 인덱스 거부, 모든 `old ≤ new ≤ 4`의 일관성 증명 왕복, 누산기와 전체 계산의 일치, 정렬 집합 판정, 정족수 프로필 규칙, 기한 산술, 짧은 입력에 대한 스트림 파서. 트리 하네스는 SHA3-512 대신 값싼 대체 노드 함수로 알고리즘을 탐색한다(왕복 성질은 노드 함수와 무관). 하네스 파일은 `src/` 밖에 있고 파일 머리에 사유를 적은 lint 완화를 가진다(CONSTITUTION §1.1).

변이 테스트: `.cargo/mutants.toml`의 공통 설정(lint 상한, `impl Drop` 제외)을 쓴다. 이 크레이트에 동치 변이로 기록된 것은 없다.

## 테스트 코드의 lint 완화

`tests/` 아래 통합 테스트 크레이트는 TCB 밖이다. 각 파일 머리에 사유를 적고 `unwrap`, `expect`, `panic`, 인덱싱, 산술 부작용, 축소 캐스팅 lint만 완화한다. TCB 크레이트(`src/`)에는 어떤 완화도 없다.
