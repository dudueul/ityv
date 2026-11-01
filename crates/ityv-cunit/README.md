# ityv-cunit

> English summary: The trusted core of the casting scanner's commitment unit (ADR-0017). A `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate that turns one interpreted ballot into every object the scanner emits: the generalized Pedersen commitments and their 1-of-(m+2) OR proof, the share package for the trustees (each secret split over the chamber access structure, sealed per member through the chamber module's one-time pad or the hybrid KEM), the device and module record signatures, the tracking code, the imprint command, and on request the signed pre-cast challenge opening or the code slip. It also keeps the box state: the sealed journal hash chain, batch attestations (with module refusals), scan-count bodies and the box close with the VC-038 verdict. The crate owns no I/O: the host implements the module ports and the journal sink and supplies time buckets and per-operation seeds. Ordering rules are types: an imprint command or a slip exists only after the journal sink reported the record durable, and a closed box has no method that accepts a ballot.

## 무엇인가

커밋먼트 유닛은 투함 스캐너의 검증 부품이다(PROTOCOL.md §7.1, CONSTITUTION §4). 이 크레이트는 그 TCB 핵심이며 명세는 `docs/spec/PROTOCOL.md` §7–§10, `docs/spec/ENCODING.md` §8.6–§8.19, `docs/adr/ADR-0017-cunit-crate.md`다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `config` | genesis에서 호스트가 만드는 선거 구성: 투표양식, 모듈(챔버당 하나, X·Y 필수·비중립, N 없음, 위임 챔버는 중립 논리 모듈), 신뢰기관 명부, 접근구조, `VOTER_CODE` | ADR-0017 §2, §12 |
| `link` | 해석 유닛 링크 `Interpretation`(0x0101), 모듈 링크 `ModuleIssue`(0x0103), 봉인 저널 `JournalEntry`(0x0014) | ENCODING.md §8.19 |
| `port` | 호스트 trait `ModulePort`(발급, 패드 봉인, 기록 서명, 배치 서명)·`JournalSink`(내구 추가), 모듈의 배치 서명 규칙 `module_may_sign_batch` | ADR-0017 §3, §7–§8, VC-021 |
| `rng` | SHA3-512 카운터 모드 생성기 `DeviceRng`(표 생성기: 장치 시드와 모든 모듈의 비공개 기여로 시드; 서명 생성기: 장치 시드) | ADR-0017 §12 |
| `ballot` | 표별 typestate `Interpreted → Issued → Committed → Built → Durable → Done` 또는 `Built → Challenged`, share 패키지·투함 기록·검증 공개·슬립 | PROTOCOL.md §7.3–§7.7, §8, §9 |
| `boxstate` | `OpenBox`: 저널 사슬, 배치 마감(`BatchAttest`), 스캔 카운터 본문, 마감(`BoxCloseBody` + 장치 서명 + VC-038 판정), `ClosedBox` | PROTOCOL.md §7.2.1, §7.8, §10.2 |
| `rules` | 순수 계수 규칙(Kani 대상): 선택지 범위, 카운터 연속, 패드 소비·인덱스, 배치·스캔 카운터 시점, 마감 불변식 | VC-021, VC-034, VC-038, VC-052 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음(워크스페이스 lint 집합, `src/`에 완화 없음).
- 해석 유닛에서는 `Interpretation` 객체 하나만 받는다. 다른 선거, 모르는 투표양식, `t > m+1`은 거부한다(ITYV-BEH-013).
- 표는 한 번에 하나만 처리한다. 새 해석은 진행 중인 표가 있거나 배치가 가득 차면 거부된다. 배치 마감은 표와 표 사이에서만 가능하므로 배치가 증명하는 모든 카운터는 이미 저널에 있는 표의 것이다.
- 각인 명령과 슬립은 `Durable` 상태에만 있고, `Durable`은 저널 싱크가 기록과 share 패키지의 내구 기록을 보고한 뒤에만 생긴다(VC-054). 컴파일 실패 문서 테스트로 고정한다. 마감한 투표함(`ClosedBox`)에는 표를 받는 메서드가 없다(VC-039).
- 모듈 카운터는 이전 값 + 1이어야 하고(틈은 `CounterGap`), 패드 인덱스는 `카운터 × b`여야 한다(VC-034). 소비된 카운터는 오류가 나도 기록되므로 마감의 카운터 불변식이 틈을 드러낸다.
- 배치 서명 전에 호스트가 다시 읽은 저널 head를 메모리의 head와 대조한다(VC-056). 거부한 모듈은 본문의 `module_refusals`에 남고 나머지 모듈이 최종 본문에 다시 서명한다.
- 증명·비밀분산의 난수는 장치 시드와 모든 모듈 기여로 시드된 생성기에서만 나오므로 장치 혼자도, 모듈 하나도 그 난수를 정하지 못한다.
- 비밀(모듈 기여, 투함 ID, 봉투 라벨, 합산 난수, 구성원 평문)은 소거 용기에 있고, 종단 상태·오류 경로·값 폐기에서 지워진다. 소거 메서드는 단위 테스트로 관찰한다.

보장하지 않는 것(미증명 항목):
- 소거의 연역 증명(V3, VC-020)은 미해결이다. 또한 `ityv-encoding`의 `Scalars`·`MemberShare`는 `zeroize`를 구현하지 않으므로 그 사본(구성원 평문을 인코딩하는 동안의 스택 사본)은 지워지지 않는다. `ityv-encoding`에 소거 구현을 추가하는 것이 후속 항목이다.
- 투표함 마감의 `record_set_root`는 호스트가 저널에서 계산해 넘긴다(투표함 전체의 기록 해시를 고정 메모리에 담을 수 없다). 공개 검증기가 공표된 기록에서 다시 계산한다(VC-027). 유닛이 이를 직접 결속하려면 집합 해시(타원곡선 다중집합 해시)를 위한 공개 hash-to-point가 `ityv-crypto`에 필요하다.
- 레코드 없이 검증 폐기만 있는 꼬리 구간(마지막 배치 뒤의 검증만)은 배치로 증명되지 않는다(배치는 기록 1건 이상). 그 카운터는 마감의 `module_counters`에만 나타난다.
- 장치 키 보관(HSM)과 모듈 펌웨어(M8), 링크 전송, fsync, 인쇄는 범위 밖이다.

## 유도와 해시 규칙

| 값 | 규칙 |
|---|---|
| 합산 난수 | `r_j = Σ_c r_{c,j} (mod ℓ)` |
| 투함 ID | `SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_{c_1} ‖ … ‖ cid_{c_n})[0..24]`, 모듈 ID 오름차순 |
| 봉투 라벨(관외·재외) | `SHA3-512("ityv:envlabel:v1" ‖ 0x00 ‖ lab_{c_1} ‖ … )[0..24]` |
| 표 생성기 키 | `SHA3-512("ityv:ballotrng:v1" ‖ 0x00 ‖ device_seed ‖ 모듈마다 r_{c,0..k−1} ‖ cid_c ‖ lab_c)` |
| 비밀 i의 분산 스트림 | `fork("ityv:split:v1", i)`: `SHA3-512(key ‖ "ityv:fork:v1" ‖ 0x00 ‖ domain ‖ u64_be(i))` |
| 생성기 블록 | `SHA3-512(key ‖ u64_be(counter))` |
| 모듈 기록 서명 메시지 | `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`, purpose `module-record` |
| KEM 연관 데이터 | `election_id ‖ box_id ‖ commitments ‖ trustee_id ‖ 1u8 ‖ 0u32 ‖ 0u64` 정규 인코딩 |
| 저널 head | 마지막 `JournalEntry` 객체의 §4 해시(첫 항목의 `prev_head`는 0) |

구성원 평문 `MemberShare`(0x0015)의 길이는 `16 + (4 + 32·s) + 1 + 24 + (1 [+ 24]) + 16 = 62 + 32·s [+ 24]`바이트다(`s` = 공유 비밀 수 = 모듈 수 × k + 1 [+ 1]; 라벨 24바이트는 관외 프로필의 모듈 챔버 구성원만). 모듈 챔버의 패드 소비 `b = 길이 + 64`, 기록 n의 패드 인덱스는 `n × b`다. 시험 구성(모듈 4, k = 1, 현장)에서 `s = 5`, 길이 222, `b = 286`.

## 바이트 배치

| 객체 | 인코딩(§3 헤더 16바이트 뒤) |
|---|---|
| `Interpretation`(0x0101) | `election_id: Ident<64>` ‖ `ballot_style_id: Ident<64>` ‖ `option_index: u16` |
| `ModuleIssue`(0x0103) | `module_id: Ident<64>` ‖ `chamber: u8`(1–5) ‖ `counter: u64`(≥ 1) ‖ `rand: Array<Scalar, 8>`(1개 이상) ‖ `cid: Token192` ‖ `lab: Option<Token192>` ‖ `tags: Array<[u8; 16], 8>` |
| `JournalEntry`(0x0014) | `prev_head: Hash512` ‖ `kind: u8`(1 기록, 2 검증 폐기, 3 격리, 4 배치 마감, 5 투표함 마감) ‖ `record_hash: Hash512`(배치 마감은 기록 root, 투표함 마감은 기록 집합 root) ‖ `share_package_hash: Hash512`(기록이 아니면 0) ‖ `module_counters: Array<{module_id, counter}, 6>`(1개 이상) ‖ `time_bucket: u64` |

나머지 객체(`CastRecordBody`, `CastRecord`, `SharePackage`, `MemberShare`, `ChallengeOpening`, `BatchAttest`, `ScanCountAttestBody`, `BoxCloseBody`, `Slip`)는 `ityv-encoding`이 구현한다(ENCODING.md §8.6–§8.18).

## 호스트 계약

1. 모듈마다 `ModulePort`를 구현한다(구성의 모듈 순서 = 모듈 ID 오름차순으로 포트를 넘긴다). `seal_member`는 패드가 소진되면 버퍼를 바꾸지 않고 `Exhausted`를 돌려준다.
2. `JournalSink::append`는 항목과(기록이면) share 패키지를 안정 저장소에 쓴(fsync) 뒤에만 `Ok`을 돌려준다.
3. 시간 구간은 단조 비감소로 준다(역행은 `TimeRegression`). 각 서명 연산마다 새 32바이트 시드를 준다.
4. 표가 오류로 끝나거나 값이 사라지면 `OpenBox::quarantine_in_flight`로 격리를 기록하고 투표지를 격리 봉투로 보낸다. 모듈이 아무것도 발급하지 않은 표는 유권자에게 돌려준다(저널 항목 없음).
5. 다음 표 전에 `batch_due`를 확인해 배치를 닫고, `scan_count_due`면 스캔 카운터 본문을 만들어 참관인 서명을 받는다. 마감 전에 열린 배치를 닫는다.
6. 마감은 `prepare_close`(본문·장치 서명·저널 항목, 판정 반환) 뒤 `into_closed`로 끝낸다. 판정이 비어 있지 않으면 `HOLD_REVIEW`다.

버퍼 크기: 빌드 scratch `scratch_len(신뢰기관 수)`(신뢰기관당 3,286바이트 + 증명 20,483), share 패키지 ≤ 269,088, 기록 본문 ≤ 21,494, 기록 ≤ 22,374, 배치 작업 `BATCH_WORK_LEN`(67,320), 마감 작업 `CLOSE_WORK_LEN`(5,715), 검증 공개 ≤ 7,445, 슬립 ≤ 4,935.

## 검증

```bash
cargo test --locked -p ityv-cunit                 # V1: 흐름·회계·링크·규칙·속성 테스트, 문서 테스트(컴파일 실패 포함)
cargo kani -p ityv-cunit                          # V2: 순수 규칙 하네스
cargo mutants -p ityv-cunit --timeout 300         # V1: 변이 테스트
cargo build --locked -p ityv-cunit --target thumbv7em-none-eabihf   # no_std 빌드
```

시험은 결정적 모의 모듈(SHA3 패드 스트림, 일회성 MAC 태그, 기록·배치 키, 오동작 스위치)과 메모리 저널로 현장·관외 흐름 전체를 돌린다. 공개 검증기의 검사(추적코드, 장치·모듈 기록 서명, OR 증명)와 신뢰기관의 검사(패드·KEM 복호, 태그 검증, 정족수 집합으로 모든 비밀 복원과 검증 공개값의 일치, 비정족수 집합의 실패)를 테스트가 직접 수행한다. 마감 불변식은 하나씩 위반시켜 각각 단독으로 보고되는지 확인한다.

Kani 하네스: 선택지 범위, 카운터 연속, 패드 소비·인덱스 산술, 모듈 배치 서명 규칙, 배치·스캔 카운터 시점, VC-038 판정 전체(두 모듈, 기호 수량)를 128비트 산술로 독립 기술한 명제와 대조한다.

## 테스트·하네스 코드의 lint 완화

| 파일 | 완화 | 사유 |
|---|---|---|
| `tests/flow.rs`, `tests/boxes.rs`, `tests/link.rs` | `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `too_many_lines`, `missing_panics_doc`, `many_single_char_names` | 테스트는 "반드시 성립한다"를 unwrap·panic·인덱싱으로 표현하고 작은 시험 크기에 산술·캐스팅을 쓰며, 흐름 하나를 한 함수에서 끝까지 검사한다 |
| `tests/common/mod.rs` | 위 집합(`many_single_char_names` 제외) + `dead_code`, `missing_errors_doc`, `struct_excessive_bools` | 모든 테스트 바이너리에 컴파일되지만 각 바이너리는 일부만 쓴다; 모의 모듈의 오동작 스위치는 서로 독립인 불리언이다 |
| `kani/proofs.rs` | `clippy::indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_lossless`, `missing_panics_doc` | 하네스는 유계 기호 입력의 기대값을 인덱싱·`as`·무검사 산술로 적고, 패닉·오버플로는 Kani가 직접 보고한다 |
| `src/` | 없음. `close_batch`, `journal`에 항목 단위 `#[expect(clippy::too_many_arguments)]`, `into_closed`에 `#[expect(clippy::needless_pass_by_value)]`(사유 주석 포함) | 호스트 능력과 저널 항목 필드를 하나씩 받는다; 마감 토큰은 증명으로 소비된다 |

## 알려진 동치 변이

변이 테스트 결과는 아래 "변이 테스트" 절에 기록한다. `impl Drop` 본문은 `.cargo/mutants.toml`의 제외 규칙으로 빠지며, 소거는 `wipe` 메서드의 단위 테스트가 직접 검사한다.
