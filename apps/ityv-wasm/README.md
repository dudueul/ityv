# ityv-wasm

> English summary: The verification console's WebAssembly wrapper (ADR-0038). Outside the TCB and without external dependencies (no wasm-bindgen, no serde): it reads a development bundle (`tools/ityv-sim/README.md`, "번들 형식"), runs `ityv_verify::verify_genesis` and `verify_ledger_with` over it (handing the audit stage the bundle's beacon observation, the simulator's fixture data, unless the caller asks not to), and writes what the verifier found as hand-written JSON — the bundle's SHA3-512, the status in the exact vocabulary, every stage outcome, every hold with its code and name, per reporting unit status, refused events with frame, schema and reason, checkpoints with their fingerprints, progress series and alarms, participation, disputes, each ballot style's audit (rounds, the drawn records' tracking codes, boxes and comparisons, devices, hand counts; the seed's inputs and the binding checkpoint against the beacon publication; never a restricted opening) and every record's tracking code with its verified inclusion in the first checkpoint that covers it — through a small C ABI (`alloc`, `dealloc`, `verify_bundle`, `verify_bundle_with`, `fingerprint`, `result_len`). Integers above 2^53 − 1 are written as decimal strings; sums that do not fit in 64 bits are written as `null` with an `overflow` flag, never trapped. No state is kept between two verifications except the last result buffer. All `unsafe` is in `src/ffi.rs`, each item allowed on its own with one SAFETY comment per block. Builds for the host (cdylib and rlib, so the simulator's tests read bundles through the same code) and for `wasm32-unknown-unknown`.

## 무엇인가

브라우저가 검증을 서버에 묻지 않고 공개 검증기를 직접 돌리게 하는 얇은 감싸개다. 서버는 여전히 이 모듈과 그것을 부르는 페이지를 내려 주므로 그것들은 믿어야 한다(콘솔이 불러온 모듈의 SHA-256을 보인다. ADR-0038 §2). 검증은 모두 TCB 크레이트가 한다. 이 크레이트가 하는 일은 셋뿐이다.

1. 번들을 읽는다(`bundle`): 길이를 모두 남은 바이트와 대조하고, 모르는 섹션·순서 위반·남는 바이트는 거부한다.
2. `verify_genesis`(번들의 핀, 또는 호출자가 준 64바이트 핀)와 `verify_ledger_with`를 부른다. 감사 단계에는 번들의 비콘 관찰(시뮬레이터의 고정 자료)을 호출자의 관찰로 넘기며, 호출자가 원하면 넘기지 않는다(그러면 감사는 끝나지 않는다). 제한 열기는 넘기지 않는다(공개 검증자). 앵커 기한은 검증기가 장부의 시점확인 토큰으로 정하고(ADR-0039, 번들의 지금 시각만 넘긴다), 게시판 기한은 번들의 입력으로 `ityv_ledger::check_board`가 판정한다. genesis가 거부되면 그 위의 단계는 돌리지 않고, 상태는 genesis 단계 실패를 `ityv_state::status::evaluate`에 넘긴 값(`HOLD_REVIEW`, `StepFailed`)이다.
3. 보고서를 JSON으로 쓴다(`report`, 손으로 쓴 작은 JSON 작성기 `json`). 보고서 맨 앞에 번들 바이트의 SHA3-512(`bundleHash`)가 있어 보고서가 어느 바이트에 대한 것인지 스스로 말한다. `pinFromBundle`은 핀을 주지 않아 번들의 핀을 썼다는 뜻이고, `pinEqualsBundle`은 쓴 핀이 번들의 핀과 같다는 뜻이다.

보고서에서 이 크레이트가 조합하는 값은 셋이며 모두 TCB 코드로 계산한다.
- 보고 단위별 상태: 장부 전체의 보류 집합에서 시작해, 다른 단위의 투표함·집계·투표양식 감사에만 있는 사유(그 단위의 것에도 없고 장부 수준 사유도 아닌 것)만 뺀다. 받지 못한 집계·감사 이벤트의 보류는 장부 수준이다(거부는 어느 단위의 것인지 말하지 않는다). 그 나머지와 그 단위의 마감 완전성, 집계 결과, 그 투표양식 감사의 종료(`AuditStage::concluded`)를 검증기의 단계 결과와 함께 `evaluate`에 넘긴다. 그래서 한 단위가 장부 전체보다 높게 읽히는 것은 장부의 보류가 모두 다른 단위의 것일 때, 또는 장부의 다른 투표양식이 감사를 끝내지 않았을 때뿐이다(`tests/robustness.rs`가 확인). 투표함이 하나도 없는 단위는 마감 완전으로 치지 않는다. 장부 전체의 상태를 대신하지 않는다.
- 투표소 진행 수열: 진행 기록 단계가 받은 진행 기록(거부된 프레임은 뺀다)의 누계를 슬롯마다 이어 적고, 바깥 장수는 `ityv_state::out_of`로 계산한다. 투표함들의 투입 누계 합은 검사한 덧셈으로 구하며, 64비트를 넘는 칸은 `sheetsIn`과 `out`을 `null`로, `overflow`를 `true`로 쓴다(그 투표소에도 `overflow`). 경보와 정지는 검증기의 `StationProgressReport`를 그대로 옮긴다. 현장 확인의 반출 장수는 수열에 넣지 않는다.
- 기록별 포함: 기록마다 그 프레임을 덮는 첫 검증된 체크포인트를 찾아, 프레임 해시로 RFC 9162 감사 경로를 만들고(`inclusion`, 메모한 부분 트리 root) `ityv_ledger::verify_inclusion`으로 그 체크포인트 root에 대해 확인한다. 결과(`included`, `checkpoint`, `treeSize`, `checkpointFingerprint`, `pathLength`)는 그 기록과 함께 보고서에 들어가므로, 포함 답이 다른 번들의 것일 수 없다.

받지 못한 집계·감사 이벤트의 보류 사유는 검증기가 공개한 표 `TallyEvent::hold`와 `AuditEvent::hold`로 정한다(예전의 사본 `report::tally_refusal_hold`는 지웠다).

감사 보고(`audit`, 모듈 `audit`)는 검증기의 `AuditStage`를 옮긴 것이다: 비콘 관찰(`fixture: true`, 회차, 공표 구간, 출력, 그 출력에서 `ityv_crypto::beacon_value`로 계산한 비콘 값), 약정과 그 고정 체크포인트(순번, 프레임, 시각 구간, 지문), 시드(지문, 비콘 확인), 고정 체크포인트가 공표보다 앞서야 하는 구간 수(`margin` = `WITNESS_TIME_TOLERANCE + CLOCK_ERROR_BUCKETS + 1`), 투표양식마다 프레임·규칙·라운드별 대조와 불일치·단계·뽑힌 기록(추적코드, 투표함, 열기 흔적의 프레임, 대조 코드, 재구성 여부)·전수 대조로 연 기록·장치별 코드·수검표·보류, 받지 못한 감사 이벤트. 공개 정보만 쓴다. 제한 열기(`SampleOpeningBody`의 선택, cast id, 난수)는 번들에 없고 검증기에 넘기지 않으며 검증기도 열린 값을 내놓지 않는다(`tools/ityv-sim/tests/audit.rs`가 보고서에 그 바이트가 없음을 확인).

지문 표기는 `ENCODING.md`의 소프트웨어 지문 표기(앞 20바이트, RFC 4648 Base32, 32자, 넷씩)다. 체크포인트 지문은 체크포인트 본문 객체 해시의 지문이다(PROTOCOL §5.7 5항).

## C ABI

```text
alloc(len) -> ptr                       입력 버퍼 (Box<[u8]>)
dealloc(ptr, len)                       입력 버퍼 해제 (같은 len)
verify_bundle(ptr, len) -> ptr          JSON 보고서 (번들의 핀, 번들의 비콘 관찰)
verify_bundle_with(ptr, len, pin, flags) -> ptr
                                        JSON 보고서 (pin: 64바이트, null이면 번들의 핀;
                                        flags bit 0: 번들의 비콘 관찰을 넘김)
fingerprint(ptr, len) -> ptr            SHA3-512의 32자 지문 (시제품 신원 줄용)
result_len() -> usize                   마지막 결과의 길이
```

포인터와 길이는 부호 없는 32비트다(JavaScript에서는 `>>> 0`). 결과 버퍼는 모듈이 갖고 다음 호출 때까지 유효하다. 호출은 한 번에 하나(단일 스레드)다. 모듈이 트랩하면(메모리 부족 등) 그 인스턴스는 버리고 새로 만든다. 콘솔의 worker가 그렇게 한다.

## 규칙

- 의존성은 워크스페이스 크레이트뿐이다. TCB 크레이트를 고치지 않으며, TCB가 계산하는 상태·보류·지문을 여기서 다시 계산하지 않는다.
- lint는 워크스페이스 집합 그대로다(`arithmetic_side_effects`, `cast_*`, `indexing_slicing`, `wildcard_enum_match_arm` 등 포함). 다른 것은 `unsafe_code`뿐으로, 워크스페이스의 `forbid` 대신 `deny`라서 `src/ffi.rs`의 C ABI 항목마다 `#[allow(unsafe_code)]`를 붙인다. 블록마다 SAFETY 주석이 있다. 크레이트 전체에 거는 `allow`는 없다.
- 빌드: `cargo build -p ityv-wasm --target wasm32-unknown-unknown --release`(약 3 MB, 기호 포함). 릴리스 프로필은 overflow-checks를 켜고 패닉하면 중단하므로, 산술은 모두 검사한 연산으로 쓴다.

## 검증

`json`·`inclusion`·지문 표기의 단위 테스트(RFC 4648 벡터, 크기 1–23의 모든 감사 경로), 그리고 `tools/ityv-sim`의 테스트가 이 크레이트로 번들을 읽는다.
- `tests/scenarios.rs`: 모든 빠른 시나리오의 상태와 보류 사유가 `ityv-verify`의 판정과 같다. 기록별 포함, 번들 해시, 체크포인트 밖 기록의 표시, 잘린 번들과 다른 핀의 거부.
- `tests/robustness.rs`: 보고서가 언제나 올바른 JSON이다. 비트를 뒤집고 자르고 덧붙인 번들에 패닉하지 않는다. 적대적인 시나리오 이름이 한 문자열로 이스케이프된다. 두 투표함의 2^63, 한 투표함의 u64::MAX가 합을 넘쳐도 트랩 없이 `overflow`로 보고되고 상태는 검증기와 같다. 단위가 장부보다 높게 읽히는 조건과 단위의 `PAPER_AUDITED` 조건. 집계·감사 거부가 검증기의 표대로 보류된다. 콘솔의 보류 이름 표가 `ityv-state`의 72개와 같다.
- `tests/audit.rs`: 감사 보고의 키, 비콘 관찰 없이는 집계 상태, 제한 열기가 보고서에 없음.

## 하지 않는 것

- 번들의 핀이 공표된 그 값이라는 것을 증명하지 않는다. 콘솔은 그 점을 보이고 다른 핀을 넣게 한다.
- 검증기에 아직 없는 단계(분기 감시, 연결, 소프트웨어; PROTOCOL §14 10–12)를 하지 않는다.
- 비콘을 관찰하지 않는다. 번들의 비콘 관찰은 시뮬레이터의 고정 자료이며 보고서와 콘솔이 그렇다고 적는다. 실제 검증에서는 호출자가 지정된 비콘의 공표를 직접 확인해 넘겨야 한다.
- 미러 두 곳 대조를 하지 않는다. 미러 형식(ADR-0018)이 아직 없다.
