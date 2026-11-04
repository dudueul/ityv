# ityv-wasm

> English summary: The verification console's WebAssembly wrapper (ADR-0038). Outside the TCB and without external dependencies (no wasm-bindgen, no serde): it reads a development bundle (`tools/ityv-sim/README.md`, "번들 형식"), runs `ityv_verify::verify_genesis` and `verify_ledger` over it, and writes what the verifier found as hand-written JSON — the status in the exact vocabulary, every stage outcome, every hold with its code and name, per reporting unit status, refused events with frame, schema and reason, checkpoints with their fingerprints, progress series and alarms, participation, disputes and every record's tracking code with its covering checkpoint — through a small C ABI (`alloc`, `dealloc`, `verify_bundle`, `verify_bundle_pinned`, `inclusion`, `fingerprint`, `result_len`). All `unsafe` is in `src/ffi.rs`, one SAFETY comment per block. Builds for the host (cdylib and rlib, so the simulator's tests read bundles through the same code) and for `wasm32-unknown-unknown`.

## 무엇인가

브라우저가 서버를 믿지 않고 공개 검증기를 직접 돌리게 하는 얇은 감싸개다. 검증은 모두 TCB 크레이트가 한다. 이 크레이트가 하는 일은 셋뿐이다.

1. 번들을 읽는다(`bundle`): 길이를 모두 남은 바이트와 대조하고, 모르는 섹션·순서 위반·남는 바이트는 거부한다.
2. `verify_genesis`(번들의 핀, 또는 호출자가 준 64바이트 핀)와 `verify_ledger`를 부른다. 앵커·게시판 기한은 번들의 입력으로 `ityv_ledger::check_anchor`·`check_board`가 판정한다. genesis가 거부되면 그 위의 단계는 돌리지 않고, 상태는 genesis 단계 실패를 `ityv_state::status::evaluate`에 넘긴 값(`HOLD_REVIEW`, `StepFailed`)이다.
3. 보고서를 JSON으로 쓴다(`report`, 손으로 쓴 작은 JSON 작성기 `json`).

보고서에서 이 크레이트가 조합하는 값은 둘이며 둘 다 TCB 코드로 계산한다.
- 보고 단위별 상태: 검증기의 단계 결과를 그 단위(투표양식 × 보고 단위)의 투표함 보류, 마감 완전성, 집계 결과로 좁혀 `evaluate`에 넘긴 값이다. 장부 전체의 보류(색인, 승인, 체크포인트, 참여 장부, 분쟁, 받지 못한 집계 이벤트)는 모든 단위에 그대로 들어간다. 장부 전체의 상태를 대신하지 않는다.
- 투표소 진행 수열: 진행 기록 단계가 받은 진행 기록(거부된 프레임은 뺀다)의 누계를 슬롯마다 이어 적고, 바깥 장수는 `ityv_state::out_of`로 계산한다. 경보와 정지는 검증기의 `StationProgressReport`를 그대로 옮긴다. 현장 확인의 반출 장수는 수열에 넣지 않는다.

추적코드 포함(`inclusion(seq)`)은 마지막으로 검증한 번들의 프레임 해시와 검증된 체크포인트로 `ityv_ledger::inclusion_proof`를 만들고 `verify_inclusion`으로 그 체크포인트 root에 대해 확인한다.

지문 표기는 `ENCODING.md`의 소프트웨어 지문 표기(앞 20바이트, RFC 4648 Base32, 32자, 넷씩)다. 체크포인트 지문은 체크포인트 본문 객체 해시의 지문이다(PROTOCOL §5.7 5항).

## C ABI

```text
alloc(len) -> ptr                       입력 버퍼
dealloc(ptr, len)                       입력 버퍼 해제
verify_bundle(ptr, len) -> ptr          JSON 보고서 (번들의 핀)
verify_bundle_pinned(ptr, len, pin) -> ptr   JSON 보고서 (pin: 64바이트)
inclusion(seq: u64) -> ptr              JSON: 그 프레임의 포함 증명 결과
fingerprint(ptr, len) -> ptr            SHA3-512의 32자 지문 (시제품 신원 줄용)
result_len() -> usize                   마지막 결과의 길이
```

결과 버퍼는 모듈이 갖고 다음 호출 때까지 유효하다. 호출은 한 번에 하나(단일 스레드)다.

## 규칙

- 의존성은 워크스페이스 크레이트뿐이다. TCB 크레이트를 고치지 않으며, TCB가 계산하는 상태·보류·지문을 여기서 다시 계산하지 않는다.
- `unsafe`는 `src/ffi.rs`에만 있고(크레이트 lint는 `unsafe_code = deny`, 그 모듈만 허용), 블록마다 SAFETY 주석이 있다. 그 밖의 lint는 워크스페이스 집합을 따르되 TCB가 아니므로 이 크레이트의 `[lints]`가 정한다.
- 빌드: `cargo build -p ityv-wasm --target wasm32-unknown-unknown --release`(약 3 MB, 기호 포함).

## 검증

`json`의 단위 테스트, 지문 표기의 RFC 4648 벡터, 그리고 `tools/ityv-sim/tests/scenarios.rs`가 모든 빠른 시나리오의 번들을 이 크레이트로 읽어 상태와 보류 사유가 `ityv-verify`의 판정과 같은지, 포함 증명이 성립하는지, 잘린 번들과 다른 핀을 거부하는지 확인한다.

## 하지 않는 것

- 번들의 핀이 공표된 그 값이라는 것을 증명하지 않는다. 콘솔은 그 점을 보이고 다른 핀을 넣게 한다.
- 검증기에 아직 없는 단계(감사, 분기 감시, 연결, 소프트웨어; PROTOCOL §14 8, 10–12)를 하지 않는다.
- 미러 두 곳 대조를 하지 않는다. 미러 형식(ADR-0018)이 아직 없다.
