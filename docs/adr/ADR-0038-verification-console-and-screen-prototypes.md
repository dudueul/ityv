# ADR-0038: 읽기 전용 검증 콘솔과 기기 화면 시제품

> English summary: The first web UI is a read-only public verification console plus prototypes of the field devices' screens, all outside the TCB (`apps/`, `tools/`). The console runs the real verifier in the viewer's browser — `ityv-verify` compiled to WebAssembly through a thin wrapper with no external dependencies, a C ABI and hand-written JSON — over a development bundle produced by a deterministic simulator (`tools/ityv-sim`), so no server is trusted; it shows only what the verifier reports, in the exact status vocabulary, says what each status does not mean, and never shows anything stronger. There is no control console: devices only send (ADR-0022), so nothing in the UI commands a device or writes evidence. The device screens are a TypeScript model of `docs/ui/SCREENS.md`, drawn from one string table transcribed from it and checked against it, with the fixed identity line in every state, zoom and contrast; firmware rendering, the canonical string-table format and its `ui_strings_hash` remain for M8. The bundle is a documented development container, not part of `ENCODING.md`, until the mirror format of ADR-0018 exists. JavaScript supply-chain rules: one exactly pinned devDependency (`typescript`), a committed lockfile installed frozen, no dependency install scripts, everything else from Bun's built-ins.

- 상태: 제안
- 날짜: 2026-11-04
- 관련: ADR-0007(헌법), ADR-0018(공개 미러), ADR-0022(장치는 보내기만), ADR-0023(신원 줄), ADR-0027(진행 기록과 경보), ADR-0029–ADR-0035(검증기); `CONSTITUTION.md` §0, §5 3항; `docs/ui/SCREENS.md`; `docs/spec/PROTOCOL.md` §5.7, §7.1, §7.9, §7.10, §14; `docs/ROADMAP.md` M6, M8

## 맥락

검증기(M5)는 장부를 `UNVERIFIED`부터 `CRYPTO_TALLY_VERIFIED`까지 판정하지만, 그 판정을 보는 방법은 Rust 테스트뿐이었다. 참관인·언론·시민이 공개원장을 스스로 검증하려면 설치 없이 돌릴 수 있는 검증기와, 그 결과를 정직하게 보여 주는 화면이 필요하다. 또 `docs/ui/SCREENS.md`는 기기 화면의 규범이지만 표와 문장뿐이어서, 신원 줄이 확대·고대비에서도 맨 아래에 남는지, 문구 표가 금지 문구를 피하는지를 그려 보고 시험할 대상이 없었다(SCREENS §8).

헌법은 UI·대시보드·미러·시뮬레이터를 TCB 밖에 두고(§0), `LOG_CONSISTENT`를 더 강한 상태처럼 보이게 하는 UI를 결함으로 정한다(§5 3항). 장치는 보내기만 하고 받는 경로가 없다(ADR-0022). 그러므로 장치를 조작하는 "관제 콘솔"은 설계에 자리가 없다.

## 결정

1. **읽기 전용 검증 콘솔.** `apps/ityv-console`은 번들을 고르거나 놓으면 브라우저 안에서 실제 검증기를 돌려 그 결과만 보인다. 상태·보류 사유·단계·체크포인트 지문·받지 않은 이벤트·분쟁·기록 상태는 모두 검증기가 낸 값이다. 콘솔은 상태를 계산하지 않고, 아무 데도 쓰거나 보내지 않으며, 어떤 장치에도 명령하지 않는다.
2. **관제 콘솔은 없다.** 장치는 고정 일정으로 보내기만 하고(ADR-0022) 증거는 장부에만 있다. 장치를 원격으로 열고 닫거나 설정을 바꾸는 화면은 만들지 않는다. 사람이 하는 일(현장 확인, 마감)은 현장에서 서명하는 사건이며, 콘솔의 현장 확인 양식은 그 내용을 보일 뿐 서명하거나 보내지 않는다.
3. **보일 수 있는 것과 없는 것.**
   - 상태는 일곱 어휘로만 쓴다: `UNVERIFIED`, `LOG_CONSISTENT`, `SOURCE_COMPLETENESS_CHECKED`, `CRYPTO_TALLY_VERIFIED`, `PAPER_AUDITED`, `HOLD_REVIEW`, `LEGAL_CERTIFIED`. 사다리를 그대로 보이고 지금 상태마다 "뜻하지 않는 것"을 함께 적는다. `PAPER_AUDITED`는 감사 단계가 없어 닿지 않는다고, `LEGAL_CERTIFIED`는 검증기가 판정하지 않는다고 쓴다. 상태보다 강하게 들리는 말("검증 완료", "정상", "확정", "당선")을 쓰지 않는다.
   - 보고 단위별 상태는 검증기의 단계 결과를 그 단위의 투표함과 집계로 좁혀 `ityv_state::status::evaluate`에 넘긴 값이고, 장부 전체의 보류를 모두 포함하며, 장부 전체 상태를 대신하지 않는다고 적는다.
   - 열어 본 수(합계 열기)는 신뢰기관의 열기를 커밋먼트에 대해 확인한 값일 뿐이며 결과의 법적 지위를 뜻하지 않는다. 시연 자료의 모든 이름은 가상이다.
   - 기기 화면은 SCREENS.md의 규칙을 그대로 따른다: 상태기계의 현재 상태와 수만, 판단 문구 없이, 후보 이름·판독 결과·순번·사건 시각·가명·각인 목록 없이. 유권자 확인 앱은 미러 두 곳 또는 공표 지문과 대조한 뒤에만 `LOG_CONSISTENT`를 보이고(PROTOCOL §5.7 4항), 추적코드 하나에 그보다 높은 칸을 붙이지 않는다.
4. **WASM 감싸개 규칙.** `apps/ityv-wasm`은 TCB 밖의 cdylib이다. 의존성은 워크스페이스 크레이트뿐이다(wasm-bindgen·serde 없음). C ABI(`alloc`, `dealloc`, `verify_bundle`, `verify_bundle_pinned`, `inclusion`, `fingerprint`, `result_len`)로 바이트를 받고 손으로 쓴 JSON을 돌려준다. `unsafe`는 FFI 모듈 하나에만 두고 블록마다 SAFETY 주석을 단다. TCB가 계산하는 값을 다시 계산하지 않는다. TCB 크레이트에 없는 공개 API가 필요하면 TCB를 고치지 않고 우회하거나 필요한 것을 적어 둔다. 감싸개는 브라우저 worker에서 돌아 큰 번들도 쪽을 멈추지 않는다.
5. **핀.** 검증기는 호출자가 준 genesis 핀만 믿는다. 개발 번들에는 핀이 들어 있지만 번들과 같은 출처이므로, 콘솔은 그 사실을 적고 다른 출처의 핀(16진 128자)을 넣어 다시 검증하게 한다.
6. **개발 번들 형식.** `tools/ityv-sim`이 쓰는 번들(magic `ITYVSIMB`, 버전, tag·길이 접두 섹션: 이름, 핀, genesis와 모든 집합, 변경, 프레임 스트림, 이벤트, 공표 기한 입력)은 `tools/ityv-sim/README.md`에 적은 개발용 컨테이너다. `ENCODING.md`에 넣지 않고 TCB 크레이트는 읽지 않는다. ADR-0018의 미러 형식(전체·증분, 체크포인트 교환)이 정해지면 그것으로 바꾼다.
7. **시뮬레이터.** `tools/ityv-sim`(M6의 첫 부분)은 고정 씨앗에서 서명된 선거 전체와 이름 붙은 시나리오를 만든다: 상태 사다리의 칸마다 깨끗한 선거, 큰 가상 선거 둘, 공격과 장애 21개. 시나리오마다 기대 결과(상태와 보류 사유)를 정의의 일부로 두고, Rust 테스트와 콘솔이 실제 판정과 비교한다. 의존성은 워크스페이스 크레이트뿐이며 같은 씨앗은 같은 바이트를 낸다.
8. **JS 공급망 규칙.** 개발 의존성은 정확히 고정한 `typescript` 하나뿐이다(형 검사). 서버·번들러·테스트는 Bun 내장을 쓰고, Bun 형 정의도 손으로 선언한다. `bun.lock`을 커밋하고 `bun install --frozen-lockfile`로만 설치한다. 의존성의 설치 스크립트는 돌지 않는다(`trustedDependencies` 비움). 의존성을 더하려면 README에 이유를 적는다. 화면 캡처 검사는 기기에 설치된 Playwright를 쓰며 의존성으로 들이지 않는다.
9. **화면 시제품과 문구 표.** 기기 화면은 SCREENS.md 표의 TypeScript 모델이며 펌웨어가 아니다. 모든 화면 문구는 SCREENS.md에서 옮긴 고정 문구 표 하나에서 나오고, 값 자리는 형(정수, 식별자, 지문, 상태 어휘)이 정해져 있다. `bun test`가 SCREENS.md의 화면 문구가 표에 글자 그대로 있는지, 금지 문구가 없는지, 자리 형이 허용된 것뿐인지 확인하고, 화면 캡처 검사가 모든 상태·확대·고대비에서 신원 줄이 보이고 맨 아래이며 가려지지 않는지 확인한다(SCREENS §8).

## 결과

- 누구나 설치 없이 브라우저에서 장부를 검증할 수 있는 첫 경로가 생긴다. 검증 결과는 Rust 테스트가 보는 것과 같은 코드에서 나온다.
- 시나리오의 기대와 판정을 나란히 보이므로, 시연 자료가 곧 자체 시험이다. 둘이 다르면 화면에 불일치가 뜬다.
- SCREENS.md의 문장이 시험 가능한 표가 된다. 규범 문서가 바뀌면 시험이 표를 바꾸라고 알린다.
- 기기 화면의 확대와 고대비, 신원 줄의 자리를 실제 렌더링으로 본다.
- 비용: 번들이 크다(하이브리드 서명). 개발용 큰 번들은 저장소에 넣지 않고 매번 만든다.

## 한계

- 콘솔이 보이는 것은 검증기가 아는 것까지다. 감사·분기 감시·연결·소프트웨어 단계(§14 8, 10–12)가 없으므로 `PAPER_AUDITED`에 닿지 않고, 현장 증명 결과와 게이트웨이 화면은 시연용 고정값이다.
- 브라우저와 그 확장, 콘솔을 내려 준 곳은 믿어야 한다. 콘솔이 틀려도 증거는 바뀌지 않지만, 틀린 콘솔은 틀린 판정을 보일 수 있다. 독립 2차 구현(V5)과 여러 출처의 콘솔이 견제한다.
- 화면 시제품은 장치가 그 화면을 그린다는 증거가 아니다. 장치가 그리는 것은 장치 자신의 주장이고(SCREENS §0.1), 확인은 현장 증명이 한다.
- 시제품의 신원 줄 지문은 시제품의 문구 표와 이름의 해시이며 릴리스 목록의 이미지 해시가 아니다.
- 현재 genesis는 투표함에 투표양식 하나, 투표소 등식은 확인 한 건에 투표지 한 장이어서 한 방문의 여러 종류 투표지를 검증할 수 없다. 시연 선거는 유권자마다 한 장으로 줄였다.

## 대안

- **관제 콘솔**(장치 상태를 보고 명령하는 화면): 장치에 받는 경로를 만들어야 하며 ADR-0022와 정면으로 충돌한다. 기각.
- **서버에서 검증하고 결과만 보이기**: 서버를 믿어야 한다. 공개 검증의 뜻과 반대다. 기각.
- **wasm-bindgen과 serde**: 편하지만 TCB 밖에도 큰 의존성 나무가 생기고 감사 대상이 늘어난다. 필요한 것은 바이트 입출력과 JSON 하나뿐이다. 기각.
- **UI 프레임워크(React 등)**: 화면이 단순하고, 의존성마다 공급망 위험이 늘어난다. 기각.
- **번들 형식을 `ENCODING.md`에 넣기**: 미러 형식(ADR-0018)이 정해지기 전에 정규 형식을 하나 더 고정하게 된다. 개발용으로 두고 나중에 바꾼다.

## 연결되는 검증

- `tools/ityv-sim/tests/scenarios.rs`: 시나리오마다 기대 상태·보류 사유가 `ityv-verify`와 `ityv-wasm`의 판정과 같음, 경보가 시뮬레이터의 하루와 같음, 번들이 실행마다 같은 바이트.
- `apps/ityv-console/test/strings.test.ts`, `test/screens.test.ts`: 문구 표와 SCREENS.md, 금지 문구, 자리 형, 모든 상태의 문구.
- `apps/ityv-console/scripts/screens.cjs`: 모든 상태·확대·고대비의 신원 줄, 휴대전화 폭.
- CI `console` 작업: wasm32 빌드, 빠른 시나리오 생성, 고정 설치, 형 검사, 시험, 정적 빌드.
- M8 과제: 장치 펌웨어의 화면 렌더링, 정식 문구 표 형식과 `ui_strings_hash`(ENCODING §8.26), 음성 안내와 점자 표기, 미러 두 곳 대조, 실제 장치 데이터로 화면 시험.
