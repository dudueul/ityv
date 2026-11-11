# ADR-0038: 읽기 전용 검증 콘솔과 기기 화면 시제품

> English summary: The first web UI is a read-only public verification console plus prototypes of the field devices' screens, all outside the TCB (`apps/`, `tools/`). The console runs the real verifier in the viewer's browser — `ityv-verify` compiled to WebAssembly through a thin wrapper with no external dependencies, a C ABI and hand-written JSON — over a development bundle produced by a deterministic simulator (`tools/ityv-sim`), so no server is asked for a verdict (the server still ships the page, the worker, the module and the scenario list, which must be trusted or checked against a local build by the module hash the console shows); it shows only what the verifier reports, in the exact status vocabulary, says what each status does not mean, and never shows anything stronger. There is no control console: devices only send (ADR-0022), so nothing in the UI commands a device or writes evidence. The device screens are a TypeScript model of `docs/ui/SCREENS.md`, drawn from one string table transcribed from it and checked against it, with the fixed identity line in every state, zoom and contrast; firmware rendering, the canonical string-table format and its `ui_strings_hash` remain for M8. The bundle is a documented development container, not part of `ENCODING.md`, until the mirror format of ADR-0018 exists. JavaScript supply-chain rules: one exactly pinned devDependency (`typescript`), a committed lockfile installed frozen, no dependency install scripts, everything else from Bun's built-ins. Since the audit stage (ADR-0036) the simulator lays down audits and the console shows them per ballot style — rounds, the drawn records (public information only, never a restricted opening), comparisons by code, escalation, full comparisons and hand counts — with the seed's inputs and the binding checkpoint's time against the beacon publication; the beacon observation is the simulator's fixture data, carried in the bundle, labelled on screen and optional, and the ladder reaches `PAPER_AUDITED`.

- 상태: 제안
- 날짜: 2026-11-04
- 관련: ADR-0007(헌법), ADR-0018(공개 미러), ADR-0022(장치는 보내기만), ADR-0023(신원 줄), ADR-0027(진행 기록과 경보), ADR-0029–ADR-0036(검증기, 감사 단계); `CONSTITUTION.md` §0, §5 3항; `docs/ui/SCREENS.md`; `docs/spec/PROTOCOL.md` §5.7, §7.1, §7.9, §7.10, §14; `docs/ROADMAP.md` M6, M8

## 맥락

검증기(M5)는 장부를 `UNVERIFIED`부터 `CRYPTO_TALLY_VERIFIED`까지 판정하지만, 그 판정을 보는 방법은 Rust 테스트뿐이었다. 참관인·언론·시민이 공개원장을 스스로 검증하려면 설치 없이 돌릴 수 있는 검증기와, 그 결과를 정직하게 보여 주는 화면이 필요하다. 또 `docs/ui/SCREENS.md`는 기기 화면의 규범이지만 표와 문장뿐이어서, 신원 줄이 확대·고대비에서도 맨 아래에 남는지, 문구 표가 금지 문구를 피하는지를 그려 보고 시험할 대상이 없었다(SCREENS §8).

헌법은 UI·대시보드·미러·시뮬레이터를 TCB 밖에 두고(§0), `LOG_CONSISTENT`를 더 강한 상태처럼 보이게 하는 UI를 결함으로 정한다(§5 3항). 장치는 보내기만 하고 받는 경로가 없다(ADR-0022). 그러므로 장치를 조작하는 "관제 콘솔"은 설계에 자리가 없다.

## 결정

1. **읽기 전용 검증 콘솔.** `apps/ityv-console`은 번들을 고르거나 놓으면 브라우저 안에서 실제 검증기를 돌려 그 결과만 보인다. 상태·보류 사유·단계·체크포인트 지문·받지 않은 이벤트·분쟁·기록 상태와 포함은 모두 검증기가 낸 값이다. 콘솔은 상태를 계산하지 않고, 아무 데도 쓰거나 보내지 않으며, 어떤 장치에도 명령하지 않는다. 판정은 서버에 묻지 않지만 페이지·worker·WASM 모듈·시나리오 목록은 서버가 내려 주므로, 콘솔은 그 사실을 적고 불러온 모듈의 SHA-256(브라우저 Web Crypto)을 보여 직접 빌드한 모듈과 대조하게 한다. 빌드한 페이지는 엄격한 CSP(`default-src 'self'`, 인라인 스크립트·스타일 없음)를 지닌다. 요청마다 번호를 매겨 늦게 온 결과를 버리고, 보이는 파일 이름·시나리오·보고서는 한 결과 객체에서 온다.
2. **관제 콘솔은 없다.** 장치는 고정 일정으로 보내기만 하고(ADR-0022) 증거는 장부에만 있다. 장치를 원격으로 열고 닫거나 설정을 바꾸는 화면은 만들지 않는다. 사람이 하는 일(현장 확인, 마감)은 현장에서 서명하는 사건이며, 콘솔의 현장 확인 양식은 그 내용을 보일 뿐 서명하거나 보내지 않는다.
3. **보일 수 있는 것과 없는 것.**
   - 상태는 일곱 어휘로만 쓴다: `UNVERIFIED`, `LOG_CONSISTENT`, `SOURCE_COMPLETENESS_CHECKED`, `CRYPTO_TALLY_VERIFIED`, `PAPER_AUDITED`, `HOLD_REVIEW`, `LEGAL_CERTIFIED`. 사다리를 그대로 보이고(칸마다 다른 아이콘, 어느 것도 확인 표시가 아니다) 지금 상태마다 "뜻하지 않는 것"을 함께 적는다. 사다리에는 언제나 닿지 않는 것과 `PAPER_AUDITED`에 필요한 것을 적는다: `LEGAL_CERTIFIED`는 검증기가 판정하지 않으며 콘솔은 분쟁에 붙은 법적 결정 참조의 건수만 보이고, `PAPER_AUDITED`에는 감사까지 실린 장부와 호출자가 본 비콘 공표가 함께 있어야 한다. 상태보다 강하게 들리는 말("검증 완료", "정상", "확정", "당선")을 쓰지 않는다.
   - 번들에 든 핀으로 낸 상태는 표지 안에 "(번들에 든 핀으로)"를 적고, 바깥에서 받은 핀으로 다시 검증하기 전에는 어떤 상태에도 확인 표시를 붙이지 않는다.
   - 검증한 선거 ID를 언제나 보이고, `SIM-`으로 시작하면 합성 선거이며 키가 공개된 씨앗에서 유도한 시험 키라는 표지를 띄운다. 시나리오 설명(기대, 주입한 것, 이름, 시연 추적코드)은 번들 바이트의 SHA3-512가 시뮬레이터 목록의 값과 같을 때만 붙인다. 후보 이름은 시뮬레이터 메타데이터에서 오며 열어 본 수의 개수가 후보 수 + 2일 때만 붙인다.
   - 보고 단위별 상태는 장부 전체의 보류 집합에서 다른 단위의 투표함·집계·투표양식 감사에만 있는 사유(그 단위의 것에도 없고 장부 수준 사유도 아닌 것; 받지 못한 집계·감사 이벤트의 보류는 장부 수준)만 뺀 나머지와, 그 단위의 마감 완전성·집계 결과·그 투표양식 감사의 종료를 검증기의 단계 결과와 함께 `ityv_state::status::evaluate`에 넘긴 값이다. 그래서 한 단위가 장부 전체보다 높게 읽히는 것은 장부의 보류가 모두 다른 단위 탓이거나 다른 투표양식이 감사를 끝내지 않았을 때뿐이고, 투표함이 없는 단위는 마감 완전으로 치지 않는다. 장부 전체 상태를 대신하지 않는다고 적는다.
   - 열어 본 수(합계 열기)는 신뢰기관의 열기를 커밋먼트에 대해 확인한 값일 뿐이며 결과의 법적 지위를 뜻하지 않는다. 시연 자료의 모든 이름은 가상이다.
   - 기기 화면의 값 가운데 장부에 출처가 없는 시연 값은 빗금으로 표시하고 기기 틀 밖에 범례를 둔다.
   - 기기 화면은 SCREENS.md의 규칙을 그대로 따른다: 상태기계의 현재 상태와 수만, 판단 문구 없이, 후보 이름·판독 결과·순번·사건 시각·가명·각인 목록 없이. 유권자 확인 앱은 미러 두 곳 또는 공표 지문과 대조한 뒤에만 `LOG_CONSISTENT`를 보이고(PROTOCOL §5.7 4항), 추적코드 하나에 그보다 높은 칸을 붙이지 않는다.
4. **WASM 감싸개 규칙.** `apps/ityv-wasm`은 TCB 밖의 cdylib이다. 의존성은 워크스페이스 크레이트뿐이다(wasm-bindgen·serde 없음). C ABI(`alloc`, `dealloc`, `verify_bundle`, `verify_bundle_with`(다른 핀, 비콘 관찰을 넘길지), `fingerprint`, `result_len`)로 바이트를 받고 손으로 쓴 JSON을 돌려준다. 보고서는 번들의 SHA3-512와 기록마다의 포함 결과를 스스로 지녀, 두 검증 사이에 남는 상태가 없다. `unsafe`는 FFI 모듈 하나에만 두고 항목마다 허용하며 블록마다 SAFETY 주석을 단다. lint는 워크스페이스 집합 그대로이며(산술·변환 lint 포함) 산술은 검사한 연산으로 쓴다: 64비트를 넘는 합은 트랩하지 않고 `null`과 `overflow`로, 2^53 − 1을 넘는 정수는 10진 문자열로 쓴다. TCB가 계산하는 값을 다시 계산하지 않는다. TCB 크레이트에 없는 공개 API가 필요하면 TCB를 고치지 않고 우회하거나 필요한 것을 적어 둔다. 예외는 하나다: 거부된 집계·감사 이벤트가 장부에 남기는 보류(`TallyEvent::hold`, `AuditEvent::hold`)를 `ityv-verify`가 공개했다(개정 1). 이미 있던 비공개 표를 그대로 공개 메서드로 바꾼 것이며 검증기의 동작은 바뀌지 않는다. 감싸개는 브라우저 worker에서 돌아 큰 번들도 쪽을 멈추지 않으며, 트랩하면 worker를 새로 만든다.
5. **핀.** 검증기는 호출자가 준 genesis 핀만 믿는다. 개발 번들에는 핀이 들어 있지만 번들과 같은 출처이므로, 콘솔은 그 사실을 적고 다른 출처의 핀(16진 128자)을 넣어 다시 검증하게 한다.
6. **개발 번들 형식.** `tools/ityv-sim`이 쓰는 번들(magic `ITYVSIMB`, 버전, tag·길이 접두 섹션: 이름, 핀, genesis와 모든 집합, 변경, 프레임 스트림, 이벤트, 공표 기한 입력, 감사한 장부의 비콘 관찰)은 `tools/ityv-sim/README.md`에 적은 개발용 컨테이너다. `ENCODING.md`에 넣지 않고 TCB 크레이트는 읽지 않는다. ADR-0018의 미러 형식(전체·증분, 체크포인트 교환)이 정해지면 그것으로 바꾼다.
7. **시뮬레이터.** `tools/ityv-sim`(M6의 첫 부분)은 고정 씨앗에서 서명된 선거 전체와 이름 붙은 시나리오를 만든다: 상태 사다리의 칸마다 깨끗한 선거(`PAPER_AUDITED`까지), 큰 가상 선거 둘, 감사의 확대·수검표·한 투표양식만 감사, 공격과 장애 28개(개정 2 뒤 34개, 감사 쪽: 뒤바뀐 판독의 전수 대조, 없는 투표지, 비콘을 본 뒤의 고정 체크포인트, 약정보다 이른 고정 체크포인트, 약정 없는 시드, 충돌하는 약정). 시나리오마다 기대 결과(상태와 보류 사유)를 정의의 일부로 두고, Rust 테스트와 콘솔이 실제 판정과 비교한다. 의존성은 워크스페이스 크레이트뿐이며 같은 씨앗은 같은 바이트를 낸다.
8. **JS 공급망 규칙.** 개발 의존성은 정확히 고정한 `typescript` 하나뿐이다(형 검사). 서버·번들러·테스트는 Bun 내장을 쓰고, Bun 형 정의도 손으로 선언한다. `bun.lock`을 커밋하고 `bun install --frozen-lockfile`로만 설치한다. 의존성의 설치 스크립트는 돌지 않는다(`trustedDependencies` 비움). 의존성을 더하려면 README에 이유를 적는다. 화면 캡처 검사는 기기에 설치된 Playwright를 쓰며 의존성으로 들이지 않는다.
9. **화면 시제품과 문구 표.** 기기 화면은 SCREENS.md 표의 TypeScript 모델이며 펌웨어가 아니다. 모든 화면 문구는 SCREENS.md에서 옮긴 고정 문구 표 하나에서 나오고, 값 자리는 형(정수, 식별자, 지문, 상태 어휘)이 정해져 있다. `bun test`가 SCREENS.md의 화면 문구가 표에 글자 그대로 있는지, 금지 문구가 없는지, 자리 형이 허용된 것뿐인지 확인하고, 화면 캡처 검사가 모든 상태·확대·고대비에서 신원 줄이 보이고 맨 아래이며 가려지지 않는지 확인한다(SCREENS §8).

10. **감사.** 감사가 실린 장부에는 검증기의 감사 단계를 그대로 옮긴 감사 칸을 보인다: 비콘 관찰, 약정, 고정 체크포인트, 시드와 그 지문; 고정 체크포인트와 비콘 공표의 시각(약정 < 공표, 고정 ≥ 약정, 고정 ≤ 공표 − 3의 표시용 대조와 선 그림, 판정은 검증기의 시드 수락·거부); 투표양식마다 단계, 라운드별 누적 표본·상한·대조·불일치, 뽑힌 기록(추적코드, 투표함, 열기 흔적, 대조 코드), 전수 대조로 연 기록, 장치별 코드와 발견, 수검표, 보류; 받지 않은 감사 이벤트와 그 이유. 공개 정보만 보인다: 제한 등급의 표본 열기(선택, cast id, 난수)는 번들에도 보고서에도 화면에도 없고 재구성은 "제공 안 됨(공개 검증)"이다. 비콘 관찰은 검증기가 스스로 얻을 수 없는 호출자의 입력이며(genesis 핀과 같다), 여기서는 시뮬레이터가 번들에 넣은 고정 자료라 화면이 그렇게 적는다. 보는 사람은 관찰을 넘기지 않고 다시 검증할 수 있고, 그러면 감사가 끝나지 않아 `CRYPTO_TALLY_VERIFIED`에 머문다.

## 결과

- 누구나 설치 없이 브라우저에서 장부를 검증할 수 있는 첫 경로가 생긴다. 검증 결과는 Rust 테스트가 보는 것과 같은 코드에서 나온다.
- 시나리오의 기대와 판정을 나란히 보이므로, 시연 자료가 곧 자체 시험이다. 둘이 다르면 화면에 불일치가 뜬다.
- SCREENS.md의 문장이 시험 가능한 표가 된다. 규범 문서가 바뀌면 시험이 표를 바꾸라고 알린다.
- 기기 화면의 확대와 고대비, 신원 줄의 자리를 실제 렌더링으로 본다.
- 비용: 번들이 크다(하이브리드 서명). 개발용 큰 번들은 저장소에 넣지 않고 매번 만든다.

## 한계

- 콘솔이 보이는 것은 검증기가 아는 것까지다. 분기 감시·연결·소프트웨어 단계(§14 10–12)가 없으므로 현장 증명 결과와 게이트웨이 화면은 시연용 고정값이다.
- 비콘 관찰은 시연용 고정 자료이며 콘솔은 비콘을 관찰하지 않는다. 실제 검증자는 지정된 비콘의 공표를 직접 확인해 넣어야 한다. 표본 크기가 위험 한도 공식에서 나온 값인지는 검증기도 콘솔도 보지 않는다(ADR-0036 9항).
- 브라우저와 그 확장, 콘솔을 내려 준 곳(페이지, worker, WASM 모듈, 시나리오 목록)은 믿어야 한다. 콘솔이 틀려도 증거는 바뀌지 않지만, 틀린 콘솔은 틀린 판정을 보일 수 있다. 모듈 해시 대조, 독립 2차 구현(V5)과 여러 출처의 콘솔이 견제한다.
- 화면 시제품은 장치가 그 화면을 그린다는 증거가 아니다. 장치가 그리는 것은 장치 자신의 주장이고(SCREENS §0.1), 확인은 현장 증명이 한다.
- 시제품의 신원 줄 지문은 시제품의 문구 표와 이름의 해시이며 릴리스 목록의 이미지 해시가 아니다.
- 현재 genesis는 투표함에 투표양식 하나, 투표소 등식은 확인 한 건에 투표지 한 장이어서 한 방문의 여러 종류 투표지를 검증할 수 없다. 시연 선거는 유권자마다 한 장으로 줄였다.

## 대안

- **관제 콘솔**(장치 상태를 보고 명령하는 화면): 장치에 받는 경로를 만들어야 하며 ADR-0022와 정면으로 충돌한다. 기각.
- **서버에서 검증하고 결과만 보이기**: 판정까지 서버를 믿어야 한다. 브라우저 안 검증은 믿을 대상을 내려 준 코드로 줄이고, 그 코드는 해시로 대조할 수 있다. 기각.
- **wasm-bindgen과 serde**: 편하지만 TCB 밖에도 큰 의존성 나무가 생기고 감사 대상이 늘어난다. 필요한 것은 바이트 입출력과 JSON 하나뿐이다. 기각.
- **UI 프레임워크(React 등)**: 화면이 단순하고, 의존성마다 공급망 위험이 늘어난다. 기각.
- **번들 형식을 `ENCODING.md`에 넣기**: 미러 형식(ADR-0018)이 정해지기 전에 정규 형식을 하나 더 고정하게 된다. 개발용으로 두고 나중에 바꾼다.

## 연결되는 검증

- `tools/ityv-sim/tests/scenarios.rs`: 시나리오마다 기대 상태·보류 사유가 `ityv-verify`와 `ityv-wasm`의 판정과 같음, 경보가 시뮬레이터의 하루와 같음, 번들이 실행마다 같은 바이트.
- `apps/ityv-console/test/strings.test.ts`, `test/screens.test.ts`: 문구 표와 SCREENS.md, 금지 문구, 자리 형, 모든 상태의 문구.
- `apps/ityv-console/scripts/screens.cjs`: 모든 상태·확대·고대비의 신원 줄, 휴대전화 폭.
- `tools/ityv-sim/tests/robustness.rs`: 변형·절단 번들에 패닉 없음, 적대적 이름의 이스케이프, 넘치는 진행 합의 보고, 단위 상태의 귀속(감사 포함), 집계·감사 거부의 보류, 72개 보류 이름 표.
- `tools/ityv-sim/tests/audit.rs`: 감사 시나리오마다 단계·확대·전수 대조·수검표·보관 보류·공격의 거부(`Late`, `Backdated`, `Premature`, `Conflict`)와 고정 체크포인트의 간격, 비콘 관찰 없는 검증, 제한 열기로 재구성, 보고서에 제한 열기가 없음.
- `apps/ityv-console/scripts/races.cjs`: 요청 경쟁, 해시로 붙는 설명, 트랩 회복, 자체 시험 정지, 핀 표지, 감사 칸(고정 자료 표지, 시각 대조, 공개 정보만, 관찰을 끄고 켜기, 확대, 늦은 고정 체크포인트), 없는 기기 상태, CSP 아래의 빌드.
- CI `console` 작업: 고정 설치, 형 검사, 시험, 그리고 `bun run build` 한 경로(wasm32 빌드, 빠른 시나리오 생성, CSP를 넣은 정적 빌드).
- M8 과제: 장치 펌웨어의 화면 렌더링, 정식 문구 표 형식과 `ui_strings_hash`(ENCODING §8.26), 음성 안내와 점자 표기, 미러 두 곳 대조, 실제 장치 데이터로 화면 시험.

## 후속 작업

- 시점확인(ADR-0034)이 연결되어 고정 체크포인트가 TSA 토큰을 지니면 감사 칸의 시각 대조를 그 시각으로 바꾼다.
- 큰 시연 선거에도 감사를 싣는다. 감사 이벤트의 변조(동결 프레임 불일치, 부르지 않은 열기, 수검표 거부) 시나리오를 더한다.

## 개정 1 (2026-11-04, 감사 단계 통합)

1. **TCB 공개 API.** 후속 작업이던 집계 거부의 보류 표를 `ityv-verify`가 `TallyEvent::hold`로 공개했고, 같은 모양의 감사 표를 `AuditEvent::hold`로 공개했다. 둘 다 이미 있던 비공개 함수 `refusal_hold`를 공개 메서드로 바꾼 것이며 `TallyStage::holds`·`AuditStage::holds`가 그것을 쓴다. `apps/ityv-wasm`의 사본은 지웠다.
2. **감사의 표시와 비콘 관찰.** 결정 10항을 더했다. 번들 형식은 버전 2로 비콘 관찰 섹션(0x0008)을 더했고, C ABI의 `verify_bundle_pinned`는 비콘 관찰을 넘길지 고르는 `verify_bundle_with`로 바꿨다. 사다리의 "아직 닿지 않는 것"은 `PAPER_AUDITED`에 필요한 것으로 고쳤다.
3. **시뮬레이터.** 감사 시나리오 10개를 더했다(빠른 묶음 36개, 전체 39개). 명부에 감사인 둘, 법적 승인에 `RLA`·`OBSERVER_ACCESS`를 더했다. 객체의 스키마 버전은 이제 `ityv_encoding::schema_version`에서 가져온다(직접 쓰던 `QuorumSigned` 버전 1이 버전 2가 되며 모든 장부가 보류되었다). 체크포인트의 시각 구간은 이미 줄지 않았다(ADR-0036 개정 2의 사슬 규칙).

## 개정 2 (2026-11-05, 시점확인·명부 보관 통합, ADR-0039·ADR-0040)

1. **번들 형식 3.** 감사 갈래(개정 1)와 시점확인·명부 갈래가 따로 번들 형식을 버전 2로 올렸다(비콘 관찰 섹션 0x0008, GENESIS 섹션의 genesis 집합 12·13). 통합하며 둘을 합친 버전 3으로 올렸다. 형식은 `tools/ityv-sim/README.md`의 "번들 형식"에 있다. 버전 1과 2는 읽지 않는다.
2. **앵커 기한.** 검증기가 장부의 시점확인 토큰으로 정한다(ADR-0039 7항). 번들의 PUBLICATIONS에 있는 체크포인트와 영수증 구간은 읽지 않고, 호출자는 지금 시각과 게시판 기한만 넘긴다.
3. **시뮬레이터.** 체크포인트마다 두 가상 기관(정부 운영과 정부 밖)이 찍는다. 감사의 고정 체크포인트도 시드보다 앞에서 찍으므로 감사 시나리오는 시점확인 규칙(`AuditRefusal::Unstamped`) 아래에서도 같은 결과에 닿는다. `attack-seed-grinding`의 고정 체크포인트는 정직한 기관이 만든 때(공표 뒤)에 찍으므로 토큰 규칙으로도 걸리지만 먼저 걸린 `Late`가 보인다.
4. **시나리오 7개.** `quick-roll-amended`, `attack-checkpoint-backdated`, `fault-anchor-missed`, `attack-tsa-unpinned`, `attack-roll-extract-after-freeze`, `fault-roll-amendment-short`, `attack-binding-unstamped`(빠른 묶음 43개, 전체 46개). 기존 시나리오의 기대 결과는 바뀌지 않았다.
5. **콘솔.** 체크포인트 칸에 체크포인트마다 검증기의 앵커(두 구분, 운영 주체 수, 충족)와 토큰, 받지 않은 시점확인 기록을 보인다. 감사 칸의 고정 체크포인트에는 그 토큰과 시드 앞·공표 전 여부, 네 번째 대조(시드 앞 프레임의 공표 전 토큰이 두 구분·두 운영 주체)를 더했다. 후속 작업의 첫 항목("고정 체크포인트가 TSA 토큰을 지니면 감사 칸의 시각 대조를 그 시각으로")은 증인 시각 대조를 그대로 두고 토큰 대조를 나란히 보이는 것으로 했다: 검증기도 둘 다 요구한다(ADR-0039 8항). 선거인명부 보관 칸은 동결과 변경마다 같은 값의 영수증과 정족수, 명부 가명 root, 효력을 보인다. 모두 읽기 전용이고 공개 정보만이며 CSP는 그대로다. `test/vocab.test.ts`는 감사 거부·감사 이벤트·시점확인 기관 구분·명부 변경 사유·보고서의 단계 이름이 Rust 원본의 모든 변형을 한국어로 덮는지 원본을 읽어 확인하고, 보류 표 시험은 0–76 전부를 본다.

## 개정 3 (2026-11-05, 연결 감사, ADR-0041)

1. **번들 형식 4.** GENESIS 섹션의 서명된 genesis 다음에 genesis가 고정한 연결 목록(`ConnectivityManifest` 객체)을 blob으로 싣는다. 검증기가 그것을 genesis 입력(`GenesisInput::connectivity`)으로 받는다. 버전 3은 읽지 않는다.
2. **시뮬레이터.** 모든 투표소에 게이트웨이(하이브리드 키·증명 키), 모든 스캐너와 카운터·가명 유닛에 프레임 키가 있다. 연결 목록은 기준값(스캐너 16, 유닛 4, 따라잡기 64)을 쓴다. 장치는 개시부터 마감 구간 다음 슬롯까지 슬롯마다 그 수의 프레임을 보내고, 게이트웨이는 투표소 개시부터 여섯 슬롯마다 프레임 기록과 세션을, 참여 집합 뒤에 `final` 세션을 싣는다(투표소의 두 참관인이 캡처 서명). 세션은 계획의 단계(`Step::Uplink`)이고 장부를 깔 때 그때까지 깐 장치 이벤트로 만들어지므로 장부를 바꾸는 공격도 그 장부를 그대로 나른다. 장애는 세션에 붙인다(`uplink::Fault`).
3. **시나리오 12개.** `attack-manifest-two-way`(79), `attack-uplink-hidden-frame`(80), `attack-uplink-injected-frame`·`fault-uplink-padding`·`fault-uplink-extra-frame`·`fault-uplink-after-close`(81), `attack-uplink-batch-order`(82), `fault-uplink-lost-frame`·`attack-hidden-path-record`(83), `fault-roll-line-incident`·`fault-capture-mismatch`(84), `attack-incident-forged`(85). 빠른 묶음 55개, 전체 58개. 기존 시나리오의 기대 결과는 바뀌지 않았다.
4. **WASM.** 보고서에 `connectivity`(목록의 어긴 규칙, 투표소마다 세션·창·`final`·캡처 서명 수·바깥 회선 바이트·세션 발견, 링크마다 프레임·객체·포함·확인한 덩어리와 봉인 덩어리·발견, 링크 밖 장치 이벤트, 사건과 전수 대조 대상)를 더했다. 보고 단위의 상태는 그 단위 투표함들의 투표소가 모두 `final` 세션을 가질 때 11단계를 통과로 본다. 연결 단계의 투표함 보류와 장부 보류도 단위 판정에 들어간다.
5. **콘솔.** 대시보드에 '연결 감사' 칸(투표소·링크 표, 발견, 사건)과 보류 79–85, 연결 판정 어휘를 더했다. 단계 이름의 '아직 구현 안 됨'을 지웠다. 게이트웨이 장치 화면은 여전히 장치의 실시간 계수를 보이는 시연 값이고(장부에 없다), 장부에 실린 세션은 연결 감사 칸이 보인다. `test/vocab.test.ts`는 연결의 판정·장치 종류·사건 종류가 Rust 원본의 모든 변형을 한국어로 덮는지 보고, 보류 표 시험은 0–85 전부를 본다.

## 개정 4 (2026-11-06, 자기 기술 프레임, ADR-0041 2i 검토)

1. **시뮬레이터.** 장치의 프레임이 데이터에 걸친 모든 객체를 목록으로 적어 서명한다. 기록마다 그 기록이 가리키는 봉인 share 패키지(그 투표함과 커밋먼트로 만든 대리 객체)를 기록 바로 뒤에, 프레임의 4 KiB 경계에 싣는다. 창의 데이터 슬롯에서 진행 기록 등을 먼저, 닫힌 배치는 그다음 프레임부터 싣는다. 스캐너의 마감 슬롯은 따라잡기 묶음 64개로, 남은 객체 다음에 모든 배치를 마감 재전송으로 다시 싣는다. 장애 `Lose`는 프레임 번호를 받고, `Covert`(목록에 없는 바이트와 빈 슬롯)·`Relist`(게이트웨이가 바꿔 적은 목록)를 더했다.
2. **시나리오 3개.** `fault-uplink-recovered-loss`(보류 없음), `attack-uplink-covert-bytes`(82), `attack-uplink-relisted-object`(81, 83). 빠른 묶음 58개, 전체 61개. `attack-mirror-tampered`는 `UplinkObjectInvalid`를 더 건다: 미러가 바꾼 기록은 거부된 프레임이라 그 뒤의 share 패키지를 받아들여진 기록이 가리키지 않는다. `fault-uplink-after-close`는 같은 보류에 `KindOrder` 발견 16개가 더 붙는다(마감 재전송 뒤의 일반 프레임). 나머지 기대 결과는 그대로다.
3. **콘솔.** 링크 판정 어휘에서 `Early`를 빼고 `Alignment`·`Foreign`을, 사건 판정에 `Scope`를 더했다.


## 개정 5 (2026-11-06, 배치를 따르는 묶음, ADR-0041 2i 둘째 검토)

1. **시뮬레이터.** 배치는 앞 배치 뒤의 카운터를 이으므로 링크의 배치는 가장 오래 기다린 기록을 담는다(출력은 그대로). 장애 `Singled`(기록마다 배치 증명을 다시 붙임)와 `Mislabel`(패키지 뒤의 숨은 바이트를 다른 스키마의 장부 해시로 적음)을 더했다.
2. **시나리오 2개.** `attack-uplink-singled-records`(82), `attack-uplink-mislabeled-object`(82). 빠른 묶음 60개, 전체 63개. 세 시나리오가 `UplinkObjectInvalid`를 더 건다: `attack-hidden-path-record`(업링크로 오지 않은 기록 자리에서 잃은 바이트 없이 배치의 묶음이 끊김), `attack-tampered-record`(묶음에 기록 단계가 거부해 어느 배치에도 들지 않는 기록), `attack-no-authorization`(투표함 이벤트가 거부되어 기록 단계가 받은 배치가 없으므로 링크의 기록이 어느 배치에도 들지 않음). 나머지 기대 결과는 그대로다.
3. **콘솔.** 링크 판정 어휘에 `AfterSwap`·`Schema`·`Repeat`·`Time`을 더하고 `KindOrder`·`Batch`의 설명을 넓혔다(23개).

## 개정 6 (2026-11-06, 종류의 자리와 재전송, ADR-0041 2i 셋째 검토)

1. **시뮬레이터.** 닫힌 배치를 다음 창의 첫 슬롯에서 무엇보다 먼저 한 번 더 보낸다(둘째 사본, PROTOCOL §5.8 4항). 마감 슬롯에 나간 배치는 마감 재전송이 둘째 사본이다. 기대 결과는 하나도 바뀌지 않았다. 장애 `WitnessedMidday`(투표 중의 입회 재전송 묶음)를 더했다.
2. **시나리오 1개.** `attack-uplink-witnessed-midday`(81). 빠른 묶음 61개, 전체 64개. 나머지 기대 결과는 그대로다. 무시 시험 `no_cut_of_an_honest_ledger_holds_a_link`는 정직한 장부를 프레임마다 잘라 연결 보류가 없음을 본다.
3. **콘솔.** 링크 판정 어휘에 `BeforeSwap`·`Resend`를 더하고 `KindOrder`·`Batch`·`Package`의 설명을 고쳤다(25개).

## 개정 7 (2026-11-11, 개표상황표 두 시나리오, 법령 부속서 개정안 16)

1. **시뮬레이터.** 한 투표양식이 보고 단위 둘로 세어지는 가장 작은 선거 `SIM-QUICK-UNITS`(`catalog::quick_two_units`)를 더했다. SIM-QUICK에서 사전투표소의 관외 투표함(한빛구청장)을 `RU-HB-OUT`(관외 사전투표, PROTOCOL §4.1)으로 따로 세고, 선거일 투표함은 `RU-HB`에 둔다. 두 단위 모두 한빛구 위원회가 보고하므로 `Election::build`는 위원회마다 위원장 한 명을 두고 명부에 한 번만 적는다. 기존 선거는 위원회마다 단위가 하나여서 위원장, 명부, 묶음이 그대로다.
2. **시나리오 2개.** `attack-count-sheet-copied`는 `RU-HB`의 종이 계수 보고에 `RU-HB-OUT`의 후보별 득표와 무효 수를 그대로 옮겨 적는다. `HOLD_REVIEW`(`PaperCountMismatch`)만 걸린다. 수를 빌려 준 단위와 누리구 단위는 `CRYPTO_TALLY_VERIFIED`다. `attack-count-sheet-rewritten`은 바른 보고를 체크포인트가 덮은 뒤 같은 단위에 한 표를 옮긴 둘째 보고를 싣는다. `HOLD_REVIEW`(`PaperCountRefused`, `Paper: Conflict`, ADR-0035 11항)만 걸리고, 대조는 처음 보고로 하므로 `PaperCountMismatch`는 없다. 두 보고 모두 장부에 남는다. 둘 다 빠른 묶음이다. 빠른 묶음 63개, 전체 66개. 기존 64개 묶음은 바이트가 같다. 검증기는 바뀌지 않았다.
3. **콘솔.** 어휘는 그대로다. 받지 않은 이벤트 카드는 다른 집계 거부처럼 `Paper: Conflict`를 원 코드로 보인다.
