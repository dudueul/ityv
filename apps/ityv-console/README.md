# ityv-console

> English summary: The read-only public verification console and the prototypes of the field devices' screens (ADR-0038). Outside the TCB, development only, never for a real election. The dashboard runs the real verifier in the browser (`ityv-verify` compiled to WebAssembly through `apps/ityv-wasm`, in a worker) over a simulator bundle the viewer picks or drops, and shows the status ladder in the exact seven-word vocabulary with what each status does not mean, expected against actual for each scenario, holds with code and Korean explanation, per-unit status, refused events, checkpoint fingerprints, progress and alarms, and tracking-code inclusion proofs. The device pages draw every screen of `docs/ui/SCREENS.md` §1–§7 in a device frame with a state picker, zoom 1×/1.5×/2× and high contrast, with the fixed identity line and its "소프트웨어 확인" detail view; every on-screen string comes from one string table transcribed from SCREENS.md and checked against it by `bun test`. The device flows are a TypeScript model of the SCREENS.md tables; device firmware does not exist yet (M8). Bun's built-in HTML server and bundler; the only devDependency is `typescript`, pinned.

## 쓰는 법

```sh
cd apps/ityv-console
bun install --frozen-lockfile
bun run dev          # WASM 검증기와 시뮬레이터 번들(전체)을 만든 뒤 http://127.0.0.1:3000/ 에서 연다
bun run build        # 같은 준비 뒤 정적 파일을 dist/에 (dist/index.html을 정적 서버로 연다)
bunx tsc --noEmit    # 형 검사
bun test             # 문구 표와 화면 모델 시험
node scripts/screens.cjs <출력 디렉터리>   # 화면 캡처 검사(아래)
```

`bun run dev`와 `bun run build`는 먼저 `scripts/data.ts`를 돌린다. 이 스크립트는 저장소 루트에서 `cargo build --locked -p ityv-wasm --target wasm32-unknown-unknown --release`와 `cargo run --locked --profile release -p ityv-sim -- public/bundles`를 실행하고 WASM을 `public/`에 복사한다. `ITYV_SIM_SET=quick`이면 빠른 묶음(25개, 약 6초)만, 기본은 전체(28개, 약 14초)를 만든다. `ITYV_SIM_PROFILE`로 cargo 프로필을 바꾼다(`dev`, `test`). 포트는 `PORT`, 주소는 `HOST`(기본 127.0.0.1). `rustup target add wasm32-unknown-unknown`이 먼저 필요하다. 만든 파일(`public/ityv_wasm.wasm`, `public/bundles/`, `dist/`)은 저장소에 넣지 않는다.

## 쪽

- **검증 대시보드** (`#/dashboard`): 시나리오를 "정상 선거"와 "공격·장애"로 묶어 고르거나 번들 파일을 놓는다. 파일은 브라우저 밖으로 나가지 않는다. 검증은 worker 안의 WASM이 한다(서버 신뢰 없음). 보이는 것: 상태 사다리(일곱 어휘만, 지금 상태와 그 상태가 뜻하지 않는 것; `HOLD_REVIEW`와 `LEGAL_CERTIFIED`는 사다리 밖에 따로), 시나리오의 기대(시뮬레이터 `index.json`)와 실제(검증기) 및 불일치 표시, 쓴 핀의 지문과 다른 핀을 넣는 칸, 보류 사유(코드·이름·한국어 설명), 단계별 결과, 보고 단위별 상태·열어 본 수·종이 대조, 투표함, 투표소별 바깥 장수 그래프와 경보(표 보기 포함), 체크포인트 지문, 받지 않은 이벤트(프레임·스키마·단계·이유), 분쟁, 추적코드 포함 확인, 빠른 시나리오 전체 자체 시험.
- **기기 화면 시제품** (`#/devices/<기기>?state=…&zoom=1.5&hc=1&detail=1`): SCREENS.md §1 투함 스캐너 유권자 화면(표의 11개 상태, 단추, 화면 밖 촉각 단추), §2 사무원·참관인 화면, §3 확인 장치 사무원 화면, §4 분류기 확장, §5 게이트웨이, §6.1 참관인 앱 현장 증명 결과, §6.2 참관인 앱 진행과 경보, §7 유권자 확인 앱. 모든 화면 맨 아래에 신원 줄과 "소프트웨어 확인"이 있고, 상세 화면은 내용 영역 안에서 열려 신원 줄을 가리지 않으며, 유권자 화면에서 열면 10초 뒤 돌아간다. "시제품" 표지와 상태 선택은 기기 틀 밖에 있다.

## 무엇이 실제 계산이고 무엇이 모델인가

| 화면의 값 | 출처 |
|---|---|
| 상태, 보류 사유, 단계, 체크포인트와 그 지문, 받지 않은 이벤트, 분쟁, 기록 상태 | `ityv-verify`(WASM) |
| 보고 단위별 상태 | 검증기 단계 결과를 단위로 좁혀 `ityv_state::status::evaluate`(WASM) |
| 진행 경보와 정지(§6.2), 경보 그래프 | `ityv-verify`의 진행 기록 단계(WASM); 칸별 수는 검증기가 받은 진행 기록, 바깥 장수는 `ityv_state::out_of` |
| 추적코드 포함(§7, 대시보드) | `ityv_ledger::inclusion_proof`·`verify_inclusion`(WASM), 검증된 체크포인트 root에 대해 |
| 사무원 화면 수(§2), 분류기의 기록·비상 투입 수(§4), 확인 장치 누적 인원(§3) | 검증기가 읽은 마감 기록·진행 기록 |
| 분류기 칸별 종이 수 | 시뮬레이터가 만든 종이(시연 자료, `index.json`) |
| 현장 증명 결과(§6.1), 게이트웨이(§5) | 시연용 고정값(`src/data.ts`, 화면 옆에 표시). 장부에 `DeviceAttestation`·`UplinkSession`이 아직 없다(검증기 11·12단계) |
| 화면 흐름(대기 → 읽는 중 → 결정 …), 상태별 화면 | SCREENS.md 표의 TypeScript 모델(`src/screens.ts`). 장치 펌웨어가 아니다 |
| 신원 줄의 지문 | 시제품의 이름·버전·빌드와 문구 표를 `fingerprint`(WASM, SHA3-512)에 넣은 값. 릴리스 목록의 이미지 해시가 아니다 |

## 고정 문구 표

`src/strings.ts`가 화면의 유일한 문구 출처다. 항목은 ID, 한국어 문자열, 형이 정해진 값 자리(`count`, `sheet`, `slotTime`, `minutes`, `identifier`, `fingerprint16`, `fingerprint32`, `status` 등: SCREENS §0.2의 정수·식별자·지문·상태 어휘), 출처(`SCREENS §n` 또는 `prototype`)다. SCREENS.md에서 옮긴 항목은 SCREENS.md의 자리 표시(N, 7, 10:40…)를 넣으면 그 문장이 글자 그대로 나온다. 자리에 다른 형의 값을 넣으면 화면 그리기가 실패한다. `prototype` 항목은 SCREENS.md가 내용만 정하고 문장을 정하지 않은 표지다(예: 사무원 화면의 "닫힌 배치 N"). 정식 문구 표 형식과 `ui_strings_hash`(ENCODING §8.26)는 M8 과제다.

`bun test`(`test/strings.test.ts`, `test/screens.test.ts`)가 확인하는 것:
- SCREENS.md §0.1과 §1–§7에 따옴표로 적힌 화면 문구, §1 표의 단추, "소프트웨어 확인", 괄호로 나열한 상태·이유 코드·판정이 모두 표에 글자 그대로 있다. 따옴표지만 화면 문구가 아닌 둘("연결 없음": 연결 목록 값, "읽는 중": 상태 이름)은 이유와 함께 뺀다.
- SCREENS.md가 금지한 판단 문구("정상", "부정 감지", "인증됨", "집계됨", "당신의 표가 반영되었습니다", "인증된 소프트웨어", "확정", "집계 완료", "귀하의 표가 집계되었습니다", "투표가 인증되었습니다", "오늘 N번째")가 표 어디에도 없다.
- 값 자리는 허용된 종류뿐이고, 후보·판독 결과·순번·사건 시각·가명·각인 목록을 담는 자리가 없다.
- 모든 기기의 모든 상태를 그린 문구에 후보 이름, BLANK·UNREADABLE, 순번, 초 단위 시각, 둘 이상의 추적코드가 없다. 유권자 앱은 상호 대조 전에는 `LOG_CONSISTENT`를 보이지 않고, 장부 상태가 더 높아도 추적코드 하나에 `LOG_CONSISTENT`보다 높은 칸을 붙이지 않는다.
- §1 유권자 화면의 흐름(읽는 중에는 결정 없음, 고른 장이 없으면 확인 단추가 꺼짐 등).

## 화면 캡처 검사 (SCREENS §8)

`node scripts/screens.cjs <출력 디렉터리>`는 이 기기에 설치된 Chromium과 Playwright를 쓴다(이 패키지의 의존성이 아니다. `playwright install`을 하지 않는다). `ITYV_CONSOLE_URL`이 없으면 `bun server.ts`를 직접 띄운다(먼저 `bun run data`). 모든 기기의 모든 상태를 1×·1.5×·2×, 보통·고대비, 상세 화면 닫힘·열림으로 그려서 확인한다: 신원 줄이 보이고, 화면의 맨 아래 줄이며, 잘리지 않고, 다섯 점 어디서도 다른 요소가 그 위에 없고, 본문 글자가 화면 높이의 4%×확대 이상, 신원 줄이 2.5% 이상이다. 상세 화면 닫힘 상태마다 기기 틀의 캡처(deviceScaleFactor 1)를 저장한다. 끝으로 375px 폭에서 대시보드와 모든 기기 쪽에 가로 스크롤이 없는지 보고 전체 캡처를 저장한다. 실패가 하나라도 있으면 종료 코드 1이다.

## 의존성

- `typescript` 5.9.3(정확히 고정, `tsc --noEmit`만): 형 검사. 실행 코드에는 들어가지 않는다.
- 그 밖에는 없다. 서버·번들러·테스트는 Bun 1.4.4에 들어 있다. Bun 형 정의(`@types/bun`)도 넣지 않고 쓰는 API만 `types/bun.d.ts`에 손으로 선언했다. `bun.lock`을 저장소에 두며 `bun install --frozen-lockfile`로 설치한다. `trustedDependencies`가 비어 있어 의존성의 설치 스크립트는 돌지 않는다(typescript에는 그런 스크립트가 없다).

## 하지 않는 것

- 장치에 명령하지 않는다. 대시보드도 기기 화면도 읽기만 한다. 현장 확인 양식(§6.2)은 내용만 보이고 서명하거나 보내지 않는다(ADR-0022, ADR-0038).
- 상태를 계산하지 않는다. 사다리의 설명 문장은 검증기가 준 상태에 붙는 설명일 뿐이다.
- 음성 안내를 내지 않는다(헤드폰 단자 전용, SCREENS §0.3). 촉각 단추의 점자 칸은 자리만 보인 것이며 실제 점자 표기는 M8에서 정한다.
- 미러 두 곳 대조를 하지 않는다. 유권자 앱은 대조 결과를 상태로 고르며 대조 전에는 `LOG_CONSISTENT`를 보이지 않는다.
