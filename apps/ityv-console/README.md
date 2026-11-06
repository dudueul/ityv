# ityv-console

> English summary: The read-only public verification console and the prototypes of the field devices' screens (ADR-0038). Outside the TCB, development only, never for a real election. The dashboard runs the real verifier in the browser (`ityv-verify` compiled to WebAssembly through `apps/ityv-wasm`, in a worker) over a simulator bundle the viewer picks or drops, and shows the verified election ID (with a banner for synthetic `SIM-` elections), the status ladder in the exact seven-word vocabulary with what each status does not mean and what no bundle reaches yet, expected against actual for each scenario (only when the bundle's SHA3-512 matches `index.json`), holds with code and Korean explanation, per-unit status, refused events, checkpoint fingerprints, progress and alarms, and tracking-code inclusion verified inside the report. No status carries a check mark until it was verified under a pin entered from outside the bundle. Every request has a ticket and stale results are dropped; a trap replaces the worker. The device pages draw every screen of `docs/ui/SCREENS.md` §1–§7 in a device frame with a state picker, zoom 1×/1.5×/2× and high contrast, with the fixed identity line and its "소프트웨어 확인" detail view; demonstration values without a ledger source are hatched, with a legend outside the frame. Every on-screen string comes from one string table transcribed from SCREENS.md and checked against it by `bun test`. The device flows are a TypeScript model of the SCREENS.md tables; device firmware does not exist yet (M8). Bun's built-in HTML server and bundler; the only devDependency is `typescript`, pinned. The built page carries a strict Content Security Policy.

## 쓰는 법

```sh
cd apps/ityv-console
bun install --frozen-lockfile
bun run dev          # WASM 검증기와 시뮬레이터 번들(전체)을 만든 뒤 http://127.0.0.1:3000/ 에서 연다
bun run build        # 같은 준비 뒤 정적 파일을 dist/에 (CSP 포함)
bun run preview      # dist/를 CSP 헤더와 함께 http://127.0.0.1:3001/ 에서 연다
bunx tsc --noEmit    # 형 검사
bun test             # 문구 표와 화면 모델 시험
node scripts/screens.cjs <출력 디렉터리>   # 화면 캡처 검사(아래)
node scripts/races.cjs                    # 요청 경쟁·오류 경로·CSP 검사(아래)
```

`bun run dev`와 `bun run build`는 먼저 `scripts/data.ts`를 돌린다. 이 스크립트는 저장소 루트에서 `cargo build --locked -p ityv-wasm --target wasm32-unknown-unknown --release`와 `cargo run --locked --profile release -p ityv-sim -- public/bundles`를 실행하고 WASM을 `public/`에 복사한다. `ITYV_SIM_SET=quick`이면 빠른 묶음(60개)만, 기본은 전체(63개)를 만든다. `ITYV_SIM_PROFILE`로 cargo 프로필을 바꾼다(`dev`, `test`). 포트는 `PORT`, 주소는 `HOST`(기본 127.0.0.1). `rustup target add wasm32-unknown-unknown`이 먼저 필요하다. 만든 파일(`public/ityv_wasm.wasm`, `public/bundles/`, `dist/`)은 저장소에 넣지 않는다. CI는 `bun run build` 한 경로로 WASM, 빠른 번들, `dist/`를 만든다.

## 무엇을 믿는가

판정은 브라우저 안의 WASM 검증기가 내며 서버에 묻지 않는다. 그러나 페이지, worker(`public/verify-worker.js`), WASM 모듈, 시나리오 목록(`index.json`)은 서버가 내려 준다. 서버를 믿지 않으려면 같은 소스에서 직접 빌드한 모듈의 SHA-256과 대시보드 맨 위에 보이는 값(브라우저의 Web Crypto가 계산)을 대조한다. 시나리오 설명(기대 상태, 주입한 것, 이름, 시연 추적코드)은 번들 바이트의 SHA3-512가 `index.json`에 적힌 값과 같을 때만 붙는다. 파일 이름은 보이기만 하고 아무것도 정하지 않는다. 검증한 선거 ID는 언제나 보이며, `SIM-`으로 시작하면 "합성 선거, 공개된 시험 키" 표지를 띄운다. 후보 이름은 시뮬레이터 메타데이터에서 오며, 열어 본 수의 개수가 그 투표양식의 후보 수 + 2(BLANK, UNREADABLE)일 때만 붙인다.

## 쪽

- **검증 대시보드** (`#/dashboard`): 시나리오를 "정상 선거"와 "공격·장애"로 묶어 고르거나 번들 파일(256 MB까지)을 놓는다. 파일은 브라우저 밖으로 나가지 않는다. 보이는 것: 파일 이름·번들 해시·시나리오, 검증한 선거 ID, 상태 사다리(일곱 어휘만, 칸마다 다른 아이콘, 지금 상태와 그 상태가 뜻하지 않는 것, 닿지 않는 것과 `PAPER_AUDITED`에 필요한 것: 감사까지 실린 장부와 호출자가 본 비콘 공표; `HOLD_REVIEW`와 `LEGAL_CERTIFIED`는 사다리 밖에 따로), 시나리오의 기대와 실제 및 불일치 표시, 쓴 핀의 지문과 다른 핀을 넣는 칸, 보류 사유(코드 0–85·이름·한국어 설명), 단계별 결과, 보고 단위별 상태·열어 본 수·종이 대조, 감사(아래), 투표함, 투표소별 바깥 장수 그래프와 경보(표 보기 포함, 넘친 칸은 띠로), 체크포인트 지문, 받지 않은 이벤트(프레임·스키마·단계·이유), 분쟁(법적 결정 참조는 건수만), 추적코드 포함 확인, 빠른 시나리오 전체 자체 시험(번들 해시까지 비교, 다른 쪽으로 옮기면 멈춤).
- **기기 화면 시제품** (`#/devices/<기기>?state=…&zoom=1.5&hc=1&detail=1`): SCREENS.md §1 투함 스캐너 유권자 화면(표의 11개 상태, 단추, 화면 밖 촉각 단추), §2 사무원·참관인 화면, §3 확인 장치 사무원 화면, §4 분류기 확장, §5 게이트웨이, §6.1 참관인 앱 현장 증명 결과, §6.2 참관인 앱 진행과 경보, §7 유권자 확인 앱. 모든 화면 맨 아래에 신원 줄과 "소프트웨어 확인"이 있고, 상세 화면은 내용 영역 안에서 열려 신원 줄을 가리지 않으며, 유권자 화면에서 열면 10초 뒤 돌아간다. "시제품" 표지와 상태 선택은 기기 틀 밖에 있다. 없는 상태를 주면 첫 상태를 그리고 그렇다고 알린다.

### 감사

감사가 실린 장부에는 감사 칸이 있다. 모든 값은 검증기의 감사 단계(`AuditStage`)가 낸 것이다.
- 시드의 입력: 비콘 관찰(회차, 공표 구간과 그 시각, 공표 출력, 비콘 값 지문), 감사 약정(프레임, 시각 구간, 주사위 기록·비콘 지정 지문), 고정 체크포인트(순번, 프레임, 시각 구간, 지문), 시드(지문, 관찰한 비콘 값과 같은지).
- 고정 체크포인트와 비콘 공표의 시각: 약정·고정 체크포인트·한계(`P − 3`)·공표를 그린 선과 세 대조(약정 < 공표, 고정 ≥ 약정, 고정 ≤ 공표 − 3, 여유 구간 수). 대조는 표시용이며 판정은 검증기의 시드 수락·거부(`Late`, `Backdated`)다.
- 투표양식마다: 단계(표본 대조 중 n라운드, 종료, 수검표)와 감사 끝 여부, 프레임 수와 root 지문, 위험 한도, 라운드별 누적 표본·상한·대조·불일치(넘으면 "상한 넘음 → 확대"), 뽑힌 기록(순서, 추적코드 앞 16자, 투표함, 열기 흔적 프레임, 대조 코드 0–6의 한국어, 재구성 여부), 전수 대조로 연 기록, 장치별 코드 수·전수 대조·발견·보류, 수검표, 그 투표양식의 보류.
- 받지 않은 감사 이벤트(이벤트, 거부 사유의 한국어).
- 고정 체크포인트의 시점확인 토큰(기관, 운영 주체, 정부 운영·정부 밖, 기록 프레임, 가장 늦은 순간의 구간, 시드 앞 프레임인지, 공표 구간 전인지)과 넷째 대조: 시드 앞 프레임의 공표 전 토큰이 두 구분·두 운영 주체에서 있는가(ADR-0039 8항). 표시용이며 판정은 검증기의 `Unstamped` 거부다.

### 연결 감사

- 연결 감사 칸(ADR-0041): 투표소마다 게이트웨이, 세션 수, 창, `final` 세션, 참관인 캡처 서명 수, 바깥 회선 바이트와 판정; 그 아래 링크마다(스캐너, 카운터·가명 유닛) 일반·따라잡기 프레임 수, 슬롯 범위, 객체와 포함된 장부 이벤트 수, 빠진 슬롯, 확인한·봉인 덩어리, 발견. 그 밑에 연결 목록이 어긴 규칙, 세션 발견, 링크 밖 장치 이벤트, 아직 받지 않은 기록, 사건(종류, 범위, 구간, 받지 않은 이유, 전자 층 보류, 종이 전수 대조 대상과 대조 여부).
- 캡처와 통신사 기록의 대조는 장부 밖 입력이라 콘솔에 없다. 그 결과는 사건으로 장부에 실려 이 칸에 보인다.

### 시점확인과 명부 보관

- 체크포인트 칸: 체크포인트마다 시각 구간과 검증기의 앵커(정부 운영·정부 밖 토큰이 있는지, 운영 주체 수, 충족 여부, 토큰 수; 마우스를 올리면 토큰마다 기관·운영 주체·가장 늦은 순간·창 밖 여부), 받지 않은 시점확인 기록(프레임, 기관, 문제), 토큰과 응답 없음 기록의 수(VC-115, ADR-0039).
- 선거인명부 보관 칸: 동결과 변경마다 프레임, 인원, 같은 값의 영수증을 낸 보관 기관 수와 정족수(이름), 명부 가명 root 확인, 효력. 변경은 사유와 출처 기관을 적는다. 받지 않은 명부 사건과 명부 값과 다른 영수증, 투표 마감 뒤에 기록된 변경과 추출이 없는 선거일 투표소(보류 78), 투표 마감 프레임(개인 확인이 비교할 명부의 시점), 이의 투표 기록의 수(제한 등급이라 프레임만)(VC-107..111, ADR-0040).

모두 검증기의 값을 옮긴 것이고 공개 정보만 보인다.

공개 정보만 보인다. 제한 등급의 표본 열기(선택, cast id, 난수)는 번들에도 화면에도 없고, 재구성은 언제나 "제공 안 됨(공개 검증)"이다.

비콘 관찰은 시뮬레이터가 번들에 넣은 시연용 고정 자료이며 화면에 그렇게 적는다. 검증기는 비콘을 직접 받지 못하므로 호출자가 본 공표를 넘긴다. "비콘 관찰을 검증기에 넘김" 칸을 끄면 같은 번들을 같은 핀으로 관찰 없이 다시 검증한다. 그러면 감사가 끝날 수 없어 감사한 장부도 `CRYPTO_TALLY_VERIFIED`에 머문다(보류는 아니다). 시나리오의 기대는 관찰을 넘긴 검증의 값이다. 자체 시험은 언제나 관찰을 넘긴다.

### 상태 표지와 핀

상태 표지는 번들에 든 핀으로 검증했으면 표지 안에 "(번들에 든 핀으로)"를 적고 확인 표시를 붙이지 않는다. 바깥에서 받은 핀을 넣어 다시 검증했을 때만, 그리고 상태가 `HOLD_REVIEW`나 `UNVERIFIED`가 아닐 때만 확인 표시가 붙는다. 넣은 핀이 번들의 핀과 같은지 다른지는 핀 칸에 적는다.

### 요청 처리

요청(시나리오 고르기, 파일 놓기, 다른 핀)마다 번호를 매기고, 새 요청은 진행 중인 것을 취소하며(그 worker를 끝낸다), 번호가 최신이 아닌 결과는 버린다. 보이는 파일 이름·시나리오·보고서는 언제나 한 결과 객체에서 온다. 모든 진입점에서 오류를 잡아 보고서를 지우고 오류를 보인다. 모듈이 트랩하면 worker를 끝내고 다음 요청에서 새로 만든다. 자체 시험과 기기 쪽은 각자의 worker를 쓴다. 추적코드 조회는 보이는 보고서의 기록별 포함 결과를 읽을 뿐 worker에 묻지 않는다.

## 무엇이 실제 계산이고 무엇이 모델인가

| 화면의 값 | 출처 |
|---|---|
| 상태, 보류 사유, 단계, 체크포인트와 그 지문, 받지 않은 이벤트, 분쟁, 기록 상태 | `ityv-verify`(WASM) |
| 보고 단위별 상태 | 장부 보류에서 다른 단위에만 있는 사유(투표함·집계·투표양식 감사)를 뺀 것과 그 단위의 마감·집계·투표양식 감사 종료를 `ityv_state::status::evaluate`(WASM) |
| 감사(동결, 약정, 고정 체크포인트, 시드, 표본, 대조, 확대, 전수 대조, 수검표) | `ityv-verify`의 감사 단계(WASM). 비콘 값은 `ityv_crypto::beacon_value` |
| 비콘 관찰(회차, 출력, 공표 구간), 주사위 기록, 비콘 지정 | 시뮬레이터의 고정 자료(번들). 경고 띠로 표시 |
| 진행 경보와 정지(§6.2), 경보 그래프 | `ityv-verify`의 진행 기록 단계(WASM); 칸별 수는 검증기가 받은 진행 기록, 바깥 장수는 `ityv_state::out_of` |
| 추적코드 포함(§7, 대시보드) | 보고서의 기록별 결과: `ityv_ledger::verify_inclusion`(WASM), 그 기록을 덮는 첫 검증된 체크포인트 root에 대해 |
| 사무원 화면의 기록·확인·격리·방문·스티커 수와 지금 배치의 채움(§2), 분류기의 기록·비상 투입 수(§4), 확인 장치 누적 인원(§3) | 검증기가 읽은 마감 기록·진행 기록·투함 기록 |
| 분류기 칸별 종이 수 | 시뮬레이터가 만든 종이(시연 자료, `index.json`). 빗금 |
| 사무원 화면의 닫힌 배치 수·참관 서명까지 남은 수와 시간, 저널·송신 프레임·밀린 배치·챔버 모듈·현장 증명(§2); 확인 장치의 공동 서명 대기 2건, 교부·훼손·반납 1장(§3) | 시연 값. 빗금 |
| 현장 증명 결과(§6.1), 게이트웨이(§5) | 시연용 고정값(`src/data.ts`). 빗금. 장부에 `DeviceAttestation`이 아직 없다(검증기 12단계). 게이트웨이 화면은 장치의 실시간 계수라 장부에 없고, 장부에 실린 세션은 대시보드의 연결 감사 칸이 검증기의 값으로 보인다. §6.1의 구성 지문은 스캐너 시제품의 신원 줄 지문이다 |
| 화면 흐름(대기 → 읽는 중 → 결정 …), 상태별 화면 | SCREENS.md 표의 TypeScript 모델(`src/screens.ts`). 장치 펌웨어가 아니다 |
| 신원 줄의 지문 | 시제품의 이름·버전·빌드와 문구 표를 `fingerprint`(WASM, SHA3-512)에 넣은 값. 릴리스 목록의 이미지 해시가 아니다 |

빗금 친 값은 화면 모델에서 `demo`로 표시한 블록이며, 기기 틀 밖에 빗금의 뜻을 적은 범례가 있다. 화면 캡처는 틀과 범례를 함께 찍는다.

보고서의 정수는 2^53 − 1까지 수로, 그 위는 10진 문자열로 온다(`src/data.ts`의 `Int`). 콘솔은 글자로 보일 때 그 값을 그대로 쓰고, 슬롯 시각은 BigInt로 계산한다. 그래프만 근사한 수를 쓴다.

## 고정 문구 표

`src/strings.ts`가 화면의 유일한 문구 출처다. 항목은 ID, 한국어 문자열, 형이 정해진 값 자리, 출처(`SCREENS §n` 또는 `prototype`)다. 값 자리의 종류는 SCREENS §0.2의 넷과 하나다.
- 정수(`count`, `sheet`, `minutes`, `percent`, `build`, `slotTime`).
- 식별자(`identifier`, `errorCode`: ASCII 영숫자와 `. _ : / -`, 64자까지; `trackingCode`: 16진 8자 넷; `semver`).
- 지문(`fingerprint16`, `fingerprint32`: Base32 넷씩).
- 상태 어휘(`status`: 일곱 어휘).
- 문구 표 항목(`ref`): 같은 표의 값 자리 없는 다른 항목 문자열만 받는다(예: 게이트웨이의 "장치 쪽 탭", 신원 줄의 프로그램 이름). 데이터가 아니라 표의 문구다.

SCREENS.md에서 옮긴 항목은 SCREENS.md의 자리 표시(N, 7, 10:40…)를 넣으면 그 문장이 글자 그대로 나온다. 자리에 다른 형의 값을 넣으면 화면 그리기가 실패한다. `prototype` 항목은 SCREENS.md가 내용만 정하고 문장을 정하지 않은 표지다(예: 사무원 화면의 "닫힌 배치 N"). 정식 문구 표 형식과 `ui_strings_hash`(ENCODING §8.26)는 M8 과제다.

`bun test`(`test/strings.test.ts`, `test/screens.test.ts`)가 확인하는 것:
- SCREENS.md §0.1과 §1–§7에 따옴표로 적힌 화면 문구, §1 표의 단추, "소프트웨어 확인", 괄호로 나열한 상태·이유 코드·판정이 모두 표에 글자 그대로 있다. 따옴표지만 화면 문구가 아닌 둘("연결 없음": 연결 목록 값, "읽는 중": 상태 이름)은 이유와 함께 뺀다.
- SCREENS.md가 금지한 판단 문구("정상", "부정 감지", "인증됨", "집계됨", "당신의 표가 반영되었습니다", "인증된 소프트웨어", "확정", "집계 완료", "귀하의 표가 집계되었습니다", "투표가 인증되었습니다", "오늘 N번째")가 표 어디에도 없다.
- 값 자리는 위의 종류뿐이고, 각 종류가 문자 집합 밖의 값을 거부하며, 후보·판독 결과·순번·사건 시각·가명·각인 목록을 담는 자리가 없다.
- 모든 기기의 모든 상태를 그린 문구에 후보 이름, BLANK·UNREADABLE, 순번, 초 단위 시각, 둘 이상의 추적코드가 없다. 유권자 앱은 상호 대조 전에는 `LOG_CONSISTENT`를 보이지 않고, 장부 상태가 더 높아도 추적코드 하나에 `LOG_CONSISTENT`보다 높은 칸을 붙이지 않으며, 체크포인트 밖 기록에 "포함"을 말하지 않는다.
- 시연 값 블록에 `demo` 표시가 있고(게이트웨이·현장 증명의 고정값, 사무원 화면의 계산 값), 진행 화면에는 없다. 64비트 슬롯이 정확하고 넘친 합을 그렇다고 말한다. 모든 기기의 신원 줄과 상세 화면이 값 자리를 채운다.
- §1 유권자 화면의 흐름(읽는 중에는 결정 없음, 고른 장이 없으면 확인 단추가 꺼짐 등).

보류 사유의 이름 표(`src/vocab.ts`)는 `tools/ityv-sim/tests/robustness.rs`가 `ityv-state`의 이름과 한 줄씩 대조한다.

## 화면 캡처 검사 (SCREENS §8)

`node scripts/screens.cjs <출력 디렉터리>`는 이 기기에 설치된 Chromium과 Playwright를 쓴다(이 패키지의 의존성이 아니다. `playwright install`을 하지 않는다). `ITYV_CONSOLE_URL`이 없으면 `bun server.ts`를 3170–3189 포트에 직접 띄운다(먼저 `bun run data`). 모든 기기의 모든 상태를 1×·1.5×·2×, 보통·고대비, 상세 화면 닫힘·열림으로 그려서 확인한다: 신원 줄이 보이고, 화면의 맨 아래 줄이며, 잘리지 않고, 다섯 점 어디서도 다른 요소가 그 위에 없고, 본문 글자가 화면 높이의 4%×확대 이상, 신원 줄이 2.5% 이상이다. 상세 화면 닫힘 상태마다 기기 틀과 그 밖의 시연 값 범례를 함께 캡처(deviceScaleFactor 1)한다. 끝으로 375px 폭에서 대시보드와 모든 기기 쪽에 가로 스크롤이 없는지 보고 전체 캡처를 저장한다. 실패가 하나라도 있으면 종료 코드 1이다.

## 경쟁·오류 경로·CSP 검사

`node scripts/races.cjs`(같은 Playwright, 3190–3199 포트에 `bun server.ts`와, `dist/`가 있으면 `bun scripts/preview.ts`를 띄운다)가 리뷰에서 나온 재현을 시험으로 돌린다: 빠르게 시나리오를 바꿔도 한 시나리오의 설명과 다른 보고서가 섞여 보이지 않는다; 이름을 바꾼 번들은 바이트로 설명되고 한 바이트를 바꾼 번들에는 설명이 붙지 않는다; 선거 ID와 합성 선거 표지; 모듈 트랩(worker에 주입)은 오류를 보이고 보고서를 지우며 다음 요청은 새 worker로 된다; 고르기 중에 놓은 파일의 결과만 보인다; 자체 시험 중의 조회 답과 입력이 남는다; 다른 쪽으로 옮기면 자체 시험이 멈추고 멈췄다고 말한다; 자체 시험이 모든 빠른 시나리오에서 시뮬레이터의 기대와 같다; 유권자 앱의 답이 자체 시험과 무관하다; 핀 표지(번들 핀이면 확인 표시 없음, 바깥 핀이면 있음, 틀린 핀이면 `HOLD_REVIEW`); 칸마다 다른 아이콘과 닿지 않는 상태·`PAPER_AUDITED`에 필요한 것의 문장; 감사한 장부가 `PAPER_AUDITED`이고 감사 칸이 비콘 관찰을 고정 자료로 적으며 고정 체크포인트가 공표보다 3구간 넘게 앞서고(세 대조 통과, 선 그림) 투표양식마다 감사가 있고 뽑힌 기록 표가 공개 정보만 보이며, 관찰을 끄면 `CRYPTO_TALLY_VERIFIED`와 그 설명, 다시 켜면 `PAPER_AUDITED`; 확대한 감사가 첫 라운드 넘음과 둘째 라운드 종료를 보이고, 시드 고르기 시도가 여유 대조와 토큰 대조에 실패하고 `Late`로 거부되며, 한 기관만 찍은 고정 체크포인트는 토큰 대조에만 실패하고 `Unstamped`로 거부된다; 고정 체크포인트의 토큰 둘이 시드 앞·공표 전으로 보인다; 깨끗한 장부의 체크포인트가 모두 앵커되고, 한 기관만 찍은 마지막 체크포인트는 미충족이며, 받지 않은 시점확인 기록이 보인다; 명부 칸이 정족수를 갖춘 변경(3/3, 효력)과 못 갖춘 변경(2/3, 효력 없음)을 보인다; 없는 기기 상태의 알림; 잘못된 `%` 이스케이프의 400; `dist/`가 CSP를 지니고 그 아래에서 대시보드와 기기 쪽이 위반·오류 없이 돌며 인라인 스크립트는 막힌다.

`dist/index.html`의 CSP(`scripts/csp.ts`): `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'`. 페이지는 인라인 스크립트·스타일을 쓰지 않는다(요소 스타일은 CSSOM으로만). 개발 서버(`bun run dev`)는 Bun의 HMR 때문에 CSP를 걸지 않는다.

## 의존성

- `typescript` 5.9.3(정확히 고정, `tsc --noEmit`만): 형 검사. 실행 코드에는 들어가지 않는다.
- 그 밖에는 없다. 서버·번들러·테스트는 Bun 1.4.4에 들어 있다. Bun 형 정의(`@types/bun`)도 넣지 않고 쓰는 API만 `types/bun.d.ts`에 손으로 선언했다. `bun.lock`을 저장소에 두며 `bun install --frozen-lockfile`로 설치한다. `trustedDependencies`가 비어 있어 의존성의 설치 스크립트는 돌지 않는다(typescript에는 그런 스크립트가 없다).

## 하지 않는 것

- 장치에 명령하지 않는다. 대시보드도 기기 화면도 읽기만 한다. 현장 확인 양식(§6.2)은 내용만 보이고 서명하거나 보내지 않는다(ADR-0022, ADR-0038).
- 상태를 계산하지 않는다. 사다리의 설명 문장은 검증기가 준 상태에 붙는 설명일 뿐이다.
- 법적 결정 참조의 내용을 보이거나 확인하지 않는다. 분쟁마다 그 건수만 보인다.
- 음성 안내를 내지 않는다(헤드폰 단자 전용, SCREENS §0.3). 촉각 단추의 점자 칸은 자리만 보인 것이며 실제 점자 표기는 M8에서 정한다.
- 미러 두 곳 대조를 하지 않는다. 유권자 앱은 대조 결과를 상태로 고르며 대조 전에는 `LOG_CONSISTENT`를 보이지 않는다.
