# ADR-0023: 소프트웨어 버전·빌드·지문을 늘 보여 주고, 언제든 현장에서 증명하게 한다

> English summary: Every field device shows, on every screen and at all times, which software it runs: name, version, build number and a fingerprint of the image hash (16 Base32 characters on the always-on bottom line, all 32 in the detail view), with every screen string drawn from a fixed table whose hash is in the release manifest. What it shows must match a release manifest pinned in genesis, built reproducibly by at least three independent builders and co-signed by the certification body and the committee. Because a screen can say anything, the real check is a challenge–response attestation any observer can request at any time between voters: the observer supplies a fresh signed nonce (by touching their observer token, or by feeding a signed challenge card that the scanner reads and hands back), and the device returns a statement of its measured images, signed by an attestation key that the immutable boot ROM derives from a device-unique secret and the measured image hash, so a modified image cannot produce a valid signature under the key registered in genesis. A compact signed summary is printed as a QR for offline checking on the spot; the full hybrid-signed attestation goes to the public board. Opening and closing attestations are mandatory. Any mismatch, refusal or unexplained reboot puts the device's records into full paper comparison and its electronic layer into HOLD_REVIEW; paper counting is unaffected. The ADR states the limit plainly: the attestation is only as sound as the boot ROM and the hardware secret, so it is backed by teardown sampling with independent flash readers and by protocol checks that catch misbehaviour regardless of software identity.

- 상태: 채택
- 날짜: 2026-11-01
- 관련: ADR-0005, ADR-0007, ADR-0011, ADR-0017, ADR-0020, ADR-0021, ADR-0022; `CONSTITUTION.md` §3 1항, §4 3항; `docs/spec/PROTOCOL.md` §3.2, §4.1, §4.6, §7.1, §7.9, §12.5, §13, §14, §16, 부록 A·B·C; `docs/spec/ENCODING.md` §6, §8.19, §8.26–§8.30; `docs/legal/LEGAL_ANNEX.md` 개정안 11; `docs/hardware/DEVICES.md` §5.7; `docs/ui/SCREENS.md`; VC-085..091

## 맥락

이미 정해 둔 것이 있다. 헌법은 재현 빌드(툴체인 고정, `cargo build --locked`, 두 빌드 기반의 해시 일치)와 서명 펌웨어·롤백 방지·측정 부팅을 요구하고(CONSTITUTION §3 1항, §4 3항), 법령 부속서 개정안 11은 독립 인증, 재현 가능성 확인, 선거 기간 중 변경 금지를 요구한다. 장치 연구는 역할마다 다른 이미지를 쓰고 측정 부팅으로 genesis와 대조하라고 했다(DEVICES §6.3).

빠진 것은 두 가지다.

1. **사람이 볼 수 있는 표시.** 투표소의 유권자와 참관인은 지금 눈앞의 기계가 어떤 소프트웨어를 돌리는지 알 방법이 없다. 인증은 공장과 인증기관에서 끝나고, 투표소에서는 "인증된 장비"라는 말만 남는다.
2. **언제든 할 수 있는 확인.** 화면에 버전과 체크섬을 띄우는 것만으로는 아무것도 증명되지 않는다. 바꿔치기한 소프트웨어도 원래 지문을 화면에 그릴 수 있다. 확인은 장치가 미리 알 수 없는 질문(신선한 도전값)에 대해, 바뀐 소프트웨어로는 만들 수 없는 서명으로 답하게 해야 의미가 있다.

ADR-0022가 연결을 "분리돼 있다"는 말 대신 기록으로 확인하게 했듯이, 소프트웨어도 "인증된 장비"라는 말 대신 현장에서 확인할 수 있어야 한다.

## 결정

1. **릴리스 목록.** 선거에 쓰는 모든 펌웨어 이미지를 장치 종류별로 `ReleaseManifest`에 적는다(해석 유닛, 커밋먼트 유닛, 챔버 모듈의 공급자별 이미지, 카운터·가명 유닛, 신원 확인 단말, 투표소 게이트웨이, 각인기·프린터 제어기). 이미지마다 이름, 의미 버전, 단조 증가 빌드 번호, 소스 커밋, 고정 툴체인 식별자, 이미지 해시(SHA3-512)를 적고, 장치 구성마다 구성 해시를 둔다. 사람이 읽는 **소프트웨어 지문**은 해시 앞 20바이트를 Base32 32자로 적어 넷씩 끊은 것이다(체크포인트 지문과 같은 표기). 서로 다른 조직의 독립 빌더 셋 이상(예: 서로 다른 정당 챔버가 추천한 둘과 학계 하나)이 각자 소스에서 다시 빌드해 같은 해시가 나와야 서명하고, 인증기관과 독립검증위원회가 함께 서명한다. 목록의 해시는 genesis의 `release_manifest_hash`로 고정하고, 지문은 genesis 지문과 함께 관보·방송·신문에 싣는다. 선거 기간 중에는 바꾸지 않는다(개정안 11 ③).
2. **부팅.** 장치의 부트 ROM은 바꿀 수 없다. 부트 ROM은 OTP 퓨즈에 넣은 릴리스 키 목록으로 이미지 서명을 확인하고(빌더 정족수와 인증기관), 맞지 않으면 시작하지 않는다. OTP의 단조 빌드 하한으로 이전 빌드로 되돌리는 것을 막는다. 부트 ROM은 실행할 이미지의 해시를 재고, 기기 고유 비밀과 그 해시에서 **증명 키**를 유도한다. 증명 키는 장치 밖으로 나가지 않으며, 등록 절차에서 인증된 이미지로 부팅한 상태의 공개키를 genesis에 등록한다. 그래서 다른 이미지로 부팅하면 다른 키가 나오고, 그 서명은 등록된 키로 검증되지 않는다.
3. **늘 보이게.** 화면이 있는 모든 장치는 모든 화면의 맨 아래 고정 줄에 신원 줄 `{프로그램 이름} {버전} · 빌드 {빌드} · {지문 앞 16자, 넷씩 넷}`을 늘 띄우고, 어떤 대화상자도 이 줄을 가리지 않는다. 스캐너는 유권자 화면에도 띄운다. 부팅 화면과 개시·마감 점검 화면, 개시·마감 출력물에는 구성 요소별 목록과 32자 지문 전체를 보이고, 신원 줄 옆 "소프트웨어 확인"으로 언제든 다시 볼 수 있다. 모든 화면 문구는 고정 문구 표에서만 나오며 그 표의 해시(`ui_strings_hash`)가 릴리스 목록의 이미지 항목에 들어간다. 화면은 상태와 수만 보이고 판단은 보이지 않는다. 장치별 화면은 `docs/ui/SCREENS.md`가 정한다. 화면이 없는 챔버 모듈은 자기 증명 키로 서명한 진술을 커밋먼트 유닛이 확인해 그 화면에 함께 보이고, 게이트웨이는 자기 표시창에 보인다.
4. **언제든 확인.** 참관인은 투표와 투표 사이 언제든 현장 증명을 요구할 수 있다. 도전값은 참관인이 만든다. 길은 둘이다. 하나는 참관인 토큰을 대는 것(토큰이 32바이트 난수를 만들고 서명해 커밋먼트 유닛이나 카운터·가명 유닛에 직접 넘긴다), 다른 하나는 참관인 앱이 만든 **확인 카드**를 스캐너에 넣는 것이다. 확인 카드의 QR에는 난수와 참관인의 확인 키 서명이 있고, 해석 유닛은 이를 `AttestChallenge` 링크 객체로만 넘긴 뒤 카드를 투입구로 되돌린다. 커밋먼트 유닛은 genesis에 등록된 참관인 확인 키로 서명을 확인하고, 열린 방문이 없을 때만, 정해진 간격 이상일 때만 받는다. 장치는 측정한 이미지 목록, 부팅 횟수, 시간 구간, 받은 도전값을 담은 `DeviceAttestation`을 증명 키로 서명해 공개원장에 올리고, 같은 내용의 요약을 Ed25519로 서명해 슬립 프린터로 QR을 인쇄한다. 참관인 앱은 인터넷 없이 genesis와 릴리스 목록만으로 QR을 확인한다. 몇 초 걸린다. 증명에는 투표에 관한 어떤 값도 없다.
5. **의무 시점.** 투표함마다 개시 때(첫 투표지 전)와 마감 때(`BoxClose` 전) 참관인 도전값에 대한 증명이 있어야 한다. 카운터·가명 유닛도 같다.
6. **어긋나면.** 서명이 틀리거나, 구성 해시가 목록과 다르거나, 빌드가 목록보다 낮거나, 화면의 지문과 증명이 다르거나, 응답을 거부하거나 정한 시간 안에 내지 못하거나, 설명되지 않는 재부팅(부팅 횟수 증가)이 있으면 `AttestationIncident`를 남긴다. 장치는 봉인된 예비로 바꾸고, 그 장치가 만든 기록은 전수 대조(§12.5)하며, 해당 투표함의 전자 층은 `HOLD_REVIEW`다. 종이 개표는 영향을 받지 않는다.
7. **누구나 재현.** 소스, 빌드 절차, 고정 툴체인은 저장소에 있다. CI는 커밋마다 이미지 해시를 공개한다. 누구든 다시 빌드해 목록과 다른 해시를 얻으면 분쟁 유형 8 `BUILD_MISMATCH`로 접수한다.

## 결과

- 유권자와 참관인이 눈앞의 장치가 무엇을 돌리는지 보고, 원하면 그 자리에서 확인할 수 있다. 바꿔치기한 이미지로는 등록된 키의 서명을 만들 수 없으므로, 화면을 흉내 내는 것만으로는 확인을 통과하지 못한다.
- 개시·마감 증명이 모든 투표함에 남아, 그 사이에 소프트웨어가 바뀌었는지(부팅 횟수, 증명 키)를 사후에도 확인한다.
- 비용: OTP 퓨즈와 부트 ROM 기능을 갖춘 MCU 선택, 화면 문구, 확인 카드 판독, 개당 수 초의 증명 시간. `DEVICES.md` §5.7에 추정치를 둔다.
- **정직한 한계.** 화면의 글자만으로는 아무것도 증명되지 않는다. 증명도 부트 ROM과 기기 고유 비밀이 정직할 때까지만 의미가 있다. 칩 안에 심은 하드웨어 이식물이나 부트 ROM 결함은 증명을 속일 수 있다. 그래서 (1) 선거 뒤 분해 표본(ADR-0022)에서 독립 시험기관이 자기 판독기로 플래시와 OTP를 직접 읽어 목록의 해시와 대조하고 부트 ROM 판을 확인하며, (2) 기록 서명, 정형성 증명, 모듈 카운터, 종이 대조 감사는 소프트웨어가 무엇이든 잘못된 동작을 잡는다. 소프트웨어 증명은 이 둘을 대신하지 않고, 현장에서 빨리 드러나게 하는 층이다.

## 기각한 대안

- **화면에 해시만 띄우기.** 바꾼 소프트웨어도 같은 글자를 그릴 수 있다. 사람을 안심시킬 뿐 증명이 아니다.
- **해석 유닛이 도전값을 자유롭게 넘기게 하기.** 해석 유닛은 불신 부품이고 투표를 본다. 아무 바이트나 도전값으로 넘길 수 있다면 읽은 순서를 공개원장으로 흘리는 통로가 된다. 그래서 확인 카드에는 등록된 참관인 키의 서명이 있어야 하고, 장치는 그 밖의 바이트를 받지 않는다.
- **증명 키를 저장된 키로 두기.** 이미지가 바뀌어도 같은 키가 남으면 바뀐 소프트웨어가 그 키로 서명할 수 있다. 키를 이미지 해시에서 유도하면 이 경로가 닫힌다.
- **선거 중 업데이트 허용.** 변경 금지(개정안 11 ③)와 충돌하고, 현장 증명의 기준이 흔들린다.

## 연결되는 검증

- VC-085 릴리스 목록의 형식과 서명, VC-086 부트 ROM 검증·롤백 방지·이미지 결속 증명 키, VC-087 화면 상시 표시와 개시·마감 출력, VC-088 현장 증명의 도전값·간격·내용, VC-089 투표함별 개시·마감 증명, VC-090 불일치 처리, VC-091 재현 빌드와 `BUILD_MISMATCH`.
- 인증 시험: 다른 이미지로 부팅했을 때 등록 키로 검증되는 서명이 나오지 않음, 롤백 거부, 확인 카드 외 바이트 거부, 열린 방문 중 도전값 거부.
- M5 검증기 단계 12, M8 부트 ROM과 OTP 설계, `ityv-encoding`의 증명 본문 인코딩, `ityv-cunit`의 `attest(challenge)` API(제공된 키로 서명만 하고 투표 상태를 건드리지 않음). 구현(2026-11-01): `ityv-encoding`의 0x0023–0x0025와 헤더 없는 서명 입력, `ityv-cunit`의 `AttestChallenge`(0x0105)와 `attest::Attestor`(ADR-0017 개정 24).
