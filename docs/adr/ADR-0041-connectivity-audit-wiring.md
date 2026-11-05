# ADR-0041: 연결 감사의 연결 — 연결 목록, 프레임 머리와 채움 증명, 세션과 프레임 기록, 연결 단계

> English summary: Step M5 2i wires ADR-0022's connectivity audit into the encoding and the public verifier. The connectivity manifest becomes a per-class policy: `ConnectivityManifest` (0x001C, version 2) lists, for each device class and port, the direction, medium, peer class, label, schedule, frames per slot, catch-up frames per slot and carried kinds; it stays pinned by the genesis body's `connectivity_manifest_hash` and is published beside the genesis. Instances live in the genesis's device entries: `GenesisBox` (0x0035, version 2) and each check-in unit of `StationEntry` (0x0036, version 2) carry the Ed25519 key that signs the device's uplink frames, and the station entry names its gateway with a hybrid key and an attestation key, so a device swap carries its new keys through the existing amendment of sets 1 and 2. A link is a transmitter: `link_id_hash = SHA3-512("ityv:link:v1" ‖ 0x00 ‖ frame_key)`. Publishing the 1 MiB frames is impractical (16 frames per 10-minute slot is about 1.1 GiB per scanner and day, tens of terabytes nationally) and their share packages are sealed, so the public could not hash whole frames anyway. A frame's signature and its link in the gateway's chain therefore cover a 151-byte header, `UplinkFrameHeader` (0x0057: link, slot, index, kind, stream offset, payload length, payload root), where the payload root is a 256-leaf tree over 4 KiB chunks of the payload zero-extended to 1 MiB (`UplinkFrame` 0x001D version 2 keeps the 1,048,576-byte body). The gateway publishes per session and link an `UplinkFrameLog` (0x0058): every frame's header fields, payload root and device signature, the leaves of the chunks that hold data, and the objects that start in the session's frames (schema, object hash, stream offset, length). The verifier rebuilds each header, checks the device signature, rebuilds the root from the published data leaves and the zero leaf (a padding proof: every chunk after the data is zero), recomputes every chunk whose bytes are all public ledger objects (the data are the objects, and the fill inside the last data chunk is zero), and recomputes the chain `h_i = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ h_{i−1} ‖ header_hash_i)` from `h_0 = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ link_id_hash)` against each signed `UplinkSession` (0x001E/0x001F version 2: at most six slots, the previous session body's hash, per link frames, catch-up frames, missing slots, stream end and chain head; observers sign the body hash with their capture's hash). A new connectivity stage checks the manifest's one-way rules (VC-077, a whole-ledger hold `ConnectivityManifest`, 79, since ADR-0022 decision 11 puts a declared inbound path on the electronic layer, not on the genesis), every session (`UplinkSessionRefused`, 80), every frame's signature, kind, index, slot shape, window, stream offset and padding proof (`UplinkFrameInvalid`, 81; VC-078), every stream's objects (allowed kinds, objects tiling the received stream, public bytes equal to the ledger's, records only in closed-batch runs in record-hash order, every fully received object on the ledger; `UplinkObjectInvalid`, 82; VC-079) and, once a station's gateway has a final session, that every device-signed ledger event of the station lies inside received frames of its device's link (`UplinkObjectOutside`, 83; VC-080). `SOURCE_COMPLETENESS_CHECKED` now also needs a final session from every station's gateway. `ConnectivityIncidentBody` (0x0059, a witnessed body: two clerks and observers of two organisations on site, or the committee and observers of two organisations) holds the electronic layer of the box, station or whole election it names (`ConnectivityIncident`, 84; a refused one is 85); it never touches the paper count, and when a commitment unit is involved the report lists the device for a full comparison. The observer capture comparison is a tool hook (`compare_capture`), the carrier log comparison a caller-supplied format and tool hook (`compare_carrier`), both outside the status: a mismatch reaches the ledger as an incident. RF checks, teardown reports and carrier reconciliation records stay unencoded.

- 상태: 제안
- 날짜: 2026-11-05
- 관련: ADR-0022(연결 공개와 감사), ADR-0028(genesis 형식, 버전 번호), ADR-0029(검증기 크레이트), ADR-0031(genesis 변경의 적용), ADR-0038(검증 콘솔, 개정 3), ADR-0039·ADR-0040(연결 단계의 본보기); `docs/spec/PROTOCOL.md` §4.1, §5.8, §14 3·11항과 끝, 부록 A·B·C; `docs/spec/ENCODING.md` §6, §8.21–§8.24, §8.43, §8.49, §8.82–§8.84; `docs/spec/FAILURE_CASES.md` §8; 법령 개정안 8(제181조의2 ④·⑤)·11(제278조의4 ⑤); VC-077..083

## 맥락

ADR-0022는 분리를 주장하지 않고 연결을 선언하고 감사하게 했다. genesis가 고정하는 연결 목록, 수신 소자가 없는 광 송신기, 10분 슬롯마다 고정 수의 1 MiB 프레임, 게이트웨이의 링크별 해시 사슬과 하이브리드 서명 세션, 게이트웨이 양쪽의 수동 탭, 통신사 기록, 무선 점검과 분해 표본, 그리고 위반을 `ConnectivityIncident`로 남겨 해당 구간의 전자 층만 `HOLD_REVIEW`로 두는 처리다. PROTOCOL §5.8과 §14 11항은 검증기가 연결 목록의 형식과 한 방향성, 세션 사슬과 연속성, 장치 출처 객체의 포함, 캡처의 바이트 대조를 하게 했다. ENCODING §8.21–§8.24는 네 스키마의 초안을 두었으나 인코딩된 적이 없다.

명세를 코드로 옮기면서 다음이 정해지지 않았거나 서로 맞지 않았다.

1. **연결 목록의 크기와 자리.** §8.21의 목록은 객체 하나에 항목 1,024개까지이고 항목마다 프레임 서명 키가 있다. 키는 장치 하나의 것이므로 항목은 장치 단위여야 하는데, 전국에는 투표소가 만 단위이고 투표소마다 스캐너가 여럿이다. 목록에는 장치와 투표함·투표소를 잇는 필드도 없다. genesis가 키를 어디에 고정하는지, 장치 교체(ADR-0031) 때 새 키가 어떻게 들어오는지도 없다.
2. **게이트웨이의 키.** `UplinkSession`은 게이트웨이가 하이브리드 서명하는데, genesis 어디에도 게이트웨이 항목이 없다(§4.1은 "장치 항목(…, 게이트웨이)의 공개키"라고만 한다).
3. **무엇을 공표하는가.** 사슬은 `UplinkFrame` 객체 전체의 해시를 잇는다. 스캐너 한 대가 하루에 1,152개(16 × 72슬롯), 약 1.1 GiB를 보낸다. 전국의 프레임을 공표하면 수십 TB다. 또 스캐너 프레임에는 봉인된 share 패키지(`sealed`)가 섞여 있어 공표된 자료만으로는 프레임 바이트를 다시 만들 수 없다. 그러면 공개 검증기는 사슬도 장치 서명도 채움도 다시 계산할 수 없다.
4. **장치 출처 객체의 포함(VC-080).** 어떤 객체가 어느 프레임에 있는지 알려 주는 자료가 없다. 프레임은 흐름의 연속 구간일 뿐이고 객체 경계는 수신자가 복원한다(§8.22).
5. **세션의 규칙.** "한 시간마다"의 판정, 앞 세션 해시가 무엇의 해시인지, `last_stream_offset`의 뜻(마지막 프레임의 오프셋인가 끝인가), `missing_slots`를 무엇으로 세는지, 참관인 서명이 캡처 해시를 덮는지(§8.24는 purpose만 적었다), 세션 본문이 `Bytes<2048>`에 들어가는지(링크 16개면 2,800바이트 안팎이다).
6. **프레임 규칙(VC-078) 가운데 공개 자료로 확인할 수 있는 것.** 슬롯당 수, 따라잡기와 마감 재전송의 모양, 개시 전·마감 뒤, 흐름 오프셋의 연속, 0 채움, 장치 서명.
7. **연결 목록 규칙의 자리.** §8.21은 한 방향성을 디코더의 불변식(`InvariantViolation`)으로 두었다. 그러면 양방향 TCB 포트를 적은 목록은 genesis 전체를 무효로 만든다. ADR-0022 11항은 목록에 없는 연결과 들어오는 경로를 사건으로 보고 해당 전자 층만 보류한다.
8. **`ConnectivityIncident`.** 부록 A는 서명자를 "위원회, 참관인 2(다른 조직)"로, `FAILURE_CASES.md` §8은 현장 발견을 "사무원·참관인 2 서명"으로 적어 서로 다르다. 범위(장치·투표소·모델 전체), 시간 구간의 뜻, 커밋먼트 유닛 연루의 표시, 보류의 해제도 없다.
9. **세 출처 대조(VC-081).** 참관인 캡처와 통신사 기록은 공개 장부에 없다. 검증기가 할 일과 못 할 일의 경계가 없다.
10. **상태 사다리.** 14절의 사다리는 1–8단계만 쓴다. 연결 단계가 보류만 낸다면 세션을 아예 싣지 않은 운영자가 잘못 실은 운영자보다 나은 상태를 얻는다.

## 결정

1. **연결 목록은 장치 종류의 규칙이다(`ConnectivityManifest` 0x001C, 버전 2).** 항목은 장치 종류와 포트마다 하나다: `device_class`, `port`, `direction`, `medium`, `peer_class`(상대의 장치 종류, 0은 시스템 밖), `counterpart`(사람이 읽는 상대 이름), `schedule`, `frames_per_slot`, `catchup_frames_per_slot`, `carries`(ENCODING §8.21). 열쇠는 (`device_class`, `port`)이며 오름차순·중복 없음, 256개까지다.
   - 실제 장치는 genesis의 장치 항목이 목록의 종류를 실체화한 것이다(2항). 그래서 목록은 작고(수십 항목), 장치가 늘어도 커지지 않으며, ADR-0022 2항의 문장("모든 장치 종류와 … 포트마다")과 같은 모양이다.
   - 버전 1의 `link_id`와 `frame_key`는 뺀다(2항). `frame_body_len`과 `slot_minutes`는 늘 같은 값이어야 했으므로 필드가 아니라 프로토콜 상수다(1,048,576바이트, 10분).
   - genesis 본문의 `connectivity_manifest_hash`가 목록 객체의 해시를 그대로 고정하고, 목록은 genesis와 함께 공표한다. 본문 모양은 바뀌지 않으므로 `GenesisBody`는 버전 8 그대로다. 검증기는 목록 객체를 genesis 입력으로 받아(`GenesisInput::connectivity`) 해시와 선거를 확인하고 정규 디코딩한다. 어긋나면 genesis를 받지 않는다(`Rule::ConnectivityPin`, `Rule::ConnectivityManifest`).
   - 디코더는 형식만 본다: 코드의 범위, 열쇠 순서, `frames_per_slot ≤ catchup_frames_per_slot ≤ 64`, 프레임을 보내지 않는 항목의 따라잡기 0, 정의되지 않은 `carries` 비트. 한 방향성과 덮음(VC-077)은 검증기의 연결 단계가 본다(7항).
   - 버전 1은 명세 초안이었고 인코딩된 적이 없다(ADR-0028의 `GenesisBody` 버전 1–5와 같은 처리). 0x001D–0x001F도 같다.

2. **장치의 키는 genesis의 장치 항목에 있다.** `GenesisBox`(0x0035)와 `StationEntry`(0x0036)의 카운터·가명 유닛(사용 중과 예비)은 `frame_key`(그 장치의 프레임 서명 Ed25519 공개키)를 더하고, `StationEntry`는 그 투표소의 게이트웨이(`gateway_id`, 하이브리드 공개키, 증명 공개키)를 더한다. 둘 다 버전 2다.
   - 장치를 교체하면 그 투표함·투표소 항목이 바뀌는 genesis 변경(ADR-0031)이 새 장치의 키와 함께 새 프레임 키를 싣는다. 변경으로 바뀔 수 있는 집합 1·2에 있으므로 `GenesisAmendmentBody`는 바뀌지 않는다.
   - 프레임 키를 장치의 기록 키(하이브리드 키의 Ed25519 반쪽)로 대신하지 않는다. 고정 일정 송신기는 장치 안의 별도 부품일 수 있고(M8), 그 부품이 기록 키를 지니면 송신기가 기록을 위조할 수 있다.
   - **링크는 송신기다.** `link_id_hash = SHA3-512("ityv:link:v1" ‖ 0x00 ‖ frame_key)`. 교체된 장치는 새 링크이고 사슬은 새로 시작한다.
   - genesis 규칙(`ityv-verify` genesis 단계): 프레임 키는 유효한 Ed25519 키이고(`InvalidKey`) 한 상태 안의 두 장치가 같은 프레임 키를 쓰지 않는다(`SharedKey`). 게이트웨이 ID는 투표함·카운터·가명 유닛·모듈·다른 게이트웨이의 ID와 겹치지 않고(`DeviceId`), 게이트웨이의 두 하이브리드 키는 한 상태의 모든 하이브리드 키와 어느 반쪽도 겹치지 않는다(`SharedKey`).

3. **프레임 머리와 채움 증명(VC-078).** 프레임 전체를 공표하지 않는다. 대신 장치의 서명과 게이트웨이의 사슬이 덮는 것을 151바이트의 머리로 옮긴다.
   - `UplinkFrameHeader`(0x0057): `link_id_hash`, `slot`, `index`, `kind`, `stream_offset`, `payload_len`, `payload_root`. 사슬의 `frame_hash`는 이 머리 객체의 §4 해시다.
   - `payload_root`는 탑재부(1,048,425바이트)를 0으로 늘린 1 MiB를 4,096바이트 덩어리 256개로 나눈 완전 이진 트리의 root다. 잎은 `SHA3-512("ityv:uplink-chunk:v1" ‖ 0x00 ‖ 덩어리)`, 마디는 `SHA3-512("ityv:uplink-node:v1" ‖ 0x00 ‖ 왼쪽 ‖ 오른쪽)`. 늘린 151바이트는 늘 0이다.
   - `UplinkFrame`(0x001D, 버전 2)은 본문 1,048,576바이트의 모양이 그대로이고(머리 필드, 탑재부, `frame_sig`), `frame_sig`는 그 프레임에서 만든 머리 객체에 대한 프레임 키의 Ed25519 서명이다(purpose `uplink-frame`). 탑재부의 `payload_len` 뒤는 0이어야 한다(디코더, `NonCanonical`).
   - 공개 검증기가 얻는 것: 모든 프레임의 머리를 다시 만들어 장치 서명과 사슬을 확인하고, 공표된 데이터 덩어리 잎과 0 덩어리 잎으로 root를 다시 만들어 서명된 root와 비교한다. 이것이 **채움 증명**이다: 데이터가 든 마지막 덩어리 뒤의 모든 덩어리는 0이다. 바이트가 모두 공개 장부 객체인 덩어리는 장부의 객체로 다시 만들어 잎과 비교한다: 데이터는 그 객체이고, 마지막 데이터 덩어리 안의 채움도 0이다.
   - 탭이 남는 것(VC-081): 봉인 바이트 자체, 봉인 바이트가 든 마지막 데이터 덩어리 안의 채움(프레임마다 4 KiB 미만). 그 밖의 채움은 공개 검증기가 증명한다.
   - 비용: 데이터가 든 덩어리 잎만 공표한다. 하루 종일 데이터가 거의 없는 프레임(대부분)은 잎이 없고 root가 상수다.

4. **세션과 프레임 기록(VC-080).**
   - `UplinkFrameLog`(0x0058, 공개 장부 이벤트, 자기 서명 없음): 선거, 투표소, 게이트웨이, 세션 번호, 링크, 그 세션에 받은 그 링크의 프레임마다 `slot`·`index`·`kind`·`stream_offset`·`payload_len`·`payload_root`·`frame_sig`(받은 순서, (`slot`, `index`) 오름차순), 데이터가 든 덩어리의 잎(프레임 순서대로, 프레임마다 `⌈payload_len / 4096⌉`개), 그 세션의 프레임에서 시작하는 객체마다 스키마·객체 해시·흐름 오프셋·길이(오프셋 오름차순, 겹침 없음). 게이트웨이는 받은 흐름에서 객체 경계를 복원하므로(§8.22) 이 목록을 만든다. 서명된 세션의 사슬 head가 기록의 머리를 덮고, 머리의 root가 잎을, 잎이 바이트를 덮는다.
   - 기록은 그 세션보다 앞 프레임에 싣는다. 게이트웨이가 기록을 싣고 그 위에 세션을 서명한다. 세션 뒤의 기록이나 세션이 없는 기록, 같은 (세션, 링크)의 둘째 기록은 받지 않는다.
   - `UplinkSessionBody`(0x001E, 버전 2): 선거, 투표소, 게이트웨이, 세션 번호(게이트웨이마다 1부터 1씩), `final`, 창(`start_slot` ≤ `end_slot` ≤ `start_slot + 5`, 한 시간 이하), 링크마다 일반 프레임 수·따라잡기 프레임 수(종류 1–3)·빠진 슬롯 수·흐름 끝(그 링크에서 지금까지 받은 마지막 프레임의 `stream_offset + payload_len`)·사슬 head, 바깥 회선 송신 바이트(`wan_bytes`), 앞 세션 본문의 객체 해시(첫 세션은 0). 창은 앞 세션의 창보다 뒤다. 사이가 비어도 되지만, 링크의 프레임이 걸친 슬롯(장치는 개시부터 마감까지 슬롯마다 보낸다, §7.10 1항) 가운데 어느 창도 덮지 않은 슬롯은 적지 않은 빈틈이다(8항).
   - `UplinkSession`(0x001F, 버전 2): 본문 `Bytes<4096>`, 게이트웨이의 하이브리드 서명(purpose `uplink-session`), 참관인 서명 0–4개. 참관인은 헤더 없는 필드 묶음 `세션 본문 해시 ‖ observer_id ‖ capture_hash`에 서명한다(purpose `uplink-capture`, 하이브리드). 그 참관인이 받아 둔 캡처가 이 세션의 사슬을 재현한다는 증언이며, 캡처 파일 해시가 서명으로 묶인다. 참관인은 genesis 명부에 그 투표소의 참관인으로 같은 조직에 등록되어 있어야 한다.
   - `final`은 그 게이트웨이의 마지막 세션이다. 보통 투표소 마감 때이고, 개표소에서 입회 재전송(종류 3)을 했으면 그 뒤다. 게이트웨이는 마감 뒤에도 같은 투표소의 게이트웨이다(봉인 장치와 함께 옮긴다).

5. **검증기가 확인하는 프레임 규칙(VC-078).** 링크마다(세션을 받은 프레임만):
   - 머리를 다시 만들어 그 링크의 프레임 키로 서명을 확인한다(장치의 프레임 키는 그 장치가 있는 어느 genesis 상태의 것이든 된다).
   - `kind` 0(일반)의 `index`는 연결 목록의 `frames_per_slot` 미만, 1–3(따라잡기, 마감 재전송, 입회 재전송)은 `catchup_frames_per_slot` 미만이다. 한 슬롯의 프레임은 한 종류 묶음(0, 또는 1·2, 또는 3)이고, 다 받은 슬롯은 그 모양의 번호를 하나씩 모두 지닌다. 모자란 슬롯은 빠진 슬롯이다.
   - 개시 전 없음: 투표함 링크의 첫 프레임은 그 투표함의 첫 `BoxOpened` 시간 구간이 걸친 첫 슬롯보다 앞서지 않는다. 카운터·가명 유닛은 그 투표소의 가장 이른 `BoxOpened`로 잰다.
   - 마감 뒤 없음: 투표함 링크의 종류 0·1 프레임은 그 투표함의 첫 `BoxClose` 시간 구간이 걸친 마지막 슬롯의 다음 슬롯보다 늦지 않다(마감 진행 기록의 슬롯까지, ADR-0027). 종류 2(마감 재전송)가 나온 뒤에는 종류 2·3만, 종류 3 뒤에는 종류 3만 온다. 카운터·가명 유닛은 투표 종료 뒤 참여 집합을 보내므로 마감 규칙을 두지 않는다.
   - 흐름 오프셋: 첫 프레임은 0에서 시작하고, 다음 프레임은 앞 프레임의 끝에서 시작한다. 앞서는 일은 없고, 건너뛰는 것은 그 사이에 빠진 슬롯이 있을 때만이다.
   - 채움 증명과 공개 덩어리(3항).
   - 빠진 슬롯: 링크의 첫 프레임과 마지막 종류 0–2 프레임의 슬롯 사이에서 다 받지 못한 슬롯은 그 슬롯이 든 세션이 그 링크의 빠진 슬롯으로 세어야 한다. 셈이 다르면 세션의 기록이 자기 기록과 어긋난 것이다(8항).
   - 어긴 프레임은 목록에 남고 그 장치의 투표함(카운터·가명 유닛이면 그 투표소의 모든 투표함)을 보류한다(`UplinkFrameInvalid`, 81). 서명이 맞지 않는 프레임은 받은 프레임으로 세지 않는다.

6. **흐름의 객체(VC-079).** 링크의 객체 목록을 모든 세션에 걸쳐 이어 본다.
   - 종류: 스캐너 링크는 `CastRecord`·`BatchAttest`·`ChallengeOpening`·`ProgressTick`·`SharePackage`, 카운터·가명 유닛 링크는 `ProgressTick`·`ParticipationSet`·`ObserverCountAttest`(본문이 그것인 `WitnessedEvent`)만 싣고, 연결 목록의 `carries`가 그 비트를 허용해야 한다(공개 객체는 비트 0, 봉인 패키지는 비트 1). `CheckinCounter`와 `ContestedCheckin`은 어느 링크에도 실을 수 없다(VC-084).
   - 객체가 받은 흐름을 빈틈없이 덮는다: 객체 사이나 마지막 객체 뒤의 틈은 빠진 범위(받지 못한 프레임의 바이트)와 겹칠 때만 둔다. 그 밖의 틈은 정규 객체가 아닌 바이트다. 객체는 그 시작 바이트가 든 프레임의 세션 기록에 있다.
   - 공개 객체의 바이트: 장부가 그 해시의 이벤트를 받았으면 길이가 같고, 그 객체의 바이트로 만든 덩어리 잎이 공표된 잎과 같아야 한다(3항).
   - 배치 단위와 순서: `CastRecord`는 `BatchAttest` 바로 뒤의 묶음 안에만 오고(그 사이에는 기록과 그 기록의 `SharePackage`만), 한 묶음 안의 기록 해시는 엄격히 오름차순이다. `SharePackage`는 그것을 가리키는 기록(`share_package_hash`) 바로 뒤에만 온다. 닫힌 배치를 두 번 보내는 것(ADR-0022 결과)은 같은 묶음이 두 번 오는 것이다.
   - 게이트웨이의 마지막 세션 뒤: 다 받은 객체는 모두 장부의 프레임(받아들여졌든 거부되었든)이 그 해시로 가리키는 이벤트다. 장치가 보낸 것을 운영자가 장부에서 뺐으면 드러난다.
   - 어긴 것은 목록에 남고 그 장치의 투표함을 보류한다(`UplinkObjectInvalid`, 82).
   - 봉인 바이트, 장부에 아직 없는 객체의 바이트, 시작을 받지 못한 객체는 확인하지 않은 덩어리로 센다(보고에 수). 배치가 닫힌 슬롯과 보낸 슬롯의 관계는 공개 자료로 알 수 없다(한계).

7. **연결 목록의 규칙(VC-077).** 연결 단계가 목록 전체를 본다. 어긴 항목은 목록에 남고 장부 전체를 보류한다(`ConnectivityManifest`, 79). genesis를 거부하지 않는 것은 ADR-0022 11항 때문이다: 선언된 들어오는 경로는 genesis의 형식 결함이 아니라 그 종류의 모든 장치에 대한 사건이고, 종이 개표와 나머지 검증은 그대로 볼 수 있어야 한다. 그 종류는 모든 투표함에 있으므로 보류는 장부 전체다.
   - 덮음: 장치 종류 1–15마다 항목이 하나 이상 있다. 바깥 연결이 없는 종류도 방향 0의 항목으로 없음을 선언한다.
   - TCB 장치(종류 1 해석 유닛, 2 커밋먼트 유닛·스캐너, 3 카운터·가명 유닛, 4 챔버 모듈): 방향은 없음 또는 내보내기만이고 무선이 아니다. 선거일 신원 확인 단말(5)은 연결이 없다.
   - 양방향은 사전투표 신원 확인 단말(6, 선거 전용회선, 사전투표 기간, 상대는 시스템 밖), 게이트웨이(7), 중앙 시스템(9–12)에만 있다. 관찰 탭(8)은 내보내기만이다. 명부 조회(`carries` 비트 5)는 종류 6에만 있다.
   - 프레임 링크: 종류 2와 3은 각각 프레임을 보내는 항목이 정확히 하나이고, 그 항목은 내보내기만, 광 송신 전용, 상대 종류 게이트웨이(7), 투표함 개시–마감 일정이다. 다른 종류는 프레임을 보내지 않는다. 종류 2의 링크는 공개 객체와 봉인 패키지(비트 0·1)만, 종류 3은 공개 객체(비트 0)만 싣는다(확인 카운터 비트 2는 VC-084).
   - 슬롯당 수는 목록이 정한다(스캐너 16, 카운터·가명 유닛 4, 따라잡기 64가 기준값). 검증기는 목록의 값으로 프레임을 판정한다.

8. **세션의 규칙(VC-080).** 투표소마다 세션을 장부 순서로 읽는다.
   - 받는 조건: 투표소가 genesis에 있고 게이트웨이가 그 프레임까지의 어느 상태에서 그 투표소의 게이트웨이이며 그 키로 서명이 맞는다; 참관인 서명이 모두 맞는다(4항); 번호가 앞 세션의 다음이고 앞 세션 본문 해시를 적는다; 창이 앞 세션 뒤다; 목록의 링크가 모두 그 투표소의 장치 링크다(어느 상태에서든); 프레임이 있는 링크는 모두 목록에 있고 기록이 앞에 있다.
   - 기록과의 대조: 링크마다 사슬 head를 다시 계산해 맞아야 그 기록의 프레임을 받은 것으로 센다. 일반·따라잡기 프레임 수, 빠진 슬롯 수(5항), 흐름 끝이 기록에서 다시 센 값과 같아야 한다. 링크의 첫 프레임과 마지막 종류 0–2 프레임 사이에 어느 창도 덮지 않은 슬롯이 있으면 적지 않은 빈틈이다. 같은 투표소의 기록이 둘이거나(같은 세션·링크), 받은 세션의 번호 이하인 기록이 뒤에 오거나, `final` 세션 뒤에도 남은 기록도 받지 않는다. 받지 못한 세션과 어긋난 셈은 목록에 남고 그 투표소의 모든 투표함을 보류한다(`UplinkSessionRefused`, 80). 받지 못한 세션의 기록은 받은 프레임으로 세지 않는다.
   - 완전성: genesis 마지막 상태의 모든 투표소에 게이트웨이의 `final` 세션이 있어야 연결 단계가 통과한다.

9. **포함(VC-080).** 투표소의 `final` 세션을 받은 뒤, 장부가 받아들인 그 투표소의 장치 서명 이벤트(`CastRecord`, `BatchAttest`, `ChallengeOpening`, `ProgressTick`, `ParticipationSet`)는 모두 그 장치의 링크(투표함이면 그 투표함의 어느 상태의 장치, 투표소 이벤트면 그 투표소의 카운터·가명 유닛) 객체 목록에 있고, 그 범위 전체가 받은 프레임 안에 있어야 한다. 아니면 목록에 남고 그 투표함(투표소 이벤트면 그 투표소의 모든 투표함)을 보류한다(`UplinkObjectOutside`, 83). 숨은 경로로 장부에 들어온 객체, 게이트웨이가 빠뜨리고 빠진 슬롯으로 적은 프레임의 객체가 여기서 드러난다. `final` 세션 전에는 아직 오지 않은 것이므로 판정하지 않는다. 운영 규칙: 게이트웨이의 `final` 세션은 그 투표소의 장치 이벤트 뒤에 싣는다.

10. **상태 사다리.** `SOURCE_COMPLETENESS_CHECKED`는 4단계의 완전성(모든 예상 투표함의 마감)과 11단계의 완전성(모든 투표소 게이트웨이의 `final` 세션)이 모두 있어야 한다. 출처의 완전성은 모든 출처가 닫혔다는 것과 그 출력이 선언된 경로로 다 왔다는 것이다. 그래야 세션을 아예 싣지 않는 운영자가 잘못 실은 운영자보다 높은 상태를 얻지 못한다. 연결 단계의 위반은 다른 단계처럼 보류다.

11. **`ConnectivityIncident`(VC-083).** `ConnectivityIncidentBody`(0x0059, `WitnessedEvent` 버전 5, purpose `connectivity-incident`): 선거, 투표소(없으면 선거 전체), 투표함(투표소가 있을 때만, 없으면 그 투표소 전체), 종류(1 목록에 없는 연결, 2 TCB 장치의 들어오는 경로·무선, 3 일정·크기를 벗어난 프레임, 4 정규 객체가 아닌 바이트, 5 캡처 불일치, 6 통신사 기록 불일치, 7 명부 회선의 사용 시간대 밖 연결, 8 설명되지 않는 송신, 9 분해 검사 발견, 10 무선 점검 발견), 구간(`from_slot` ≤ `to_slot`), 커밋먼트 유닛 연루 여부, 증거 문서 해시.
    - 서명자: 현장 발견은 그 자리의 사무원 둘 이상과 서로 다른 조직의 참관인 둘 이상(`FAILURE_CASES.md` §8), 사후 발견(캡처·통신사 대조, 분해 검사)은 위원회와 서로 다른 조직의 참관인 둘 이상(부록 A). 둘 다 받는다: 사건은 보류를 더할 뿐 무엇도 확정하지 않으므로 받는 쪽으로 넓히는 것이 실패 안전이고, 어느 쪽이든 서로 다른 조직의 참관인 둘이 있어야 한다. 사람은 genesis 명부에 그 역할과 조직으로 등록되어 있어야 한다(그 프레임까지의 상태).
    - 효과: 이름 붙은 투표함, 투표소의 모든 투표함, 또는 모든 투표함의 전자 층을 보류한다(`ConnectivityIncident`, 84). 투표함의 기록은 시간이 없으므로(VC-001) 구간보다 세밀하게 나눌 수 없다. 구간은 보고에만 쓴다. 분해 검사가 모델 전체를 걸면 위원회가 선거 전체 사건을 싣는다.
    - 종이 개표는 영향을 받지 않는다: 집계·종이 보고·감사 단계는 사건을 읽지 않는다.
    - 커밋먼트 유닛이 연루되면 보고는 그 투표함들을 전수 대조(§12.5) 대상으로 보이고, 감사 단계가 그 장치의 전수 대조를 받았는지 함께 보인다. 보류는 검증기가 풀지 않는다. 전자 층은 그 장부에서 확정되지 않고 종이가 법적 결과다.
    - 받을 수 없는 사건(서명자, 없는 투표소·투표함)은 목록에 남고 장부 전체를 보류한다(`ConnectivityIncidentRefused`, 85).

12. **세 출처 대조(VC-081)는 상태 밖의 도구다.**
    - **참관인 캡처**: 형식은 받은 `UplinkFrame` 객체를 받은 순서로 `u32_be 길이 ‖ 객체`로 이은 파일이고, `capture_hash = SHA3-512("ityv:capture:v1" ‖ 0x00 ‖ 파일)`이다(4항의 참관인 서명이 묶는 값). `ityv-verify`의 `compare_capture`는 캡처의 프레임마다 정규 디코딩(0 채움 포함), 머리와 root 계산, 서명을 확인하고 공표된 기록과 (슬롯, 번호)로 맞춰 같음·다름·캡처에만 있음(게이트웨이가 숨김)·기록에만 있음(주입이거나 탭이 놓침, 그 링크에서 캡처가 덮은 첫 슬롯과 마지막 슬롯 사이만: 늦게 붙거나 일찍 뗀 기록 장치는 그 밖을 보지 못했다)을 나누며, 캡처한 바이트로 객체 경계와 해시를 다시 만들어 공표된 객체 목록과 대조한다. 봉인 패키지도 정규 객체인지 본다(탭은 그 바이트를 본다).
    - **통신사 기록**: 제181조의2 ⑤에 따라 위원회가 받아 공표하는 기록이다. 형식은 회선마다(투표소, 게이트웨이 바깥 회선 또는 명부 조회 회선) 합산 구간(`from_slot`, `to_slot`)과 바이트 수의 목록이다(`ityv-verify`의 `CarrierLog`, 호출자가 넘김). `compare_carrier`는 바깥 회선의 합이 그 투표소 세션들의 `wan_bytes` 합과 같은지, 바이트가 있는 구간이 어느 세션 창과 겹치는지(설명되지 않는 송신), 명부 조회 회선은 사전투표소에만 있고 바이트가 있는 구간이 그 투표소의 투표 창(첫 개시 슬롯부터 마지막 마감 슬롯까지) 안인지 본다. `wan_bytes`가 세는 계층은 통신사가 세는 계층과 같아야 하며 하위 규정과 게이트웨이 참조 설계(M8)가 정한다.
    - 두 도구의 결과는 상태를 바꾸지 않는다. 어긋나면 참관인과 위원회가 `ConnectivityIncident`(종류 5·6·7·8)를 싣고, 그것이 보류가 된다. 캡처는 공개되지 않고 통신사 기록은 위원회가 공표하므로 공개 검증기의 입력이 아니다.
    - 무선 점검(`RfCheck`), 분해 검사(`TeardownReport`), 대조 결과(`CarrierReconciliation`)는 이 단계에서 인코딩하지 않는다(M8 절차와 함께). 발견은 사건으로 장부에 온다.

13. **보류 사유.** 79 `ConnectivityManifest`(장부 전체), 80 `UplinkSessionRefused`(투표소), 81 `UplinkFrameInvalid`(장치), 82 `UplinkObjectInvalid`(장치), 83 `UplinkObjectOutside`(이벤트의 투표함·투표소), 84 `ConnectivityIncident`(사건의 범위), 85 `ConnectivityIncidentRefused`(장부 전체). `HoldSet`은 128비트이므로 85까지 들어간다.

14. **API.** `ityv-encoding`: 위 스키마, `GatewayId`, `DeviceClass` 등 코드표, 상수(`FRAME_BODY_LEN`, `MAX_PAYLOAD_LEN`, `CHUNK_LEN`, `PAYLOAD_CHUNKS`, `MAX_FRAMES_PER_SLOT`, `MAX_SESSION_SLOTS`), purpose 상수. `ityv-crypto`: `uplink` 모듈(`link_id`, `chain_start`, `chain_next`, `chunk_leaf`, `payload_root`, `capture_hash`)과 `RecordPurpose::UplinkFrame`. `ityv-state`: 보류 79–85, `check_incident_signers`, 사다리. `ityv-verify`: `verify_connectivity`, `ConnectivityStage`과 그 보고형, `compare_capture`, `CarrierLog`·`compare_carrier`, `Report::connectivity`, `GenesisInput::connectivity`, `VerifiedGenesis::manifest`.

## 결과

- 누구나 공개 장부에서 모든 프레임의 일정·크기·서명·순서와 게이트웨이의 사슬을 다시 계산하고, 장치가 보낸 바이트가 장부의 객체이며 나머지가 0이라는 것을 (봉인 바이트 주변의 4 KiB 미만을 빼고) 확인한다.
- 숨은 경로로 장부에 들어온 장치 객체, 게이트웨이가 숨기거나 주입한 프레임, 일정 밖 프레임, 0이 아닌 채움, 배치 밖이나 투입 순서로 나간 기록이 상태를 멈춘다.
- 참관인은 캡처가 사슬을 재현한다는 것을 서명으로 남기고, 어긋나면 도구가 어디가 다른지 말한다.
- 공표량: 프레임마다 151바이트 남짓과 데이터 덩어리 잎. 스캐너 하루 약 1,152개 프레임이면 약 170 KB와 잎이다.

## 한계

- 봉인 바이트(share 패키지)와 그 덩어리 안의 채움은 탭과 신뢰기관만 본다. 공개 검증기는 봉인 객체의 해시와 길이가 게이트웨이의 기록과 장치 서명에 묶였다는 것만 본다.
- 배치가 닫힌 슬롯과 그 배치를 보낸 슬롯의 관계, 진행 기록을 그 슬롯에 보냈는지(공표 시점보다 이른 송신)는 장치만 안다. 검증기는 순서와 단위만 본다.
- 장부 자체에 기록이 실린 순서는 이 단계가 보지 않는다(시뮬레이터는 기록을 투입 슬롯마다 장부에 싣는다).
- 연결 목록이 실제 장치와 같은지는 분해 표본과 무선 점검(VC-082)만 확인한다. 검증기는 선언을 본다.
- 통신사 기록의 계층과 합산 구간, 게이트웨이의 `wan_bytes` 계층은 하위 규정과 M8이 정한다. 그 전에는 `compare_carrier`의 바이트 대조가 같은 계층을 가정한다.
- 첫 개시 전과 `final` 세션 뒤처럼 어느 창도 덮지 않은 시간에 보낸 프레임은 사슬에 없다. 그것은 탭과 통신사 기록이 잡는다.
- 사건의 구간은 보고에만 쓰인다. 기록에는 시간이 없어 투표함보다 세밀하게 보류할 수 없다.
- 개표소의 입회 재전송이 투표소 게이트웨이를 거친다는 것은 운영 규칙이다. 다른 게이트웨이를 쓰면 genesis에 그 투표소의 게이트웨이로 등록되어야 한다.

## 기각한 대안

- **연결 목록을 genesis 항목 집합 14로.** 장치 단위 항목이면 전국에 수만 개라 집합이 맞다. 그러나 항목마다 투표함·투표소를 다시 적어야 하고, 장치 교체 때 바꿀 수 있어야 하므로 고정 집합(9–14)이 될 수 없으며, 바꿀 수 있는 집합을 늘리면 `GenesisAmendmentBody`와 상태 기계가 바뀐다. 장치의 키를 장치 항목에 두면 교체가 그대로 따라온다.
- **프레임 전체를 공표.** 1.1 GiB/스캐너·일, 전국 수십 TB이고, 봉인 패키지 때문에 어차피 다시 만들 수 없다.
- **share 패키지를 공개 등급으로.** 그러면 프레임을 통째로 다시 만들 수 있다. 그러나 KEM으로 봉인한 패키지를 누구나 영구 보관하게 되고(ADR-0022 7항의 지금 모았다 나중에 풀기), 부록 A의 등급과 VC-033의 취지를 바꾼다.
- **채움을 덩어리 트리 없이 탑재부 전체의 해시로.** 봉인 바이트가 든 프레임에서는 공개 검증기가 채움에 대해 아무것도 증명하지 못한다. 트리는 0 덩어리 잎을 한 번만 계산하므로 계산량도 적다.
- **연결 목록의 한 방향성을 디코더 불변식으로.** genesis 전체가 무효가 되어 종이와 나머지 검증까지 볼 수 없다. ADR-0022 11항은 전자 층만 보류한다.
- **연결 단계는 보류만.** 세션을 싣지 않으면 보류가 없으므로 아무것도 싣지 않는 쪽이 유리해진다.
- **사건의 보류를 감사의 전수 대조로 풀기.** 연결 사건은 대개 비밀의 문제이고, 비밀이 깨졌는지는 대조로 되돌릴 수 없다. 정확성은 종이가 지킨다.
- **통신사 기록을 장부 이벤트로.** 기록은 통신사가 만들고 위원회가 받아 공표한다(제181조의2 ⑤). 서명 주체와 형식이 하위 규정이므로 이 단계에서는 호출자 입력으로 두고 결과를 사건으로 싣는다.

## 연결되는 검증

- `crates/ityv-encoding/tests/m5_connectivity.rs`: 모든 스키마의 왕복, 생성자와 디코더 규칙(1 MiB 프레임의 0 채움 규칙 포함), 위치까지 적은 거부 벡터, 코드표, 속성 테스트. 시험 벡터 `connectivity_manifest.txt`, `uplink_frame_header.txt`, `uplink_session_body.txt`, `uplink_session.txt`, `uplink_frame_log.txt`, `connectivity_incident_body.txt`와 갱신된 `genesis_box.txt`, `station_entry.txt`, `witnessed_event.txt`. Kani `connectivity_codes_are_exact`(코드표), `uplink_frame_header_round_trip`(머리의 왕복과 범위), `uplink_session_rules_are_exact`(창과 앞 세션 해시 규칙, `u64` 끝 포함), `connectivity_incident_rules_are_exact`(투표함·투표소, 구간, 증거).
- `crates/ityv-crypto`: 덩어리 root가 256잎 완전 트리와 같음(데이터 잎 0–256개, 257개는 거부), 채움의 바이트 하나도 root를 바꿈, 표지 분리. Kani 없음(해시).
- `crates/ityv-state`: 보류 79–85, 사건 서명자 시험, 사다리(`status_is_exact`).
- `crates/ityv-verify/tests/connectivity.rs`(실제 서명): 연결 목록 규칙마다, 세션의 받는 조건과 대조마다, 프레임 규칙마다(서명, 번호, 모양, 개시 전, 마감 뒤, 오프셋, 채움, 공개 덩어리), 객체 규칙마다, 포함, 사건의 두 서명자 집합과 범위, 캡처·통신사 대조. `tests/genesis.rs`: 프레임 키와 게이트웨이 규칙, 목록의 핀.
- `tools/ityv-sim`: 모든 투표소의 게이트웨이와 세션·기록, 공격·장애 시나리오 12개(ADR-0038 개정 3). 기존 시나리오의 기대 결과는 바뀌지 않는다.

## 구현에서 정한 것 (2026-11-05)

구현과 시험이 결정의 문장을 다음처럼 좁혔다. 결정의 뜻은 바뀌지 않는다.

1. **다 받은 슬롯(6항).** 슬롯은 그 모양의 번호 `0..n`을 모두 지닐 때 다 받은 것이다. 모양보다 큰 번호의 프레임은 번호 위반(`Index`)이지 빠진 슬롯이 아니다.
2. **재전송 순서(6항).** 마감 재전송 뒤에는 재전송만, 입회 재전송 뒤에는 입회 재전송만 온다. 한번 입회 재전송이 오면 그 뒤의 마감 재전송도 순서 위반이다.
3. **포함(9항)의 "장부가 받아들인".** 장부 색인이 받아들인 이벤트다. 색인이 무효로 한 프레임(재수록, 투표함 마감 뒤의 기록, §14 3)은 그 자체로 보류이고 포함을 따로 묻지 않는다. 그래서 시뮬레이터의 `attack-record-after-close`는 기대 결과가 그대로다.
4. **빈틈(8항).** 사이가 빈 창은 장치가 보내지 않는 동안(첫 개시 전, 마지막 마감 뒤)만 허용된다. 장치는 개시부터 마감까지 슬롯마다 진행 기록을 보내므로(§7.10) 링크의 프레임이 걸친 슬롯을 어느 창도 덮지 않으면 적지 않은 빈틈(`UndeclaredGap`)이다.
5. **캡처의 "기록에만 있음"(12항).** 위와 같이 캡처가 그 링크에서 덮은 슬롯 안만 센다.
6. **봉인 패키지와 장부(6항).** share 패키지는 봉인되어 장부 이벤트가 아니다. 바로 앞의 기록이 장부에 있고 그 기록의 `share_package_hash`가 패키지의 객체 해시이면 "장부의 프레임이 그 해시로 가리킨다"를 만족한다. 그렇지 않은 패키지는 패키지 순서 위반(`Package`)이고, 다 받았으면 장부에 없는 객체(`NotOnLedger`)이기도 하다. 시뮬레이터의 스캐너는 패키지를 보내지 않으므로 이 규칙은 검증기 시험(`tests/connectivity.rs` `records_travel_in_closed_batches_and_packages_after_their_records`)이 본다.
7. **흐름의 건너뜀(5항).** 프레임의 흐름 오프셋이 앞 프레임의 끝보다 크려면 두 프레임의 슬롯 사이(양 끝 포함)에 모자란 슬롯이나 어느 창도 덮지 않은 슬롯이 있어야 한다. 덮지 않은 슬롯은 그 자체로 세션의 빈틈(`UndeclaredGap`)이므로 오프셋 위반을 따로 더하지 않는다.
