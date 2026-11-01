# 장치 개념 도면 D-00 … D-08

> English summary: Concept engineering drawings for ityv's field devices, hand-written as SVG so they diff and review like text and render in light and dark mode. D-00 shows a polling-station layout with voter flow, one-way fibres, observer taps and the CCTV framing rule; D-01 to D-03 show the casting scanner (four-view exterior, paper-path section with escrow and diverter, electronics block diagram with trust zones and every link); D-04 the chamber module; D-05 the check-in device; D-06 the station gateway and the fixed uplink schedule; D-07 the counting-centre sorter extension and the receiving office's label reader with its one-way cassette; D-08 the challenge card and on-site attestation. They are research drafts and the starting point for M8 prototype design. Every dimension and every part arrangement not stated in a normative document is an assumption and is marked "가정"; the normative values (frame counts, sizes, link directions, card size, what is never stored) come from the documents cited in each title block.

- 상태: 연구용 초안 1판 (2026-11-01). M8 시제품 설계의 출발점이다.
- 관련: `docs/hardware/DEVICES.md`, `docs/hardware/KEY_STORAGE.md`, `docs/ballot/BALLOT_LAYOUT.md`, `docs/ui/SCREENS.md`, `docs/spec/PROTOCOL.md` §5.8·§6·§7·§10, ADR-0010, ADR-0019–ADR-0024.
- 규범은 각 도면의 표제란 "근거"에 적힌 문서다. 도면과 규범 문서가 다르면 규범 문서가 맞고, 도면을 고친다.

## 1. 도면 목록

| 번호 | 파일 | 무엇을 보이나 |
|---|---|---|
| D-00 | [`D-00-station-layout.svg`](D-00-station-layout.svg) | 투표소 평면 예시: 유권자 동선, 확인 장치·교부·기표소·스캐너·게이트웨이 배치, 광 회선과 관찰 탭, CCTV 시야와 금지 구역 |
| D-01 | [`D-01-scanner-exterior.svg`](D-01-scanner-exterior.svg) | 투함 스캐너 4면도(정면·우측면·배면·평면), 부품 목록 17개, 촉각 단추 판 상세 |
| D-02 | [`D-02-scanner-paper-path.svg`](D-02-scanner-paper-path.svg) | 종이 경로 단면: 후드 → 급지·겹침 감지 → 양면 CIS → 대기 구역 → 각인 → 3방향 분기, 방문 하나의 처리 순서 |
| D-03 | [`D-03-scanner-electronics.svg`](D-03-scanner-electronics.svg) | 전자 블록도: 해석 유닛·커밋먼트 유닛·챔버 모듈 칸·기구 제어기·호스트, 신뢰 영역, 링크 L1–L10 표 |
| D-04 | [`D-04-chamber-module.svg`](D-04-chamber-module.svg) | 챔버 모듈 분해 측면도, 기판 배치, 조립 외형, 모듈 칸, 변형(스캐너용·확인 장치용)과 보호 층 |
| D-05 | [`D-05-checkin-device.svg`](D-05-checkin-device.svg) | 확인 장치: 단말 → 카운터·가명 유닛(한 방향), 정당 모듈의 보안 칩, 봉인 저널, 명부 전용회선, 유닛 외형 |
| D-06 | [`D-06-gateway-uplink.svg`](D-06-gateway-uplink.svg) | 게이트웨이와 관찰 탭, 통신사·세 출처 대조, 10분 슬롯 고정 프레임 송신 일정과 용량 계산 |
| D-07 | [`D-07-sorter-label-reader.svg`](D-07-sorter-label-reader.svg) | 개표소 분류기에 붙이는 각인 판독기(각인 구역만 봄), 수령 선관위 라벨 판독기와 일방향 카세트 |
| D-08 | [`D-08-challenge-card.svg`](D-08-challenge-card.svg) | 확인 카드(100 × 80) 배치, 카드 QR의 `AttestChallenge`, 증명 요약 쪽지, 현장 증명 순서 |

## 2. 읽는 법

- **표제란**(오른쪽 아래): 도면 번호, 이름, 축척과 단위(mm), 판과 날짜, 근거 문서.
- **축척**: 대부분 "축척 없음"이다. 치수는 숫자로 적었고 그림의 길이로 재지 않는다. D-04 분해도와 기판 배치는 1mm = 6px, D-08 확인 카드는 1mm = 3px로 그렸다.
- **"가정"**: 규범 문서에 없는 치수, 부품 배치, 형태, 신호 구성이다. M8 실측과 설계 검토로 정한다. 가정이 아닌 값은 표제란 근거 문서에서 왔다.
- **선과 색** (모든 도면 공통):

| 표시 | 뜻 |
|---|---|
| 청록 실선 화살표 | 한 방향 링크 또는 기본 종이 경로 |
| 청록 점선 화살표 | 관찰 탭 분기, 조건부 종이 경로(폐기·반환) |
| 회색 양쪽 화살표 | 양방향 링크 |
| 청록 칸 | 검증 부품(TCB): 커밋먼트 유닛, 카운터·가명 유닛. 신원 줄 자리와 광 송신부도 같은 색 |
| 황색 칸 | 챔버가 공급한 모듈, 가림 봉투 |
| 회색 점선 칸 | 불신 부품 |
| 빨간 원 S | 번호 봉인 |
| 빨간 점선 | 봉인된 포트, CCTV 금지 구역, 센서 시야 제한 |

- 화면 모드: 각 SVG는 안에 든 `prefers-color-scheme` 규칙으로 밝은 화면과 어두운 화면에서 모두 읽힌다. 배경은 투명하다.
- QR 무늬(D-08)와 화면 속 지문·난수 문자열은 예시다. 실제 값이 아니다.

## 3. 도면이 정하지 않는 것

도면은 규범을 새로 만들지 않는다. 다음은 도면에 그렸지만 명세가 아니며 M8에서 정한다.

1. 스캐너 외형과 치수(560 × 640 × 1,000, 투입구 높이 1,040), 대기 구역을 약 58° 기울인 640mm 트레이로 두고 바닥에서 꺼내는 방식(D-01, D-02).
2. 대기 구역 장 수 센서 값을 `VisitEnd`의 장 수와 맞춰 볼지(D-02 주 2). 맞춰 보기로 하면 PROTOCOL §7.3과 VC 목록을 먼저 고친다.
3. 기구 제어기를 따로 두는 구성과 L2·L6·L7의 신호 구성(D-03). 기구 제어기 펌웨어는 이미 릴리스 목록 대상이다(PROTOCOL §7.9의 "각인기와 프린터 제어기").
4. 사무원·참관인 화면을 호스트가 그리는 구성(D-03).
5. 챔버 모듈의 커넥터 모양(USB-A 모양), 72 × 24 × 11 외형, CR1220 코인 전지(D-04). 모듈 버스는 USB 프로토콜이 아니다.
6. 카운터·가명 유닛 외형(200 × 140 × 55)과 입력 포트 4개(D-05).
7. 게이트웨이 앞판, 바깥 회선 종류, 탭의 형태, 회선 용량(D-06). 프레임 수·크기·슬롯은 PROTOCOL §5.8 3항의 값이다.
8. 각인 판독기의 차폐와 방향 처리, 판독기와 기존 판독부 사이에 장마다의 값을 주고받지 않는 구성, 라벨 판독기의 분류 단추와 카세트 구조(D-07).
9. 확인 카드 QR 크기(30mm)와 여백(D-08).
10. 투표소 배치, CCTV 위치, 광 회선을 바닥 덮개 안으로 보내는 것, 유권자 화면과 인쇄물 출구를 CCTV에서 빼는 것(D-00).

## 4. 고치는 법

- SVG는 손으로 읽을 수 있게 쓴 파일이다. 글자는 11px 이상, 파일 하나는 120KB 미만으로 둔다.
- 도면을 고치면 표제란의 판과 날짜를 올리고, 규범 문서와 다른 점이 생기면 규범 문서를 먼저 고친다.
- 새 도면은 D-09부터 번호를 이어 쓰고 이 표에 더한다.
