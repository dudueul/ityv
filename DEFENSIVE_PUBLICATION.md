# 방어적 공개 (Defensive Publication)

> English summary: This repository is a deliberate public technical disclosure. Its authors will not seek patents on anything described here and publish it so that it serves as prior art against anyone else's attempt to patent it. Code is AGPL-3.0-or-later (with the GPLv3-family patent license and patent-retaliation terms); documents are CC BY-SA 4.0. The table lists each disclosed technique, where it is specified, and when it was first published in this repository; the commit history and archived copies are the evidence of those dates.

## 원칙

1. 이 저장소의 저작자는 여기 적힌 어떤 설계에도 특허를 출원하지 않는다.
2. 공개의 목적은 선거 기반 시설에 쓰일 기술을 누구도 특허로 독점하지 못하게 하는 것이다. 여기 공개된 내용은 공개일부터 누구에게나 선행기술이다.
3. 코드는 AGPL-3.0-or-later다. 이 라이선스는 기여자가 자기 특허 청구항에 대해 실시권을 주게 하고(제11조), 이 프로그램을 특허 침해로 제소한 자의 라이선스를 끝낸다(제10조). 고친 판을 장치에 넣거나 네트워크로 서비스하면 소스를 공개해야 한다(제13조).
4. 문서는 CC BY-SA 4.0이다. 고쳐 쓴 문서도 같은 조건으로 공개해야 한다.
5. 공개일의 증거는 이 저장소의 커밋 이력(서명된 타임스탬프가 아니라 GitHub에 수신된 시각), 공개 보관소 사본(Software Heritage 등), 릴리스별 DOI다.

## 공개 내역

날짜는 이 저장소에 처음 공개된 날(UTC)이다. 세부는 해당 문서가 규범이다.

| # | 기법 | 규범 문서 | 최초 공개 |
|---|---|---|---|
| 1 | 투표함 위 투함 스캐너: 손기표 종이를 읽어 Pedersen 커밋먼트와 1-of-(m+2) OR 증명을 만들고, 봉인 저널에 영속화한 뒤에만 무작위 투함 ID를 각인하고 투함 | PROTOCOL §7, ADR-0005 | 2026-10-30 |
| 2 | 서로 다른 주체가 봉인한 복수 챔버 모듈이 표마다 난수를 더하는 구조(r = Σ r_c)와 모듈별 카운터 서명, 한 챔버만 복원하는 은닉 채널 검사 | PROTOCOL §7.2, §9.5 | 2026-10-30 |
| 3 | 챔버 모듈에 미리 넣은 일회용 패드로 share를 보내는 방식(투함별 간격, MAC·태그 키 영역, 카운터 최고값) | PROTOCOL §9.4 | 2026-10-30 |
| 4 | 챔버 접근구조 비밀분산(정당 챔버 전부 필수 + 나머지 3-of-4)과 합계만 여는 개표 | PROTOCOL §9.2, §11, ADR-0019 | 2026-10-30 (정당 n개: 2026-11-01) |
| 5 | 여러 정당 모듈 PRF로 만든 가명 참여 장부, 실시간 명부 조회, 사후 공개 중복 검사 | PROTOCOL §6 | 2026-10-30 (실시간 조회: 2026-11-01) |
| 6 | 관외 회송 봉투 라벨을 투함 ID와 무관한 토큰으로 두고 봉투를 열지 않은 채 수령 대조 | PROTOCOL §10.6 | 2026-10-30 (분류·상태: 2026-11-01) |
| 7 | 기록을 먼저 뽑는 위험제한감사와 비공개 표본 열기 | PROTOCOL §12 | 2026-10-30 |
| 8 | 공개 미러, 체크포인트 교환, 분기 증거를 분쟁 유형으로 접수, 지문 공표 | PROTOCOL §5.7, ADR-0018 | 2026-11-01 |
| 9 | 선택별 누계 없음, 모든 투표 마감 전 합계 열기 금지 | PROTOCOL §7.3, §11.2 | 2026-11-01 |
| 10 | 단말기 비용·정확도 설계(방문 단위 투입, 유휴 시간 사전 계산, 붉은 인주 분리 판독, 재사용 모듈과 파쇄형 패드 카드 등) | docs/hardware/DEVICES.md, ADR-0020 | 2026-11-01 |
| 11 | 배치 증명(64건)과 참관인 스캔 수 앵커, 봉인 저널 재개 판정표 | PROTOCOL §7.2.1, §7.8, ADR-0014, ADR-0017 | 2026-10-31 |

이후 공개되는 기법은 이 표에 날짜와 함께 더한다.

## 보관

- Software Heritage: 공개 저장소 전체의 보관을 요청한다(https://archive.softwareheritage.org).
- 릴리스마다 Zenodo DOI를 받는 것을 권장한다(저장소 소유자 계정으로 GitHub 연동).
