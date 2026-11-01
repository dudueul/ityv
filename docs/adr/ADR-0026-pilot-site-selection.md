# ADR-0026: 시범 선거구 선정과 평가

> English summary: The first live trials run as non-binding parallel pilots (the paper count stays the legal result) in contested local-election districts chosen by a published rule and a public draw, never hand-picked. Candidates are districts whose previous same-type election had a winning margin of at most 5 percentage points (municipal council and mayoral districts and by-elections first); the draw is stratified by region and by the previous winner's party so no party's strongholds dominate, and an equal or larger comparison group is drawn from lopsided districts so problems can be attributed to the system rather than to closeness. The rule, the candidate list and the seed inputs are published in advance and recorded as a PilotSelection event that anyone can recompute (VC-097); results are published in a PilotReport with fixed metrics, and the committee and every party chamber jointly decide whether the next stage may start, with a kill switch for serious faults.

- 상태: 채택
- 날짜: 2026-11-01
- 관련: ADR-0002(단계 활성화), ADR-0011(감사 시드), ADR-0012·0019(거버넌스, 정당 챔버), ADR-0020(장치), ADR-0021(방문 단위 투입); `docs/legal/LEGAL_ANNEX.md` 개정안 12·§3.5; `docs/spec/PROTOCOL.md` §12.1, 부록 A·C; `docs/usecases/USE_CASES.md` 시나리오 R

## 맥락

이 설계의 부품 하나하나는 다른 선거와 다른 분야에서 쓰였지만, 이 묶음 그대로 큰 공직선거에 쓰인 적은 없다. 실선거에서 시험해야 하는데, 어디서 시험하느냐가 결과의 신뢰를 좌우한다. 표차가 작은 접전 선거구는 재검표와 소송 요구가 가장 많고 여야 참관인이 가장 꼼꼼히 지켜보므로 검증 도구의 가치가 가장 잘 드러난다. 반대로 시험 중 결함이 생기면 접전 결과 자체에 대한 불신으로 번질 수 있고, 선거구를 고른 방식이 곧 정치적 공격 대상이 된다.

## 결정

1. **비구속 병행.** 시범은 언제나 병행이다. 법적 결과는 현행 종이 개표이고, 시범 시스템의 전자 합계는 비교용으로만 공개한다(개정안 12 제278조의5 ①④). 2단계 진입 전 병행 시범을 거친다(LEGAL_ANNEX §3.2).
2. **후보군.** 직전 같은 종류의 선거에서 1·2위 득표율 차가 5%p 이하였던 선거구. 1차 시범은 지방선거의 기초의원·기초단체장 선거구와 재·보궐선거에서만 고른다. 관외 사전투표 경로는 2차 시범부터 더한다.
3. **비교군.** 직전 득표율 차가 15%p 이상인 선거구에서 시범 선거구와 같은 수 이상을 같은 방식으로 뽑는다. 문제가 생기면 접전 때문인지 시스템 때문인지를 가르기 위해서다.
4. **층화 추첨.** 후보군을 광역 권역과 직전 승리 정당으로 나눈 층마다 정해진 수를 뽑아, 어느 정당의 텃밭이나 한 권역에 몰리지 않게 한다. 층과 층별 수는 규칙에 미리 적는다.
5. **사전 공개와 공개 추첨.** 선정 60일 전에 규칙, 후보군 목록, 층별 수를 공개하고, 독립검증위원회와 모든 정당 챔버 대표가 규칙에 서명한다. 추첨은 감사 시드와 같은 방식(공개 주사위 추첨 기록, 사전 지정한 공개 분산 난수의 회차 값, 그 시점의 공개원장 체크포인트 해시)으로 시드를 만들고, 그 시드로 층마다 거부 샘플링 추출한다(PROTOCOL §12.1과 같은 규칙). 결과는 `PilotSelection` 이벤트로 남기고 누구나 다시 계산한다(VC-097).
6. **규모 상한.** 1차 시범의 투표소 수는 해당 선거 전체 투표소의 1% 이하로 한다.
7. **공개 지표.** 선거 후 30일 안에 `PilotReport`를 공개한다. 담는 지표: 투표함·보고 단위별 종이 개표와 전자 합계의 차이(§11.5), 감사 사유 코드 1–4와 `transfer_mark` 빈도(§12.3), '확인' 사용률, 방문당 처리 시간과 대기 시간, 장치 장애·`HOLD_REVIEW` 건수와 사유, 연결 감사 위반(§5.8), 소프트웨어 확인 결과(§7.9), 진행 경보의 종류별 빈도와 현장 확인 판정(§7.10, ADR-0027), 참관인 진술 요약. 비교군의 같은 지표를 나란히 둔다.
8. **전환과 중단.** 독립검증위원회와 모든 정당 챔버가 공동 평가해 다음 단계로 넘어갈지 정한다. 넘어가려면 적어도 확정 오판독(사유 코드 1·2) 0건, 종이·전자 차이가 모두 원인과 함께 설명됨, 장애 처리 절차 준수가 필요하다. 시범 중 비밀이나 정확성에 대한 중대 결함이 확인되면 위원회는 그 시범을 즉시 멈춘다. 종이 개표는 영향을 받지 않는다.

## 결과

- 선거구 선정이 공개 규칙과 재계산 가능한 추첨으로 정해져 "왜 하필 거기냐"는 공격의 근거가 사라진다.
- 접전지에서 검증 도구의 실제 가치(재검표 요구 해소, 분쟁 처리 시간)를 측정할 수 있다.
- 비교군 덕분에 결함의 원인을 가를 수 있다.
- 비용: 비교군까지 장비를 두어야 해 시범 규모가 두 배 가까이 된다. 1% 상한으로 묶는다.

## 기각한 대안

- **표차가 큰 안전한 곳에서만 시범:** 위험은 낮지만 검증 도구가 가장 필요한 상황을 시험하지 못하고, 여야의 관심도 낮아 깐깐한 검증을 받지 못한다.
- **선관위나 정부가 선정:** 선정 자체가 정치적 쟁점이 된다.
- **시범 결과를 법적 결과로 사용:** 검증되지 않은 시스템에 선거 결과를 맡기게 된다. 병행 원칙과 충돌한다.

## 연결되는 검증

- VC-097: `PilotSelection`의 규칙 해시, 후보군 root, 층별 수, 시드 입력 세 가지, 층별 추출 결과를 누구나 재계산한다.
- `PilotReport`의 지표는 공개원장의 해당 이벤트(§11.5, §12.3, §5.8, §7.9)에서 다시 셀 수 있어야 한다.
