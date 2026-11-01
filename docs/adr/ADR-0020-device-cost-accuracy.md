# ADR-0020: 현장 장치의 비용과 판독 정확도

> English summary: Field-device cost is driven by unit counts, not chip prices: with up to four party chambers each scanner carries seven chamber modules, and the same fleet must carry seven-ballot local elections. We adopt: an open reference board family ("ityv-core") in at least two MCU families, Cortex-M7 class for the commitment unit and Cortex-M33 class for chamber modules and counter units, no discrete secure element; a commodity, RAM-only interpretation unit with duplex RGB contact image sensors at 300 dpi, red-minus-green ink isolation, fiducials and a non-unique ballot-style mark, classical published decision rules with an UNREADABLE band, and a certification target of zero definite misreads in at least 10^7 positions; an optocoupler data diode for the one-way link; NOR flash for pads; proof generation reordered so vote-independent work is precomputed (same output distribution, verifier unchanged) and precomputed KEM encapsulations. We propose (for integration by the spec owners) batch insertion with one cast/check decision per visit, one slip per visit, a fix for out-of-district envelopes holding several ballots, ballot fiducials and style marks, reusable chamber modules with shreddable pad cards, one shared counter unit per station, misread classification with per-device feedback, and optional per-reporting-unit openings. Estimated initial fleet cost USD 25–68 M versus USD 55–151 M for the current one-ballot-at-a-time design. Status: proposed; estimates to be measured in M8.

- 상태: 채택(2026-11-01, 수치는 M8 실측 후 고친다)
- 날짜: 2026-11-01
- 관련: ADR-0005, ADR-0006, ADR-0014, ADR-0017, ADR-0019; `docs/hardware/DEVICES.md`; `CONSTITUTION.md` §1·§3·§4; `docs/spec/PROTOCOL.md` §6.2, §7, §8, §9.4, §9.6, §10, §11, §12; `docs/ballot/BALLOT_LAYOUT.md`

## 맥락

장치 설계는 지금까지 구조(세 부분 분리, 챔버 모듈, 단방향 링크)만 정했고, 부품, 처리량, 판독 방식, 비용은 정하지 않았다. 정당 챔버가 최대 넷으로 늘면서(ADR-0019) 스캐너당 챔버 모듈이 최대 일곱 개가 되었고, 확인 장치에도 정당 모듈이 넷씩 붙는다. 지방선거는 1인 7장(재보궐이 겹치면 8장)이고, 2024년 비례대표 투표지는 38개 정당, 51.7cm로 기존 분류기를 쓰지 못했다. 같은 장비로 모든 선거를 치르므로 수량은 가장 무거운 선거에 맞춰야 한다. 계산은 병목이 아니다(사전 계산을 넣으면 Cortex-M33급에서도 표당 수십–수백 ms). 병목은 사람의 투입과 종이 이송이고, 비용은 대수에 비례한다. 세부 근거와 출처는 `docs/hardware/DEVICES.md`에 있다.

## 결정

1. **코어 보드.** 커밋먼트 유닛, 카운터·가명 유닛, 챔버 모듈은 공개 참조 설계 `ityv-core`를 함께 쓴다. 같은 커넥터와 링크 프로토콜에 MCU 계열 둘 이상을 지원하고, 챔버마다 다른 제조사와 계열을 고르게 한다. 커밋먼트 유닛은 Cortex-M7급(운영체제 없음), 모듈과 카운터 유닛은 Cortex-M33급(RAM 128KB 이상)이다. 별도 보안 칩은 두지 않는다.
2. **해석 유닛.** 불신 부품으로서 범용 소형 응용 프로세서를 쓰되 RAM만 쓰고 부팅 플래시는 쓰기 방지를 배선으로 고정한다. 호스트와 합치지 않는다.
3. **판독.** 양면 RGB CIS 300dpi. 빨강과 초록 채널의 차이로 인주를 분리한다. 기준점으로 위치를 보정하고 투표양식 표지로 투표양식을 읽는다. 사전투표지 상단의 일련번호 바코드는 해독하지 않고 판독 전에 지운다. 판정은 공개된 고전 규칙(칸별 인주 비율, 칸 밖 인주, 도장 모양 상관)으로 하고 애매하면 `UNREADABLE`이다. 임계값은 genesis 정책 해시에 고정한다.
4. **정확도 목표.** 인증 시험에서 1,000만 기표 위치 이상에 확정 판정 오류 0. `UNREADABLE` 비율은 별도 목표(법적으로 유효한 표의 0.2% 이하)로 잰다. 투표양식마다 시험 덱을 두고 개시 시험에서 돌린다.
5. **단방향 링크**는 광커플러 UART로 만든다.
6. **패드 저장**은 NOR 플래시다. NAND와 SD카드는 쓰지 않는다(제자리 0 덮어쓰기 보장 불가, VC-034).
7. **각인기**는 안료 잉크 열 잉크젯이다.
8. **증명 생성 재배열과 KEM 사전 계산**을 `ityv-crypto`에 넣는다. 출력 분포와 형식이 명세와 같아 프로토콜 변경이 아니다. 독립 암호 검토와 상수 시간 검사를 조건으로 한다.
9. **J·A·C 중립 모듈 통합은 권하지 않는다.** 허용은 하되 공개 표기한다(현행 그대로).
10. **프로토콜 제안 P1–P8**(DEVICES.md §7)은 모두 채택해 명세에 반영했다. P1(방문 단위 투입과 한 번의 결정), P2(방문당 슬립), P2b(관외 봉투 하나에 투표지 여러 장: 방문당 스티커, `visit_count`·`envelope_count`·`sticker_count`)는 커밋먼트 유닛 동작을 바꾸므로 ADR-0021에 따로 적었다. P2b는 현행 명세의 결함 수정이다. P3(기준점, 투표양식 표지, 일련번호 바코드 해독 금지, 긴 투표지 봉투)는 PROTOCOL §7.1과 `BALLOT_LAYOUT.md` §0–§5, 법령 부속서 개정안 1 ⑨, VC-071. P4(모듈 본체 재사용과 패드 카드)는 PROTOCOL §9.4.2·§9.4.6·§15, VC-072. P5(투표소당 카운터·가명 유닛 하나)는 PROTOCOL §6.2, ADR-0009 개정, VC-073. P6은 아래 11. P7(감사 사유 코드와 확정 판정 불일치 시 전수 대조)은 PROTOCOL §12.3·§12.5, VC-074. P8(보고 단위별 합계 열기와 종이 대조)은 PROTOCOL §11.1·§11.2·§11.5, `PaperCountReport`, VC-075.
11. **P6(증명 생성 재배열과 KEM 사전 계산)은 구현 과제다.** `ityv-crypto`에 넣고 명세는 바꾸지 않는다. 출력 분포와 인코딩이 §7.5와 같다는 점만 PROTOCOL §7.5에 적었다. 들어가는 조건은 결정 8과 같다(독립 암호 검토, 상수 시간 검사, 명세 방식과의 분포 비교 차분 테스트). 사전 계산 API(`ProofPrecomputation`, `prove_precomputed`)는 `ityv-crypto`에 있으나 커밋먼트 유닛은 쓰지 않는다(2026-11-01): 증명 난수는 모듈 기여로 시드되며(ADR-0017 §12, 개정 4) 모듈 발급 전에는 뽑을 수 없고, 지연보다 보안을 택한다. M8에서 모듈이 다음 표의 기여를 한가한 시간에 미리 발급하고(묶음 항목처럼 저널에 남김) 사전 계산이 모듈이 낸 난수를 그대로 쓰게 하는 방식을 평가하며, 결정은 하드웨어 실측 뒤에 한다.

## 결과

- 묶음 투입(P1)과 각인 겹치기, 투표소당 카운터 유닛 하나(P5)를 함께 하면 지선 기준 스캐너는 약 67,000대에서 약 25,300대로, 모듈은 약 58.9만 개에서 약 25.2만 개로 준다(추정). 초기 비용은 약 5,500만–1억5,100만 달러에서 약 2,500만–6,800만 달러로 준다(추정).
- 모듈 재사용과 패드 카드(P4)로 선거마다 드는 모듈 비용이 약 350만–710만 달러에서 약 80만–200만 달러로 준다(추정).
- 정당 챔버 하나를 더할 때마다 모듈이 약 4.4만 개 늘고, 선거마다 약 13만–35만 달러가 든다(P4 적용 시).
- 보안 칩을 빼는 대신 칩 계열 다양화, 봉인, 인계 사슬, 측정 부팅에 의존한다. 모듈 하나가 뚫리는 것은 그 챔버의 공모와 같고 접근구조가 견딘다.
- 남는 위험: 해석 유닛이 상단 바코드를 몰래 해독·보관하는 경우는 불신 부품의 성질이라 인증 시험과 영속 저장소 부재로만 막는다. 가격과 시간은 추정이며 M8에서 실측해 이 ADR을 고친다.

## 기각한 대안

- **한 장씩 넣고 매번 선택(현행)을 유지하고 스캐너를 늘리기.** 지선에서 스캐너가 2.6배, 모듈이 2.3배 필요하다.
- **카메라 판독.** 부품은 싸지만 조명, 초점, 원근 보정, 메모리가 따라오고 정확도 검증이 어렵다.
- **판정에 학습형 모델 사용.** 결정 근거를 설명하고 감사할 수 없다. 애매한 표는 종이 판정에 맡기는 것이 법적 구조(종이 원본)와 맞다.
- **모듈마다 보안 칩.** ML-DSA 키를 넣을 수 없어 PQ 보호를 더하지 못하고, 25만 개에 곱해지는 비용만 늘린다.
- **해석 유닛과 호스트 통합.** 네트워크 쪽이 투표지 영상에 닿게 된다.
- **커밋먼트 유닛에 리눅스급 프로세서.** 성능은 사전 계산으로 충분하고, 운영체제가 공격면과 인증 범위를 키운다.

## 연결되는 검증

- M8 실측 항목(DEVICES.md §8): MCU 계열별 사이클·스택, 급지·겹침·걸림률, 1,000만 위치 판독 시험, 각인 노화, 전원·재개 1,000회, 패드 플래시 잔류, 시간대별 부하 보정, 수량별 견적.
- 재배열 증명: `ityv-crypto` 차분 테스트(명세 방식과 출력 분포 통계 비교, 검증기 통과), 상수 시간 검사.
- 불변식 대조표(DEVICES.md §6.1)의 각 항목은 해당 VC와 인증 시험에 연결한다.
