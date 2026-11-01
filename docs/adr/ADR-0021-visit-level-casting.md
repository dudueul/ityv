# ADR-0021: 방문 단위 투입, 결정 전 결속, 방문당 슬립과 라벨 스티커

> English summary: The casting scanner now takes one visit at a time: the voter inserts every ballot they received (up to 8) in one sleeve, the unit reads and fully builds and signs every record of the visit (device and module record signatures obtained before any decision), and only then asks once which ballots, if any, to check. Modules sign at most one body hash per counter, so the device cannot change a record after learning the decision; this also closes a binding gap that the per-ballot flow left implicit. Checked ballots are opened and spoiled and only those are re-marked. The journal writes position entries, then a visit-decision entry that closes them, then imprint and label entries; resume rules follow from that order. One slip per visit lists the visit's tracking codes under a single hybrid signature. Out-of-district visits get one label sticker carrying every env_label of the visit; readers store label values only as flat sets, and BoxClose gains visit_count, envelope_count and sticker_count, replacing the wrong invariant envelope_count == record_count.

- 상태: 채택
- 날짜: 2026-11-01
- 관련: ADR-0005, ADR-0010, ADR-0014, ADR-0017, ADR-0020; `docs/hardware/DEVICES.md` §3, §7(P1, P2, P2b); `docs/spec/PROTOCOL.md` §7.1, §7.2.1, §7.3, §7.7, §7.8, §8, §10.2, §10.6; `docs/spec/ENCODING.md` §8.16, §8.18, §8.19; VC-038, VC-054, VC-068, VC-069, VC-070

## 맥락

1. **처리량.** 지방선거에서 유권자는 투표지를 7장(재보궐이 겹치면 8장) 받는다. 한 장씩 넣고 매번 "투입 / 검증"을 고르게 하면 한 사람이 스캐너 앞에서 약 45초를 쓰고, 지선 기준 스캐너가 약 6.7만 대 필요하다(DEVICES.md §3). 한 번에 넣고 한 번 고르면 약 22초, 각인을 다음 사람 투입과 겹치면 약 15초가 된다.
2. **결속의 빈틈.** Benaloh 검증이 건전하려면 장치가 확인 여부를 알기 전에 기록에 묶여 있어야 한다. 기존 절차는 기록 서명 시점을 정하지 않아, 장치가 "투입"을 들은 뒤 같은 모듈 기여로 다른 선택의 기록을 만들 여지를 명세가 막지 않았다.
3. **관외 봉투 결함.** 관외 유권자는 받은 투표지를 회송용 봉투 하나에 넣는다. 그런데 명세는 기록마다 라벨 스티커를 뽑고 마감 불변식을 `봉투 수 == record_count`로 두었다. 투표지가 한 장인 선거에서만 맞는다.
4. **슬립 서명 비용.** 7장 선거에서 슬립을 표마다 뽑으면 ML-DSA-87 서명이 7번 든다.

## 결정

1. **방문.** 투입 단위는 방문이다. 유권자는 받은 투표지 전부(1–8장)를 가림 봉투 하나에 넣어 한 번에 넣는다. 해석 유닛은 투표지마다 `Interpretation`을 보내고 끝에 `VisitEnd { election_id, ballot_count }`(0x0104)를 보낸다. 커밋먼트 유닛은 장수가 맞지 않으면 방문을 결정 없이 격리한다.
2. **결정 전 결속.** 방문의 모든 위치에 대해 기록 본문, share 패키지, 장치 기록 서명, 모든 모듈의 기록 서명을 끝낸 뒤에만 결정을 받는다. 모듈은 한 카운터에 본문 해시 하나만 서명하고 같은 카운터의 다른 본문은 거부하며, 서명한 해시를 그 카운터가 배치 증명이나 마감에 들어갈 때까지 보관한다(VC-068). 장치가 결정 뒤 기록을 바꾸려면 새 카운터가 필요하고, 버려진 카운터는 실물 없는 격리로 남아 마감 때 격리 봉투 수와 어긋난다(VC-038).
3. **결정.** 화면은 투표지 종류만 위치 순서로 보여 주고 선택은 보여 주지 않는다. 선택부는 커밋먼트 유닛에 직접 연결된다. 결정은 위치마다 넣기·확인 중 하나이며 빈 집합(모두 넣기)과 전체(모두 확인)를 모두 허용한다. 확인한 표만 `ChallengeOpening`으로 열고 폐기하며, 유권자는 그 투표양식만 새로 받아 다음 방문으로 넣는다.
4. **저널 순서.** 위치 항목(넣는 표는 종류 1, 확인하는 표는 종류 2) n개 → 방문 결정 항목(종류 7, 위치 항목을 묶는 다이제스트) → 한 번의 fsync → 위치 순서로 각인(종류 6)·격리(종류 3)·배출 → 관외면 라벨 출력(종류 8). 방문 결정 항목이 없으면 그 방문의 결정은 성립하지 않는다. 업링크는 닫힌 방문만 보낸다.
5. **재개.** PROTOCOL §7.3의 네 경우(결정 전 멈춤은 전부 격리, 결정 후는 남은 뒤쪽 위치를 결정대로 처리하되 각인 없는 넣는 표는 격리, 관외 스티커 미출력은 그 방문의 넣은 표 전부 격리, 그 밖은 `HOLD_REVIEW`)를 따른다(VC-069). 스캐너는 진행 중인 방문 하나를 끝낼 만큼의 배터리를 가진다.
6. **슬립.** 방문당 하나. `SlipBody.tracking_codes: Array<Hash512, 8>`에 그 방문에서 넣은 표의 추적코드를 위치 순으로 담고 하이브리드 서명은 한 번 한다. 확인해 폐기한 표의 코드는 넣지 않는다(VC-070).
7. **라벨 스티커.** 관외·재외 방문에서 넣은 표가 하나 이상이면 스티커 하나에 그 방문의 `env_label` 목록을 2차원 코드로 담는다. 다시 찍은 표의 스티커는 같은 봉투에 붙인다. 수령지 판독기는 라벨 값을 낱개 집합으로만 저장하고 같은 스티커·봉투였다는 정보는 남기지 않는다.
8. **마감 수량.** `BoxCloseBody`에 `visit_count`(넣은 표가 있는 방문 수), `envelope_count`, `sticker_count`를 더한다. 관외·재외 함은 `paper_count`를 0으로 두고 `sticker_count == visit_count`, `envelope_count == 회송용 봉투 교부 수 − 빈 봉투 회수 수`를 쓴다. 모든 함에서 `visit_count ≤ record_count ≤ 8·visit_count`다. 관외·재외 함의 `no_record_count`는 비상 구간 교부 투표지 수로 적는다.

## 결과

- **Benaloh 건전성.** 결정 전 결속으로 각 위치가 확인될지는 기록이 묶인 뒤에야 정해진다. 유권자가 일부만 고를 수 있으므로 특정 선거만 조작하는 장치도 그 위치가 확인될 위험을 진다. 기존 한 장씩 흐름에 있던 결속의 빈틈도 같은 규칙으로 닫힌다.
- **비밀.** 장치는 지금도 한 유권자의 여러 장을 연달아 본다. 묶어 보는 것은 같은 정보다. 공개 게시판에는 기록이 투표함별 정렬 집합으로만 올라가 방문 묶음이 드러나지 않는다(VC-027). 저널은 원래 투입 순서를 담는 `sealed` 자료이고, 방문 경계는 그 순서에 더해지는 것이 거의 없다.
- **슬립이 묶음을 보여 준다.** 슬립 하나가 한 유권자의 기록 여러 건을 가리킨다. 기록에는 선택이 없고 표본 열기는 비공개(§12.3)라 슬립을 남에게 보여 줘도 선택은 증명되지 않는다. 남는 위험은 비공개 열람자가 누설하고 그 유권자가 슬립까지 내준 경우인데, 슬립 하나에 코드가 하나일 때와 성격이 같고 범위만 그 유권자의 표본 기록 수로 늘어난다.
- **스티커가 묶음을 보여 준다.** 관외 봉투 하나에 한 사람의 투표지가 모두 들어가는 것은 현행 제도와 같다. 이 묶음이 선택과 이어지지 않게 판독기는 값을 낱개 집합으로만 남기고, 수령 대조 의식은 기록별 상태만 공개하며, 복원한 라벨은 의식 끝에 지우고(VC-041), 개봉한 투표지는 봉투에서 꺼내 섞은 뒤에만 다룬다. 감사 표본 열람자는 라벨 정보를 받지 않는다.
- **처리량과 비용.** 지선 기준 스캐너 대수가 절반 이하로 준다(DEVICES.md §5.5). 7장 방문의 ML-DSA-87 슬립 서명은 7번에서 1번으로 준다.
- **새 부담.** 대기 구역은 최대 8장을 순서대로 붙잡아야 한다. 결정 전 전원이 나가면 방문 전체를 격리하고 다시 받아 찍어야 하므로 배터리 요건을 둔다.

## 기각한 대안

- **한 장씩 넣고 매번 선택(현행 유지).** 처리량 문제가 그대로이고 결속의 빈틈을 따로 메워야 한다.
- **"모두 넣기 / 모두 확인" 둘 중 하나만.** 확인하려면 7장을 모두 다시 찍어야 해 확인률이 떨어지고, 특정 선거만 조작하는 장치를 잡을 확률이 낮아진다.
- **기록마다 스티커.** 봉투 하나에 스티커가 7장 붙고, 붙이다 빠뜨리면 그 기록이 `CAST_NOT_RECEIVED`가 된다.
- **결정 전 화면에 기록 해시 일부 표시.** 유권자에게 보여 주는 값으로 결속하는 방식이다. 사람이 비교하기 어렵고, 모듈 서명으로 이미 결속된다.

## 연결되는 검증

- VC-038(마감 불변식에 방문·봉투·스티커 수), VC-054(저널 전 각인 금지), VC-068(결정 전 결속), VC-069(방문 저널 순서와 재개), VC-070(방문당 슬립).
- 코드(M3): `ityv-cunit`의 방문 흐름(작업 영역 8개, `VisitEnd` 링크 디코더, 결정 전 서명, 결정 입력 typestate, 저널 종류 7·8, 재개 판정, 방문당 스티커·슬립), `ityv-encoding`의 `SlipBody.tracking_codes`, `BoxCloseBody` 세 필드, 모듈 측 "카운터당 본문 하나" 규칙의 참조 구현과 시험. Kani와 TLA+로 "결정 입력은 모든 위치의 서명 뒤"와 재개 판정의 완전성을 확인한다.
