# ADR-0027: 투표 진행 기록

> English summary: During voting, the check-in unit and every commitment unit publish one signed progress tick per 10-minute uplink slot: cumulative sheets issued, spoiled and returned at the station, and cumulative sheets that entered each box. Ticks carry station- and box-level totals only (no ballot-style breakdown, no record, pseudonym, order or time finer than the slot) and are sent every slot even when nothing changed. From the public ticks anyone computes the number of sheets outside the box ("issued − entered − spoiled − returned") and three alarms: negative (more sheets entered than issued, a sign of stuffing), high (more sheets in hand than the station's booths can hold), and floor (sheets still outside after 20 quiet minutes, the signature of chain voting, which keeps a constant offset that the high alarm cannot see). Each alarm requires an on-site check signed by two clerks and two observers from different organisations within 20 minutes; a confirmed carry-out or an unexplained gap switches the station to a counterfoil check until close and puts its electronic layer on `HOLD_REVIEW`. Alarms never affect the validity of any ballot, and the absence of alarms proves nothing; correctness still rests on paper and the close equations.

- 상태: 채택
- 날짜: 2026-11-01
- 관련: ADR-0011(감사·분쟁), ADR-0018(공개 미러), ADR-0021(방문 단위 투입), ADR-0022(연결 공개와 감사, 10분 슬롯); `docs/spec/PROTOCOL.md` §5.8, §6.2, §7.10, §10.2, 부록 A–C; `docs/spec/ENCODING.md` §8.44–8.48; `docs/spec/FAILURE_CASES.md` §9; `docs/ui/SCREENS.md` §3, §6.2; `docs/legal/LEGAL_ANNEX.md` §5

## 맥락

투표가 진행되는 동안 공개원장에 올라가는 것은 참관인이 서명하는 누적 수(50건 또는 2시간마다), 다 찬 기록 묶음, 개시·비상 투입·봉인 변경 같은 사건이다. 교부와 투입이 맞는지는 마감 때 사람이 세는 `IssuanceCount`(§10.2)로 처음 확인한다.

그 사이에 생기는 일 두 가지를 그날 잡지 못한다.

1. **릴레이 투표.** 누군가 받은 투표지를 들고 나가면, 밖에서 미리 기표한 그 투표지를 다음 사람이 들고 들어와 넣고 새로 받은 투표지를 다시 들고 나온다. 매수·강요된 표가 사슬처럼 이어지고, 교부와 투입의 차이는 하루 종일 정확히 1장으로 유지된다.
2. **끼워 넣기.** 교부하지 않은 투표지가 투표함에 들어가면 투입이 교부를 앞지른다.

마감 등식이 둘 다 결국 드러내지만, 그때는 사슬이 이미 하루 동안 이어졌고 언제 시작됐는지도 모른다.

한편 기록을 한 장씩 실시간으로 올리는 방식은 쓸 수 없다. 기록이 올라온 시각과 누가 기표소에 들어갔는지를 맞추면 그 기록이 누구 것인지 알 수 있고, 기록의 `cast_id`는 종이에 각인되어 있어 종이 감사나 표본 열기에서 그 사람의 표가 드러난다. 그래서 기록은 지금처럼 다 찬 묶음 단위로, 순서를 섞어서만 낸다(VC-001, VC-079).

## 결정

1. **진행 기록.** 투표 중 10분 슬롯(ADR-0022)마다 장치 하나가 진행 기록 하나를 낸다.
   - 커밋먼트 유닛: 투표함별 `BoxProgress`. 그 투표함에 들어간 장수 누계(기록 + 검증 폐기 + 격리)와 상태(투입 중, 비상 투입 중, 마감).
   - 카운터·가명 유닛: 투표소별 `CheckinProgress`. 본인 확인 인원 누계, 교부 장수 누계(재교부 포함), 훼손 회수 장수 누계, 반납 장수 누계, 상태.
   - 장치의 하이브리드 서명이 붙고(`ProgressTick`), 슬롯의 업링크 프레임에 실린다.
2. **비밀 규칙.** 진행 기록에는 투표함·투표소 단위 누계만 있다. 투표양식별 내역, 검증 폐기와 격리의 구분, 기록 해시, 가명, 순번, 저널 head, 슬롯보다 세밀한 시각은 없다. 변화가 없어도 슬롯마다 반드시 하나를 보내서, 보냈는지 여부도 아무것도 알려 주지 않는다. 기록과 share 패키지는 지금처럼 다 찬 묶음 단위로만 나간다(VC-102).
3. **입력.** 본인 확인 인원은 카운터·가명 유닛이 직접 센다. 교부·훼손 회수·반납 장수는 신원 확인 단말이 유권자 식별자 없이 장수만 유닛에 넘긴다. 선거일 투표소는 교부 사무원이 교부할 때 장수를 확정하고(기본값은 그 유권자의 투표양식 묶음 장수, 차수가 나뉜 선거는 차수마다), 사전투표소는 발급기가 인쇄를 마친 장수를 넘긴다. 단말은 불신이지만, 마지막 진행 기록이 마감 때 사람이 센 수와 같아야 하므로(5항) 거짓 입력은 마감에서 드러난다.
4. **경보.** 누구나 공개된 진행 기록만으로 계산한다. 슬롯 t에서 투표소의 바깥 장수 `out(t)`는 교부 누계 − 그 투표소 모든 투표함의 투입 누계 − 훼손 회수 누계 − 반납 누계 − 확인된 반출 누계다.
   - **음수 경보:** 두 슬롯 연속 `out < 0`. 교부하지 않은 투표지가 들어갔거나 입력이 빠졌다.
   - **과다 경보:** 두 슬롯 연속 `out > L`. `L`은 genesis에 투표소별로 고정한 기준 장수다(기본: 기표소 수 × 2 × 한 방문의 최대 장수).
   - **바닥 경보:** 두 슬롯 동안 교부 누계와 투입 누계가 모두 그대로인데 `out > 0`. 20분 동안 아무도 받거나 넣지 않았는데 바깥에 투표지가 남아 있다. 릴레이 투표는 차이가 1장으로 유지되어 과다 경보에 걸리지 않으므로 이 경보가 잡는다.
   - 경보는 투표소 참관인 앱과 위원회 상황실이 같은 규칙으로 띄운다. 계산 결과는 누가 하든 같아야 한다(VC-103).
5. **현장 확인.** 경보가 나면 두 슬롯 안에 사무원 2인과 서로 다른 조직 참관인 2인이 기표소와 대기 줄을 보고 `ProgressCheck`를 수록한다. 담는 것: 경보 종류와 슬롯, 투표지를 들고 있는 사람 수, 판정(1 현장 인원으로 설명됨, 2 반출 확인, 3 입력 누락 정정, 4 설명 안 됨), 반출 장수, 진술 해시. 입력 누락은 단말에서 빠진 재교부·반납을 입력해 진행 기록 자체를 바로잡고, 그 사실을 판정 3으로 남긴다. 반출 장수는 이후 계산에서 바깥 장수에서 뺀다.
6. **강화 절차.** 판정 2·4이거나 두 슬롯 안에 확인이 없으면 그 투표소는 마감까지 교부 번호 대조로 바꾼다.
   - 교부 사무원은 투표지 번호(선거일 투표지는 떼지 않은 일련번호지의 번호, 사전투표지는 사람이 읽는 일련번호)를 이름 없는 교부표에 적어 투표지와 함께 준다.
   - 투입구 사무원은 투입 직전에 번호가 교부표와 같은지 보고 일련번호지를 떼어(선거일 투표지) 교부표와 함께 파쇄함에 넣는다.
   - 다르면 넣지 않고 그 투표지와 교부표를 봉인해 사건으로 남긴다.
   - 번호는 어떤 전자 기록에도 들어가지 않고, 해석 유닛은 지금처럼 일련번호를 읽지 않는다(VC-071). 미리 기표해 온 투표지는 지금 받은 투표지와 번호가 달라서 사슬이 끊긴다.
7. **효력과 보류.** 판정 2·4이거나 확인이 없으면 그 투표소 투표함들의 전자 층은 `HOLD_REVIEW`이고 사유가 남는다. 반출은 현행법 위반이므로 고발 대상이다. 종이 개표는 영향을 받지 않는다. 경보와 확인 결과만으로 어떤 투표지도 무효로 하지 않는다(LEGAL_ANNEX 개정안 6 ④).
8. **마감 대조.** 마지막 `BoxProgress`의 투입 누계는 `BoxClose`의 기록 수 + 검증 폐기 수 + 격리 수와, 마지막 `CheckinProgress`는 `IssuanceCount`의 교부·훼손·반납 수 및 마지막 `ObserverCountAttest` 누적 수와 같아야 한다. 누계가 줄어들거나, 슬롯이 빠지거나, 마감 수와 다르면 그 장치의 투표함(카운터·가명 유닛이면 투표소 전체)은 `HOLD_REVIEW`다(VC-102).
9. **정지 조건.** 비상 투입(`FallbackDeclared`)이나 장치 교체(커밋먼트 유닛 예비 교체, `CheckinUnitSwap`)가 있었던 투표소는 그 뒤로 마감까지 세 경보를 모두 멈춘다. 비상 투입구로 들어간 장수와 교체 전 마지막 슬롯 이후의 수를 실시간으로 알 수 없기 때문이다. 그 투표소는 마감 등식으로만 판단한다.

## 결과

- 릴레이 투표와 끼워 넣기를 그날 경보로 잡고, 언제 시작됐는지 슬롯 단위로 남는다. 현장에서 교부 번호 대조로 사슬을 끊을 수 있다.
- 공개원장을 가진 사람은 누구나, 어느 미러에서든 같은 경보를 계산한다. 위원회만 보는 내부 지표가 아니다.
- 비밀: 진행 기록은 누계만 담으므로 어느 기록이 누구 것인지 알려 주지 않는다. 다만 사람이 아주 적은 투표소에서는 "몇 시쯤 누군가 투표했다"가 드러날 수 있다. 이는 투표소 입구에서 이미 보이는 정보이고, 무엇을 찍었는지와는 이어지지 않는다.
- 한계: 투표소가 하루 종일 한 번도 비지 않으면 바닥 경보가 나지 않는다. 그때는 마감 등식이 잡는다. 비상 투입·장치 교체 뒤에도 마감 등식에 맡긴다. 경보가 없다고 정확하다는 뜻은 아니다. 정확성은 여전히 종이, 마감 등식, 공개 검증이 보장한다.
- 거짓 경보: 오래 기표하는 유권자 때문에 바닥 경보가 날 수 있다. 확인 한 번으로 끝나고(판정 1) 아무 효과가 없다. 시범(ADR-0026)에서 경보 빈도를 `PilotReport` 지표로 재고 기준을 조정한다.
- 비용: 장치당 슬롯마다 서명 하나(13시간 투표에 약 80개), 프레임 용량에 비하면 무시할 만하다. 신원 확인 단말 화면에 재교부·반납 입력이 생긴다.
