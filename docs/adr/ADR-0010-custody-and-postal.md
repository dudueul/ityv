# ADR-0010: 보관 사슬과 관외 사전투표

> English summary: Custody rules: genesis inventory of boxes, seals and containers; every handoff dual-signed by sender and receiver from different organizations; CCTV segment hashes anchored to the ledger; one-way intake cassettes so sealed containers are never reopened; triple reconciliation (dispatch, postal acceptance, receipt) per batch; every mismatch is HOLD_REVIEW. For out-of-district early voting the baseline is P1: scan before sealing, an independent random envelope label (not derived from the cast id) travels only in trustee shares, destination marks receipt by label, lost envelopes are publicly counted as cast-not-received and excluded from the cryptographic tally. P4 (count where cast, abolishing the postal leg) is recommended in the legal annex; the custody route is genesis configuration so one codebase supports both.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0005, ADR-0006, ADR-0011; 위협 KR-01..20, ST-02..04, V7-015..024

## 결정

### 일반 보관 규칙
1. 투표함·봉인·운송함·카세트를 genesis 인벤토리에 고정한다. 인벤토리에 없는 용기의 이벤트는 수록하지 않는다.
2. 모든 인계는 `CustodyHandoff` 이벤트로 남기며 송신자와 수신자가 서로 다른 조직이어야 하고 둘 다 서명한다. 이전 인계 해시, 봉인 해시, 수량에 결속된다.
3. CCTV는 영상 구간 해시를 주기적으로 장부에 앵커한다. 영상 자체는 비공개이며 봉투 표면과 기표면이 보이지 않는 구도여야 한다.
4. 우편 접수는 일방향 투입구 또는 교체형 봉인 카세트로 하며, 이미 봉인된 용기는 개표 전까지 열지 않는다. 포화 시 새 카세트를 개시한다.
5. 발송 수, 우체국 인수 수, 도착 수, 보류 수를 회차별로 서로 다른 기관이 기록하고 대조한다.
6. 어떤 불일치도 자동 무효가 아니라 `HOLD_REVIEW`다.

### 관외 사전투표 기준선 P1
1. 유권자는 기표 후 투표지를 스캐너에 넣는다. 스캐너는 투함 기록을 만들고 투함 ID를 각인한 뒤 투표지를 돌려준다. 유권자는 사무원 앞에서 회송용 봉투에 밀봉하고 관외 투표함에 넣는다.
2. 봉투 라벨은 챔버 모듈들의 기여에서 유도한 독립 무작위 24바이트 토큰이며 스캐너가 인쇄한 라벨로 봉투에 부착한다. 투표지에 각인된 투함 ID와 무관하므로 봉투와 투표지를 (라벨, 각인)으로 연결할 수 없다. 라벨 값은 공개 기록에 노출하지 않으며 share로만 신뢰기관에 전달된다.
3. 관할 선관위는 봉투 수령 시 라벨을 읽어 `ReceiptMark` 이벤트(라벨 목록)를 장부에 올린다. 봉투는 열지 않는다.
4. 정족수는 집계 전 수령 대조 절차에서 관외 기록의 라벨 share만 복원해(선택·투함 ID는 복원하지 않음) 수령 목록과 대조하고 복원값을 소거한다. 수령되지 않은 기록은 `CAST_NOT_RECEIVED`로 공개 집계되고 암호 집계에서 제외된다.
5. 투표함 마감 시 봉투 수와 투함 기록 수가 정확히 같아야 하며 어긋나면 해당 투표소는 참관인 진술과 함께 `HOLD_REVIEW`다.
6. 개봉은 회차 단위로 하되 봉투와 투표지를 분리해 섞은 뒤 투표지를 계수한다. (봉투, 투표지) 쌍을 기록하는 행위는 금지한다.

### P4 현지 개표
법령 부속서에 권고 최종 상태로 둔다. genesis의 보관 경로가 `COUNT_AT_ORIGIN`이면 관외 투표지는 사전투표소 봉인함에 남고 개표일에 그 자리에서 선거구별로 개표되며 종이만 관할 선관위로 보낸다.

### 수집 프로필
- `IN_PERSON_SCAN`: 선거일, 관내, 관외, 재외(공관을 사전투표소로 보고 외교행낭을 보관 구간으로 추가).
- `RECEIPT_SCAN`: 거소, 선상. 투표 시점 커밋먼트가 없음을 상태 어휘에 명시한다.

## 결과

- 운송 중 바꿔치기는 개표 시 종이와 커밋먼트의 기록 우선 대조(ADR-0011)로 잡힌다.
- 유권자가 스캔 후 투표지를 손에 쥐는 순간이 생긴다. 밀봉은 사무원 앞에서 하며 수량 일치 규칙이 고의 불일치 시도를 격리한다.
