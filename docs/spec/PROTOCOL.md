# ityv 프로토콜 명세 v0.1 / Protocol Specification v0.1

> English summary: Normative specification of the ityv protocol: actors and trust, identifiers and encoding, hybrid signatures, genesis and the legal gate, the evidence ledger and public board with witness checkpoints, the pseudonymous participation ledger, cast-record generation by the split casting scanner with chamber-supplied sealed modules, pre-cast challenge, chamber-structured secret sharing with one-time-pad transport (primary) and hybrid KEM fallback, box close and custody, aggregate-only tally, record-first risk-limiting audit, disputes, the public verifier, destruction and retention, and a security argument. Status: research draft; nothing here is certified; release remains NO_GO.

상태: 초안 v0.1 (2026-10-30). 규범적 문장은 "해야 한다/하지 않는다"로 쓴다. 용어는 `GLOSSARY.md`를 따르고, 결정 근거는 `docs/adr/`에 있다. 바이트 형식은 `docs/spec/ENCODING.md`를 따른다.

---

## 0. 범위와 읽는 법

- 이 문서는 **무엇을 기록하고, 누가 서명하고, 누가 무엇을 검증하며, 무엇이 공개되는가**를 정한다. 하드웨어 규격, 운영 매뉴얼, 법령 문구는 각각 `docs/processing/`, `docs/usecases/`, `docs/legal/`에 있다.
- 검증 조건은 `VC-nnn`으로 번호를 붙인다. 모든 VC는 테스트·증명 ID로 연결되어야 한다(`CONSTITUTION.md` §5).
- 배포 프로필 L0에서는 §6(참여 장부 수량 부분), §5(장부·게시판), §10(보관)만 활성화된다. §7–§9, §11–§13의 L1 요소는 genesis의 `legal_authorization` 승인 범위가 있을 때만 활성화된다(§4.4).

## 1. 참여자와 신뢰 가정

| 참여자 | 역할 | 무엇에 대해 신뢰하는가 | 무엇에 대해 신뢰하지 않는가 |
|---|---|---|---|
| 선관위 | 운영 주체. 장치·서버·명부·투표지 취급 | 가용성 | 정확성, 비밀 |
| 유권자 | 기표, 투입 전 검증 요구, 추적코드 확인 | 자기 표의 포함 검증 | 선택 증명(불가능해야 함) |
| 투표사무원 | 확인, 교부, 마감, 인계 | 절차 수행 | 단독 판단 |
| 참관인 | 서명 권한. 확인 카운터 공동 서명, 마감·인계 서명, 투입 전 검증 요구 | 서로 다른 조직이 함께 있을 때 | 같은 조직 둘 |
| 증인단 | 체크포인트 서명 | 정족수와 다양성 조건 아래 일관성 | 입력의 진실성 |
| 신뢰기관 | share 보유, 합계 열기, 감사 표본 열기 | 챔버 접근구조 미만 공모 없음 | 개별 표 열람 금지 외 어떤 재량도 없음 |
| 독립검증위원회 | genesis·법적 승인 공동 서명, 지정, 의식, 분쟁 공동 접수 | 감독의 성실성 | 결과 변경(권한 없음) |
| 공개 검증자 | 게시판 전체 검증 | 1곳 이상 정직 | 선관위 서버 응답 |
| 우정사업본부·운송사 | 관외 봉투 운송 | 없음 | 수량, 봉인 |
| 장치(해석 유닛, 신원 확인 유닛) | 이미지 해석, 신원 확인 | 없음 | 모든 것 |
| 커밋먼트 유닛, 카운터·가명 유닛 | 암호 기록 생성 | 검증된 펌웨어의 명세 준수 | 하드웨어 변조(측정 부팅·봉인으로 보완) |
| 챔버 모듈 | 난수, 일회용 패드, 가명 PRF | 각 모듈은 자기 챔버가 공급. 서로 다른 챔버 모듈이 공모하지 않음 | 단일 모듈 |

적대자 모델은 ADR-0004(T3)다. 정당은 적대자 집합에 포함된다.

## 2. 식별자, 시간, 인코딩

- `election_id`: `Ident<64>`. 선거마다 유일하며 모든 객체의 첫 필드다.
- `ballot_style_id`: `Ident<64>`. 투표양식(선거구·선거 종류)별 식별자. 집계 단위.
- `box_id`, `station_id`, `device_id`, `module_id`, `witness_id`, `trustee_id`, `observer_id`, `actor_id`: `Ident<64>`. 모두 genesis에 등록된 값만 유효하다.
- 시간: TCB는 벽시계를 쓰지 않는다. 기록에 들어가는 시간은 선거 epoch(genesis에 고정된 날짜) 기준 **15분 구간 인덱스** `time_bucket: u64`뿐이며, 투함 기록에는 시간을 전혀 넣지 않는다(VC-001).
- 인코딩: `ENCODING.md`. 해시·서명·Fiat-Shamir 규칙은 `ENCODING.md` §4.
- 서명 purpose 목록은 부록 B.

## 3. 키와 서명

### 3.1 하이브리드 서명
서명 묶음 `HybridSig = mldsa87: [u8; 4627] ‖ ed25519: [u8; 64]`(고정폭 4,691바이트, 길이 접두사 없음). 검증자는 두 서명을 **모두** 같은 입력(`ENCODING.md` §4의 서명 메시지의 SHA3-512 다이제스트 64바이트, ML-DSA-87은 `purpose`를 FIPS 204 컨텍스트로 추가, Ed25519는 컨텍스트 없음)에 대해 검증해야 하며, 하나라도 실패하면 전체 실패다(VC-002). 구현은 `ityv-crypto` 크레이트만을 통한다(ADR-0015). 알고리즘 식별자는 메시지의 purpose와 genesis의 키 등록에 고정되어 있으므로 다운그레이드 협상이 존재하지 않는다(VC-003).

장기 보존 체크포인트(§5.6)에는 `slhdsa: [u8; 29792]`(SLH-DSA-SHAKE-256s, 같은 다이제스트를 서명하고 `purpose`를 FIPS 205 컨텍스트로 넘긴다)를 추가로 붙인다. 검증 결과는 `bool`이 아니라 검증된 입력(키, purpose, 객체, 서명)을 참조하는 `Verified` 토큰이며, 토큰 없이 서명된 객체를 소비하는 경로는 타입상 존재하지 않는다(ADR-0015 §2).

### 3.2 키 역할
| 키 | 보유자 | 생성 | 수명 |
|---|---|---|---|
| 장치 키 | 커밋먼트 유닛, 카운터·가명 유닛 | 제조 후 등록 의식에서 생성, 공개키를 genesis에 등록 | 선거별 |
| 모듈 키 | 챔버 모듈 | 챔버가 공급 시 생성, 공개키를 genesis에 등록 | 선거별 |
| 증인 키 | 증인 | 자체 HSM | 선거별 |
| 신뢰기관 키 | 신뢰기관 구성원 | 자체 HSM, DKG 참여 | 선거별, 파기 의식에서 파기 |
| 참관인 토큰 | 참관인 | 추천 조직이 발급, genesis에 등록 | 선거별 |
| 선관위·위원회 키 | 선관위, 독립검증위원회 | 자체 HSM | 선거별 |

모든 키는 선거별이며 genesis에 등록되지 않은 키의 서명은 어떤 상태 전이도 일으키지 않는다(VC-004).

## 4. 기준정보(genesis)

### 4.1 내용
`Genesis` 객체(스키마 0x0002)는 다음을 담는다.
- `election_id`, `election_epoch_day`, `policy_hash`(법령·규칙·계수 규칙 문서 묶음의 해시), `proof_system_id`.
- `ballot_styles[]`: 투표양식별 선택지 수 `m`, 청크 수 `k = ⌈(m+2)/9⌉`(§7.4).
- `expected_boxes[]`: 정렬·중복 없음. 각 항목에 `box_id`, `station_id`, `ballot_style_id`, `capture_profile`, `route_id`, 장치 공개키, 모듈 공개키 목록.
- `stations[]`: 확인 장치 공개키, 투표소 참관인 토큰 목록.
- `witness_roster`: 13개 이상 항목(`witness_id`, 조직, 공급자, 지역, 공개키). `witness_roster_hash`.
- `trustee_roster`: 챔버별 구성원(`trustee_id`, 챔버 코드, 조직, 공개키, `k_c`, `n_c`). 챔버 코드: X, Y, J, A, C, N.
- `custody_routes[]`: 경로별 인계 순서(조직 역할 열거), `COUNT_AT_ORIGIN` 여부.
- `appointments[]`: 임명 이벤트 해시 목록(§4.5).
- `legal_authorization`: §4.4.

### 4.2 서명과 핀
genesis 본문의 해시는 독립검증위원회와 선관위가 각각 하이브리드 서명하고, 증인단 정족수(9 이상, 다양성 조건 충족)가 서명한다. genesis 해시는 대역 외로 배포한다. 최소: 관보 게재, 독립검증위원회 웹사이트, 지정 공개 검증자 3곳 이상의 서명 게시, 인쇄물. 검증기는 **호출자가 명시적으로 제공한 핀**과 일치하지 않는 genesis를 거부해야 한다(VC-005). 같은 서버에서 받은 핀은 핀이 아니다.

### 4.3 변경
genesis는 선거 시작 후 변경되지 않는다. 장치 교체 등 불가피한 변경은 `GenesisAmendment` 이벤트(선관위·위원회 공동 서명, 증인 정족수 서명)로 추가되며, 원본은 그대로 남는다. 교체된 장치의 과거 기록은 그대로 유효하다.

### 4.4 법적 승인 객체
`LegalAuthorizationBody`(스키마 0x0003): `election_id`, `scopes[]`(정렬·중복 없음), `statute_refs_hash`, `effective_from_day`, `effective_until_day`. 선관위와 위원회의 서명이 모두 있어야 유효하다(VC-006). 승인 범위 코드: 1 `PUBLIC_BOARD`, 2 `TRUSTEE_BODY`, 3 `BALLOT_MARK`, 4 `CRYPTO_TALLY_AID`, 5 `RLA`, 6 `OBSERVER_ACCESS`, 7 `DEPLOY_AUTH`, 8 `STAGE_GATE`, 9 `VOTER_CODE`.

활성화 규칙:
- `BALLOT_MARK` 없이 `CastRecord`를 만들 수 없다. `VOTER_CODE` 없이 `Slip`을 만들 수 없다. `TRUSTEE_BODY` 없이 share 패키지를 만들 수 없다. `CRYPTO_TALLY_AID` 없이 합계 열기 이벤트를 수록할 수 없다. `RLA` 없이 표본 추출 이벤트를 수록할 수 없다(VC-007).
- `VOTER_CODE`는 `BALLOT_MARK`와 `TRUSTEE_BODY`를 전제한다. 전제 없는 조합은 genesis 검증에서 거부한다(VC-008).
- 코드에서는 capability 타입으로 강제한다(`CONSTITUTION.md` §1.7).

### 4.5 임명 이벤트
증인·신뢰기관·위원회 위원·참관인의 독립성은 추천 기관이 서명한 `Appointment` 이벤트로 장부에 남긴다. 필드: 피임명자 ID, 역할, 챔버, 추천 기관 ID, 추천 기관 서명, 이해충돌 공시 문서 해시. genesis의 명부 항목은 대응하는 임명 이벤트 해시를 참조해야 한다(VC-009).

## 5. 증거 장부와 공개 게시판

### 5.1 프레임
장부는 선거별 추가 전용 프레임 로그다. 프레임 객체 `LedgerFrame`(스키마 0x0001): `election_id`, `seq`(1부터 1씩 증가), `prev_hash`(이전 프레임의 해시, 첫 프레임은 0), `event_schema_id`, `event_hash`(이벤트 객체의 `ENCODING.md` §4 해시). 프레임 해시 = 프레임 객체의 §4 해시. 이벤트 본문은 프레임과 별도로 저장되며 `event_hash`로 결속된다. 디스크 형식은 길이 접두 프레임의 연속이며, 찢어진 꼬리는 복구하지 않고 격리한다(VC-010).

### 5.2 이벤트 종류와 공개 등급
부록 A에 전체 목록이 있다. 공개 등급: `public`(게시판에 공표), `restricted`(참관인·감사인·법원 열람), `sealed`(신뢰기관 또는 법원만). 투함 기록, 체크포인트, 마감, 인계, 분쟁 처리 결과, 합계 열기, 표본 추출은 `public`이다. share 패키지, 수령 라벨 목록의 원본, 영상 해시의 대응표는 `sealed` 또는 `restricted`다.

### 5.3 Merkle 트리
게시판의 Merkle 트리는 RFC 9162의 트리 모양(좌측 완전 이진, 가장 큰 2의 거듭제곱 분할)을 쓰되 해시는 SHA3-512이고 리프 접두 `0x00`, 노드 접두 `0x01`이다. 리프는 프레임 해시다(리프 해시 = `SHA3-512(0x00 ‖ 프레임 해시)`, 노드 = `SHA3-512(0x01 ‖ 왼쪽 ‖ 오른쪽)`, 빈 트리의 root = `SHA3-512("")`). 포함 증명과 일관성 증명은 RFC 9162 §2.1.3·§2.1.4의 알고리즘을 SHA3-512로 수행한다(VC-011). 트리 크기 상한은 2^40이므로 포함 증명은 40개 이하, 일관성 증명은 41개 이하의 해시다(RFC 9162의 일관성 증명은 깊이 + 1개까지 될 수 있다). 체크포인트의 `box_close_root`와 `dispute_root`는 같은 해시 규칙의 **정렬 집합 트리** root다: 리프는 해당 이벤트 해시를 바이트 오름차순으로 정렬한 것이고 중복은 거부하며 빈 집합의 root는 빈 트리의 root다. 구현은 `ityv-ledger`(ADR-0016).

### 5.4 체크포인트
`CheckpointBody`(스키마 0x0004): `election_id`, `ledger_id`, `keyset_id`, `checkpoint_seq`, `tree_size`, `root_hash`, `previous_checkpoint_hash`(seq 1이면 0), `box_close_root`(마감 이벤트 해시들의 정렬 Merkle root), `dispute_root`(미해결 분쟁 이벤트 해시들의 root), `genesis_hash`, `time_bucket`.

증인은 다음을 모두 확인한 뒤에만 서명한다(VC-012): 자기 서명한 직전 체크포인트와의 일관성 증명, `tree_size` 단조 증가, `previous_checkpoint_hash` 일치, genesis 해시 일치, `box_close_root`와 `dispute_root`의 재계산 일치. 증인은 같은 `checkpoint_seq`에 서로 다른 본문을 서명하지 않는다(VC-013). 증인 도구는 마지막으로 서명한 체크포인트를 기억(`WitnessMemory`, 스키마 0x0011)하고 `checkpoint_seq`가 그 다음이며 `election_id`·`ledger_id`·`keyset_id`가 같을 때만 서명한다. 확인과 기억의 전진은 한 동작이며, 도구는 전진한 기억을 영속화한 뒤에 서명한다(`docs/models/LedgerWitness.tla`의 `HonestSign`, ADR-0016 §4). 정족수는 9 이상이며 조직 7·공급자 4·지역 3 이상이어야 한다(VC-014). 정족수 프로필 `(n, q, f)`는 `2q − n > f`를 만족해야 한다(기본 13/9/4).

장부에 수록되는 체크포인트 이벤트는 `SignedCheckpoint`(스키마 0x0010, `ENCODING.md` §8.4) = `body`(인코딩된 `CheckpointBody` 객체 바이트) ‖ `signatures`(`witness_id` 오름차순의 `{witness_id, HybridSig}` 목록, 64 이하)이다. 각 서명은 `body` 바이트에 대한 purpose `checkpoint`의 하이브리드 서명이고, 객체는 모든 서명이 명부 키로 검증되고 명부 밖·중복 ID가 없으며 정족수와 다양성을 만족할 때만 유효하다. 하나라도 틀리면 객체 전체가 무효다.

### 5.5 외부 앵커와 공표 기한
체크포인트는 생성 후 1시간 이내에 지정 공개 검증자 3곳 이상에 전달되고, 각 검증자는 자기 서명으로 수신을 게시한다. 투표 종료 후 24시간 이내에 전 기간 게시판이 공표되어야 한다. 기한 위반은 `PublicationBreach` 이벤트(위원회 서명)로 기록된다.

### 5.6 장기 보존
최종 체크포인트에는 SLH-DSA 서명을 추가한다. 게시판 전체(프레임, 이벤트 본문, 체크포인트, 서명, genesis, 검증기 소스 해시)는 불변 저장소 2곳 이상(서로 다른 관리 주체)에 보관한다. 보존 기간과 알고리즘 전환 절차는 법령 부속서 9번을 따른다.

## 6. 유권자 확인과 참여 장부

### 6.1 명부 동결
선거 시작 전 선관위는 `RollFreeze` 이벤트를 수록한다. 내용: 투표구별 명부 인원수, 명부 가명 다중집합의 Merkle root(가명은 §6.4 규칙으로 계산), 동결 시점. 이후 변경은 `RollAmendment` 이벤트(사유 코드, 영향 인원수, 승인자 서명)로만 가능하다. 가명 자체는 선거 후에만 공개된다.

### 6.2 확인 장치
확인 장치는 신원 확인 유닛(불신), 카운터·가명 유닛(검증), 챔버 모듈 X·Y로 구성된다. 신원 확인 유닛은 신분증을 확인하고 `voter_id`(주민등록번호 등 법정 식별자)를 카운터·가명 유닛에 넘긴다. 카운터·가명 유닛은 가명을 만들고(§6.4) `CheckinCounter` 이벤트를 서명한 뒤 `voter_id`를 소거한다(VC-015).

### 6.3 확인 카운터 이벤트
`CheckinCounter`(스키마 0x0009): `election_id`, `station_id`, `seq`(투표소별 1부터), `pseudonym: Hash512`, `time_bucket`, `ballot_style_id`, 카운터·가명 유닛 서명, 모듈 X·Y 서명(각각 `(station_id, seq)`에 대한 서명). 50건마다 또는 2시간마다(먼저 오는 쪽), 그리고 마감 시 `ObserverCountAttest` 이벤트: 누적 수와 서로 다른 조직의 참관인 토큰 서명 2개 이상(VC-016).

### 6.4 가명
`pseudonym = SHA3-512("ityv:pseudonym:v1" ‖ 0x00 ‖ PRF_X(voter_id) ‖ PRF_Y(voter_id))`. `PRF_c(voter_id) = SHA3-512("ityv:prf:v1" ‖ 0x00 ‖ key_c ‖ voter_id)`를 챔버 모듈 c 안에서 계산한다. `key_c`는 선거별이며 챔버 c가 보유하고 파기 의식에서 파기한다. 어느 한 챔버도 혼자서는 가명을 계산할 수 없다(VC-017). 모듈은 `voter_id`를 계산 후 즉시 소거한다.

### 6.5 공개와 검증
투표 종료 후 선관위는 투표소별 가명 다중집합을 **순서 없이 정렬한 형태**로 공개한다. 누구나 다음을 검증한다(VC-018).
- 전 채널 합집합에 중복 가명이 없다.
- 투표소별 가명 수 = `ObserverCountAttest` 최종 누적 수 = 교부 수 − 훼손·반납 수 = 해당 투표함들의 투함 기록 수 + 투입 전 검증 폐기 수(§8).
- 가명 다중집합이 `RollFreeze`의 명부 가명 집합(과 `RollAmendment`)의 부분집합이다. 이 검사는 명부 가명 집합이 공개된 뒤에만 가능하므로, 선거 후 명부 가명 집합의 Merkle 포함 증명을 선관위가 제공하고 독립 명부 감사가 표본을 확인한다.

절대 규칙: 어떤 이벤트도 가명 또는 `voter_id`를 `cast_id`, 추적코드, 투함 기록 해시와 함께 담지 않는다(VC-019).

## 7. 투함과 투함 기록

### 7.1 장치 구성
투함 스캐너는 세 종류의 부품으로 물리적으로 나뉜다.
- **해석 유닛**(불신): 투표지 이미지를 얻어 선택 인덱스를 판정한다. 커밋먼트 유닛으로 가는 단방향 링크로 `Interpretation { ballot_style_id, option_index: u16 }`만 보낸다. 이미지를 영속 저장하지 않아야 하나 이 성질은 증명되지 않으며 하드웨어 인증(P0 게이트)으로 다룬다.
- **커밋먼트 유닛**(검증): `no_std` Rust. 커밋먼트, 정형성 증명, share, 서명, 추적코드, 각인 명령을 만든다. 선택·난수·투함 ID·share를 처리 후 즉시 소거한다(VC-020, V3 증명 대상).
- **챔버 모듈**(챔버 공급): 챔버마다 하나. X와 Y 모듈은 필수이며 절대 위임하지 않는다. J·A·C는 자체 모듈을 두거나 독립검증위원회가 공급하는 중립 모듈에 위임할 수 있다(위임은 그 세 챔버의 share 기밀이 한 모듈에 집중됨을 뜻하며 공개 상태로 표기한다). N(선관위)은 모듈을 두지 않고 KEM 대체 경로를 쓴다. 모듈의 기능: 난수 기여, 투함 ID·봉투 라벨 기여, 자기 챔버 구성원의 일회용 패드 보관과 XOR, 일회성 MAC 키 공급, 카운터 서명.

### 7.2 모듈 발급 절차와 일괄 증명
커밋먼트 유닛은 표마다 존재하는 모든 모듈에 `Issue(device_id)`를 요청하고, 모듈 c는 `ModuleIssue`를 돌려준다.
- 공개부: `module_id`, `counter`(모듈별 1부터 1씩 증가). 서명은 표마다 붙이지 않고 §7.2.1의 일괄 증명으로 묶는다.
- 비공개부: `r_c: [Scalar; k]`, `cid_c: Token192`, `lab_c: Token192`(관외·재외 프로필에서만), 그리고 챔버 c 구성원 각각을 위한 일회성 MAC 태그 `tag_{c,i}` = `OTMAC(key_{c,i,counter}, r_c ‖ cid_c ‖ lab_c)`. `key_{c,i,counter}`는 구성원 i의 패드에서 §9.4.3 규칙으로 꺼낸 32바이트다. `OTMAC`은 Poly1305 일회성 MAC이다.
- 모듈은 발급한 값을 보관하지 않되, 아직 일괄 증명에 포함되지 않은 발급의 `counter` 목록은 보관한다. 카운터는 단조 증가하며 재사용하지 않는다.

#### 7.2.1 기록 서명과 일괄 증명(BatchAttest)
서명은 두 층이다. 비싼 것은 ML-DSA-87(4,627바이트)이고 Ed25519(64바이트)는 싸므로, **기록마다 고전 서명**을 붙이고 **배치마다 하이브리드 서명**을 붙인다. 이 구조의 경우의 수 분석은 `docs/spec/FAILURE_CASES.md`에 있다(ADR-0014).

**기록 서명.** 커밋먼트 유닛은 `CastRecordBody` 객체 바이트에 장치 Ed25519 키로 서명하고(purpose `cast-record`), 존재하는 각 모듈은 메시지 `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`(정규 인코딩)에 자기 Ed25519 키로 서명한다(purpose `module-record`). 모듈은 본문 내용을 보지 않고 해시만 본다. 이 서명들은 기록과 함께 즉시 공개되며, 고전 공격자에 대해 기록의 출처를 그 자리에서 증명한다.

**일괄 증명.** 커밋먼트 유닛은 기록 64건마다, 또는 마지막 기록 후 15분이 지나면, 또는 마감 직전에 배치를 닫는다. 배치를 닫을 때:
1. 커밋먼트 유닛은 메모리에 유지한 해시 사슬과 봉인 저널의 내용을 대조한다. 다르면 서명하지 않고 `JournalMismatch` 사건으로 격리한다(VC-056).
2. 배치에 든 기록 해시의 정렬 Merkle root와 각 모듈의 카운터 구간 `[counter_first, counter_last]`를 담은 `BatchAttest` 본문을 만든다.
3. 각 모듈은 자기가 발급했으나 아직 증명되지 않은 카운터 목록이 본문의 구간과 정확히 일치할 때에만 본문에 하이브리드 서명한다. 틈이나 누락이 있으면 서명을 거부하고, 거부 사실은 본문의 `module_refusals`에 남는다(VC-021).
4. 커밋먼트 유닛이 본문에 하이브리드 장치 서명을 한다.
5. `BatchAttest` 이벤트(공개)를 수록한다. 본문 `BatchAttestBody`(스키마 0x0012): `election_id`, `box_id`, `batch_index`, `record_count`, `records_root`, `module_ranges: Array<{module_id, counter_first, counter_last}, 6>`, `module_refusals: Array<module_id, 6>`, `journal_head`, `time_bucket`. 이벤트 `BatchAttest`(스키마 0x0017) = 본문 바이트 + `module_sigs` + `device_sig`(purpose `batch-attest`). 필드 배치는 `ENCODING.md` §8.12·§8.13.

**늦은 마감.** 장치가 배치를 닫기 전에 멈췄다가 살아나면, 사무원 2인과 서로 다른 조직 참관인 2인의 입회 아래 장치를 켜고 저널에서 미결 배치를 닫는다. 결과는 `LateBatchClose` 이벤트(배치 본문과 서명, 입회자 서명, 사유 코드)로 수록되며 일반 배치와 같은 효력을 가진다. 모듈도 미결 카운터 목록이 일치해야 서명한다.

**미증명 기록.** 기록 서명은 유효하나 어떤 `BatchAttest`에도 포함되지 않은 기록은 `UNATTESTED` 상태다. 검증기는 이를 목록으로 공개하고, 집계 범위(§11.1)에서 `UNATTESTED` 사유로 제외하며, 감사(§12)에서는 종이와 대조한다. 늦은 마감으로 증명되면 `CAST_COMMITTED`로 돌아온다. 집계 범위는 늦은 마감 기한(마감 후 24시간) 이후에 확정한다(VC-057).

검증기는 모든 기록이 정확히 하나의 `BatchAttest`에 포함되는지, 배치의 카운터 구간이 투표함 전체에서 틈 없이 이어지는지, 기록에 적힌 `(module_id, counter)`가 그 배치 구간 안에 있는지, 기록 서명이 모두 유효한지 확인한다(VC-053). 같은 `batch_index`에 서로 다른 본문이 둘 있으면 장치 이중 서명 사건이다.

### 7.3 생성 절차
1. 해석 유닛이 `Interpretation`을 보낸다. `option_index` `t`는 0(BLANK), 1..m(제150조 순서의 후보), m+1(UNREADABLE) 중 하나여야 하며 그 외 값은 거부한다. 투표지는 이 시점부터 스캐너 내부 대기 구역에 물리적으로 머문다.
2. 커밋먼트 유닛이 모든 모듈에서 `ModuleIssue`를 받는다. `r_j = Σ_c r_{c,j} (mod ℓ)`, `cast_id = SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_X ‖ cid_Y ‖ …)[0..24]`(존재 모듈을 `module_id` 바이트 오름차순으로 연접), 관외면 `env_label = SHA3-512("ityv:envlabel:v1" ‖ 0x00 ‖ lab_X ‖ lab_Y ‖ …)[0..24]`를 같은 순서로 유도한다.
3. 커밋먼트 `C_j`를 §7.4로 계산하고 정형성 증명 `π`를 §7.5로 만든다.
4. `CastRecord`(§7.6)를 만들고 추적코드 = 그 객체의 해시로 둔다.
5. `SharePackage`(§9.3)를 만들고 그 해시를 `CastRecord`에 넣는다. 따라서 순서상 share 패키지의 해시가 먼저 확정되고 기록이 그것을 참조한다.
6. 화면에 "투입 / 검증" 선택이 표시된다. 검증이 선택되면 §8로 간다.
7. 투입이 선택되면 기록 해시와 share 패키지를 봉인 저널(§7.8)에 추가하고 fsync한다. **저널 기록이 영속화되기 전에는 각인도 투입도 하지 않는다**(VC-054). 전원 상실 시 대기 구역의 투표지는 저널에 기록이 있으면 재개 후 각인·투입하고, 없으면 기록 없는 투표지로 격리 봉투에 보내 `QUARANTINED` 사유로 남긴다.
8. 각인기에 `cast_id`를 인쇄하게 하고(숫자와 2차원 바코드) 투표지를 함으로 떨어뜨린다. 각인 실패 시 투표지는 함으로 들어가지 않고 격리 봉투로 보내며 `ImprintFailure` 이벤트로 기록 상태를 `QUARANTINED`로 바꾼다(VC-023). 관외·재외 프로필에서는 투표지를 함이 아니라 반환 트레이로 내보내고 봉투 라벨 스티커를 인쇄한다.
9. `VOTER_CODE`가 활성화돼 있으면 슬립을 인쇄한다(§7.7).
10. 모든 비밀값을 소거한다.

스캐너를 쓸 수 없고 예비 장치도 없으면 사무원 2인과 참관인 2인이 `FallbackDeclared` 이벤트(사유, 시작 구간)를 수록한 뒤 봉인된 비상 투입구로 투표지를 받는다. 이 투표지에는 기록이 없으며 마감 때 `no_record_count`로 센다. 예비 장치가 오면 `FallbackEnded`를 수록한다. 비상 투입구 사용은 법령 부속서 개정안 2의 장치 장애 대체 절차에 따른다.

참관인이 요구하는 검증에는 실제 투표지가 아니라 **시험용 투표양식**(`ballot_style_id`가 `TEST-`로 시작)의 투표지를 쓴다. 시험용 기록은 `TallyScope`에서 `TEST_BALLOT` 사유로 제외되고 참여 장부와도 대조하지 않는다(VC-055).

### 7.4 커밋먼트 인코딩
- 군: Ristretto255, 위수 ℓ. 베이스 `G_val = HashToGroup("ityv:base:val:v1")`, `G_id = HashToGroup("ityv:base:id:v1")`, `H = HashToGroup("ityv:base:rand:v1")`. `HashToGroup(label) = from_uniform_bytes(SHA3-512(label ‖ 0x00))`: 라벨 뒤 `0x00` 구분자를 붙인 SHA3-512 출력 64바이트를 Ristretto255의 균등 사상(Elligator 2 기반 `from_uniform_bytes`)으로 보낸다(`ENCODING.md` §4). 세 베이스의 32바이트 인코딩은 `ityv-crypto`의 상호운용 벡터에 고정한다. 세 베이스 사이의 이산대수 관계는 누구도 모른다.
- `M = 2^26`. 청크 `j = 0..k-1`은 인덱스 `t ∈ [9j, 9j+8]`을 담당한다. `val_j(t) = 2^{26·(t−9j)}` if `t ∈ chunk j`, else `0`.
- `C_j = val_j(t)·G_val + cast_id·G_id + r_j·H`. `cast_id`는 24바이트 little-endian 정수로 스칼라에 사상한다(`< 2^192 < ℓ`).
- 집계 시 자릿수 `d_t = ⌊T_j / 2^{26·(t−9j)}⌋ mod 2^26`는 인덱스 t의 표 수다. 전국 유권자 수가 `2^26`보다 작으므로 자리올림이 없다(VC-024: 각 자릿수가 해당 투표양식의 교부 수를 넘지 않음을 검증기가 확인한다).

### 7.5 정형성 증명
진술: 커밋먼트 벡터 `(C_0..C_{k−1})`에 대해 어떤 `t ∈ {0..m+1}`와 `(x, y_0..y_{k−1})`가 존재하여 모든 j에 `D_{t,j} := C_j − val_j(t)·G_val = x·G_id + y_j·H`.

증명자(참 가지 `t*`, 증인 `x = cast_id`, `y_j = r_j`):
1. `t ≠ t*`에 대해 무작위 `c_t, z_{t,x}, z_{t,0..k−1}`를 뽑고 `a_{t,j} = z_{t,x}·G_id + z_{t,j}·H − c_t·D_{t,j}`.
2. `t*`에 대해 무작위 `α, β_0..β_{k−1}`를 뽑고 `a_{t*,j} = α·G_id + β_j·H`.
3. `c = FS("ityv:proof:or-rep:v1", 대본)`. 대본 = 다음 순서의 정규 인코딩(`ENCODING.md` §2): `election_id: Ident<64>` ‖ `box_id: Ident<64>` ‖ `ballot_style_id: Ident<64>` ‖ `proof_system_id: u16` ‖ `option_count: u16`(= m+2) ‖ `chunk_count: u8`(= k) ‖ `commitments: Array<Point, 8>`(`u32` 개수 k 뒤 `C_0..C_{k−1}`) ‖ `announcements: Array<Point, 512>`(`u32` 개수 (m+2)·k 뒤 `a_{t,j}`, t 외측·j 내측). 두 개수 필드와 배열 접두사가 커밋먼트와 공표값의 경계를 유일하게 정한다.
4. `c_{t*} = c − Σ_{t≠t*} c_t`, `z_{t*,x} = α + c_{t*}·x`, `z_{t*,j} = β_j + c_{t*}·y_j`.
5. 증명 `π = { c_0..c_{m+1}, z_{t,x}, z_{t,j} }`. `a` 값은 전송하지 않는다. 정규 인코딩: `option_count: u16` ‖ `chunk_count: u8` ‖ t = 0..m+1 순서로 `c_t ‖ z_{t,x} ‖ z_{t,0}..z_{t,k−1}`(모든 스칼라 32바이트 little-endian canonical). 길이 = `3 + (m+2)·(k+2)·32`바이트. 디코더는 `k ≠ ⌈(m+2)/9⌉`, 비정규 스칼라, 범위 밖 개수를 거부한다.

검증자: 모든 `t, j`에 대해 `a_{t,j} = z_{t,x}·G_id + z_{t,j}·H − c_t·D_{t,j}`를 재계산하고, `c`를 같은 대본으로 재계산한 뒤 `Σ_t c_t ≡ c (mod ℓ)`을 확인한다(VC-025). 모든 스칼라는 canonical이어야 하고 모든 점은 유효한 Ristretto 인코딩이어야 한다(VC-026).

성질: 특수 건전성(두 다른 챌린지에서 증인 추출), 완전 증인 구별불가성(가지 간 분포 동일). 후자가 §16의 영구 비밀성 논증에 필요하다. 크기: `(m+2)·(k+2)` 스칼라에 3바이트 머리부. 대통령 선거(m=14, k=2)에서 2,051바이트, 상한(m+2=64, k=8)에서 20,483바이트.

### 7.6 투함 기록
`CastRecordBody`(스키마 0x0005), 공개: `election_id`, `box_id`, `ballot_style_id`, `proof_system_id: u16`, `commitments: Array<Point, 8>`, `proof: Bytes<20483>`(§7.5 증명 인코딩을 그대로 담는다; 상한은 m+2=64, k=8일 때의 길이), `module_counters: Array<{module_id, counter: u64}, 6>`, `share_package_hash: Hash512`, `transport_flags: u8`(비트0: 한 구성원 이상 KEM 대체 사용, 비트1: 중립 모듈 위임 사용).

`CastRecord`(스키마 0x0016) = `body`(인코딩된 본문 객체 바이트) + `device_sig_ed25519: [u8; 64]` + `module_sigs: Array<{module_id, ed25519: [u8; 64]}, 6>`(`ENCODING.md` §8.6·§8.7). 추적코드 = **본문** 객체 바이트의 `ENCODING.md` §4 해시. 양자내성 서명은 §7.2.1의 `BatchAttest`가 기록 해시 집합에 대해 제공하며, 검증기는 배치 포함이 없는 기록을 `UNATTESTED`로 분류한다(VC-053, VC-057). 기록에는 시간, 순번, 유권자 정보, 투함 ID, 봉투 라벨, 선택이 없다(VC-001, VC-019). 크기는 선택지 14개·청크 2개 기준 본문 약 2.4KB에 기록 서명 약 0.26KB, 배치 증명 분담 약 0.3KB를 더해 표당 약 3KB다.

### 7.7 슬립
`SlipBody`(스키마 0x0019): `election_id`, `station_id`, `time_bucket`, `tracking_code: Hash512`. `Slip`(스키마 0x000A) = 본문 바이트 + `device_sig`(purpose `slip`, 하이브리드)(`ENCODING.md` §8.18). Ed25519 부분은 추적코드와 함께 첫 QR에, ML-DSA-87 부분(4,627바이트)은 이어지는 QR 둘에 나눠 인쇄한다. 인쇄 형식은 `docs/ballot/`에 있다. 분쟁 접수 시 두 서명을 모두 검증한다. 슬립은 선택에 관한 정보를 담지 않으며, 같은 추적코드를 가진 기록이 게시판에 있는지만 확인할 수 있다.

### 7.8 봉인 저널과 투표함 집합
커밋먼트 유닛은 기록 해시와 share 패키지를 순서대로 담은 해시 체인 저널(`JournalEntry`, 스키마 0x0014, `ENCODING.md` §8.19; 항목 종류: 기록, 검증 폐기, 격리, 배치 마감, 투표함 마감)을 fsync하며 유지한다. 저널은 `sealed` 등급이며 투함 순서를 드러내므로 공개하지 않는다. 투표함 마감 시 공개되는 것은 기록 해시를 바이트 사전순으로 정렬한 **집합**과 그 Merkle root뿐이다(VC-027). 저널은 모든 구성원의 `ShareReceipt`가 확인된 뒤 파기 의식까지 보관한다.

업로드 전 저널 되감기를 막기 위해 50건마다 또는 2시간마다(먼저 오는 쪽) 서로 다른 조직의 참관인 둘이 토큰으로 `ScanCountAttest` 이벤트를 공동 서명한다(본문 `ScanCountAttestBody` 0x0013: `election_id`, `box_id`, 누적 기록 수, 검증 수, 격리 수, 저널 head, `time_bucket`; 이벤트 0x001B = 본문 바이트 + 참관인 서명, purpose `scan-count`, `ENCODING.md` §8.14·§8.15). 마감 시 `BoxClose`의 수량과 저널 head는 마지막 `ScanCountAttest`와 단조 연속이어야 한다(VC-052).

## 8. 투입 전 검증

1. 유권자 또는 참관인이 투입 전에 "검증"을 선택한다. 유권자의 요구는 거부할 수 없다. 참관인 요구는 투표소 정책이 정한 시간당 상한을 둘 수 있으나 상한과 거부 사실은 이벤트로 남긴다.
2. 커밋먼트 유닛은 `ChallengeOpeningBody`(스키마 0x0006)를 만든다. 공개: `election_id`, `box_id`, `ballot_style_id`, `record_hash`, `option_index`, `cast_id`, `r_0..r_{k−1}`, 모듈별 `(module_id, counter, r_c, cid_c)`. 이벤트 `ChallengeOpening`(스키마 0x0018) = 본문 바이트 + `device_sig`(purpose `challenge`, 하이브리드)(`ENCODING.md` §8.8·§8.9). 이 표의 선택은 공개되지만 표는 폐기되므로 실제 투표와 무관하다.
3. 누구나 `C_j`와 `π`를 공개값으로 재구성·재검증하고, 모듈 `pub_sig`의 카운터가 기록과 일치하는지 확인한다(VC-028).
4. 투표지는 격리 봉투(검증 폐기)로 보내고 기록 상태는 `CHALLENGED_SPOILED`다. 유권자는 새 투표지를 교부받는다. 폐기 봉투의 실물 수는 마감 시 `challenge_count`와 같아야 한다(VC-029).
5. 재구성이 실패하면 `ScannerQuarantine` 이벤트(참관인 2인 서명)를 수록하고 장치를 예비로 교체한다. 그 장치가 만든 모든 기록은 §12.5의 전수 대조 대상이다(VC-030). 이미 함에 든 투표지는 그대로 보존한다.

강요 저항: 강요자가 검증을 요구하더라도 검증된 표는 폐기되고 유권자는 다시 기표하므로 검증 결과는 실제 투표를 증명하지 않는다.

## 9. share 생성과 전송

### 9.1 비밀값
기록 하나당 비밀값은 모듈 c마다 `r_{c,0..k−1}`, 그리고 `cast_id`(스칼라), 관외·재외면 `env_label`(스칼라)이다. 모듈별 `cid_c`, `lab_c`는 §9.3의 봉인 패키지에 평문으로(패드 암호화 아래) 포함한다.

### 9.2 선형 비밀분산
각 비밀 `s`에 대해:
1. `s_X, s_Y ← 무작위`, `s_rest = s − s_X − s_Y (mod ℓ)`.
2. `s_rest`를 챔버 {J=1, A=2, C=3, N=4}에 3-of-4 Shamir로 분산: 차수 2 다항식 `p`, `p(0) = s_rest`, 챔버 share `σ_c = p(c)`.
3. `σ_X = s_X`, `σ_Y = s_Y`, `σ_J, σ_A, σ_C, σ_N`을 각 챔버 안에서 `k_c`-of-`n_c` Shamir로 구성원에게 분산한다.

이 체계는 선형이므로 기록들의 구성원 share를 더하면 비밀의 합에 대한 구성원 share가 된다. 접근구조 Γ(ADR-0012)에 속하는 집합만 복원할 수 있고 그 밖의 어떤 집합도 정보이론적으로 아무것도 얻지 못한다(VC-031). v0.1은 검증 가능 비밀분산(VSS)을 쓰지 않으며 불일치는 §11.3에서 탐지·국소화한다.

### 9.3 share 패키지
`SharePackage`(스키마 0x000B), `sealed`: `election_id`, `box_id`, `commitments`(대응 기록의 커밋먼트; 기록 해시는 이 패키지의 해시에 의존하므로 넣지 않는다), 구성원 항목 `Array<{trustee_id, chamber: u8, transport: u8, pad_id: u32, pad_index: u64, ciphertext: Bytes<4096>, tag: [u8; 16]}, 64>`(`ENCODING.md` §8.10). 패키지에는 서명이 없다: 서명된 투함 기록의 `share_package_hash`가 패키지를 결속하고 기록 자체는 기록 서명과 `BatchAttest`로 보호된다(ADR-0014의 표당 서명 크기 원칙).

구성원 i(챔버 c)의 평문 = `MemberShare`(스키마 0x0015, `ENCODING.md` §8.11): `(share of each secret) ‖ has_module ‖ cid_c ‖ lab_c ‖ 모듈 c의 tag_{c,i}` (길이는 선거 구성으로 고정). `transport = 0`이면 ciphertext는 평문 ⊕ 패드 조각, `tag`는 평문 전체에 대한 Poly1305 태그(키는 패드에서 §9.4.3 규칙으로 추가로 꺼낸 32바이트). `transport = 1`이면 KEM 대체 경로(§9.6).

패키지의 해시가 서명된 공개 기록에 있으므로 패키지를 바꿔치기하면 공개 기록과 어긋난다(VC-032).

### 9.4 일회용 패드 전송 프로토콜

#### 9.4.1 목표와 비목표
목표: 투표소에서 신뢰기관 구성원까지 share의 기밀성이 계산 가정 없이(정보이론적으로) 성립한다. 비목표: 패드로 무결성을 보장하지 않는다(무결성은 서명과 일회성 MAC이 맡는다). 모듈 공급 챔버와 구성원 자신에 대한 기밀성은 목표가 아니다.

#### 9.4.2 패드 생성과 복사
- 챔버 c의 모듈은 제작 후 **발급 의식**에서 자기 챔버 구성원 i마다 패드 `P_{c,i}`를 모듈 내부 하드웨어 난수원으로 생성한다. 길이 `L = N_max · b`, `N_max`는 해당 장치의 최대 표 수의 2배 이상, `b`는 기록당 소비 바이트(§9.4.3).
- 구성원 i는 의식 현장에서 직접 연결된 유선 링크로 자기 패드의 사본을 자기 보관 장치(HSM 관리 저장소)에 받는다. 패드 또는 그 해시는 어디에도 게시하지 않는다(VC-033). 사본 일치는 사용 시 태그 검증으로 확인된다.
- 의식은 독립검증위원회가 주관하고 참관인이 입회하며 `ModuleProvisioned` 이벤트(모듈 ID, 장치 ID, 챔버, 구성원 수, 패드 길이, 의식 참석자 서명)를 수록한다. 패드 값이나 해시는 이벤트에 없다.
- 모듈은 봉인되고 `CustodyHandoff` 사슬을 따라 투표소에 도착한다. 봉인 번호와 모듈 ID는 genesis의 장치 항목과 일치해야 하며, 투표소 개시 시 사무원과 참관인이 확인해 `BoxOpened` 이벤트에 서명한다.

#### 9.4.3 소비 규칙
- 기록당 구성원당 소비 바이트 `b = share 평문 길이 + 32(MAC 키) + 32(모듈 태그 키)`. 기록 `n`(모듈 카운터 값)은 패드 구간 `[n·b, (n+1)·b)`를 쓴다. `pad_index = n·b`.
- 모듈은 구간을 한 번만 내주며, 내준 즉시 그 구간을 0으로 덮어쓴다(VC-034). 같은 인덱스의 재요청은 거부한다. 따라서 선거 후 압수된 모듈에는 사용된 패드가 남아 있지 않다.
- XOR는 모듈 안에서 수행한다. 커밋먼트 유닛은 구성원 i의 평문을 모듈 c에 보내고 암호문과 태그를 받는다. 모듈 c는 자기 챔버 구성원의 share만 본다. 이는 챔버 c가 자기 구성원으로부터 어차피 얻을 수 있는 정보다.
- 커밋먼트 유닛은 패드를 보지 않는다. 선관위가 운영하는 어떤 부품에도 패드가 존재하지 않는다(VC-035).

#### 9.4.4 수신과 복호
- 패키지는 투표소에서 중앙으로 보내는 일반 네트워크 경로(저장 후 전달)를 타며, 경로상의 누구도 평문을 얻을 수 없다.
- 구성원 i는 `(pad_id, pad_index)`로 자기 사본의 구간을 찾아 복호하고 태그를 검증하며, 챔버 c의 모듈 태그 `tag_{c,i}`를 보관한다(§9.5의 검사에 쓴다). 성공하면 HSM 관리 저장소에 share를 기록하고 사용한 사본 구간을 0으로 덮어쓴다.
- 구성원은 투표함별로 `ShareReceipt` 이벤트(공개: `box_id`, 수신 기록 수, 수신 기록 해시 집합의 root, 구성원 서명)를 수록한다. 누구나 모든 기록이 모든 구성원에게 도달했는지 대조한다(VC-036). 누락은 커밋먼트 유닛의 봉인 저널에서 재전송한다.

#### 9.4.5 고갈과 대체
- 모듈의 패드가 소진되면 `EXHAUSTED`를 돌려주고, 커밋먼트 유닛은 해당 구성원에 대해 §9.6의 KEM 대체 경로를 쓰며 `transport_flags` 비트0을 세운다. 공개 기록에서 누구나 대체 비율을 본다.
- 한 투표함에서 대체 비율이 1%를 넘으면 발급 의식의 용량 산정이 잘못된 것이므로 `HOLD_REVIEW`로 조사한다.

#### 9.4.6 파기
- 파기 의식(§15)에서 구성원은 패드 사본과 share를 파기하고 모듈은 전부 0으로 덮어쓴 뒤 물리 파쇄한다. `DestructionAttest` 이벤트에 서명한다.

#### 9.4.7 보안 논증과 잔여 위험
- 전송 구간: 평문 ⊕ 균등 패드는 완전 비밀이다. 공격자가 전체 트래픽을 영구 보관해도 얻는 것이 없다.
- 모듈 공급 챔버가 자기 모듈의 패드를 보관하면 그 챔버 구성원의 share를 얻는다. 이는 그 챔버가 공모하는 경우와 같으며 접근구조가 여전히 X와 Y를 요구한다.
- 구성원의 패드 사본 유출은 그 구성원의 share 유출과 같다. 챔버 내부 임계치 `k_c`가 완충한다.
- 모듈 난수원이 편향되면 그 챔버의 패드가 예측 가능해진다. 발급 의식에서 통계 검사를 하되 완전한 보장은 아니다. 중립 모듈 위임은 J·A·C의 기밀을 한 공급자에 모으므로 공개 표기한다.
- 사용 전 모듈 압수는 그 장치의 미래 패드를 노출하지만 과거 기록은 소거되어 있다. 압수는 봉인과 인계 사슬에서 드러난다.
- 모듈 자체가 난수를 보관하면 그 챔버는 자기 난수 기여만 알 뿐 `r = Σ_c r_c`를 모르므로 선택을 복원할 수 없다. X와 Y 두 모듈이 함께 보관하고 J·A·C 기여를 더 얻어야 하며, 이는 접근구조 위반 공모와 같다.

### 9.5 은닉 채널 검사
표본 기록(§12의 RLA 표본과 장치당 공개 난수 2% 표본)에 대해 정족수는 `r_{c,j}`와 `cid_c`, `lab_c`만 복원하고(`cast_id`와 선택은 복원하지 않음), 챔버 c의 구성원이 보관한 모듈 태그 `tag_{c,i}`를 자기 패드 키로 검증한다. 태그가 맞지 않으면 커밋먼트 유닛이 모듈 난수를 쓰지 않은 것이므로 그 장치의 전 기록을 전수 대조한다(VC-022). `r_c`만 복원하면 `cast_id`가 숨겨진 채 남으므로 선택은 계산적으로 드러나지 않는다(§16).

### 9.6 KEM 대체 경로
`transport = 1`: ciphertext = HPKE 방식 봉인. KEM은 ML-KEM-1024와 X25519의 결합, AEAD는 ChaCha20-Poly1305(RFC 8439), 수신자 공개키는 genesis의 구성원 키(`mlkem1024_ek: [u8; 1568] ‖ x25519: [u8; 32]`).
- 키 유도: `key = SHA3-512("ityv:kem:v1" ‖ 0x00 ‖ ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ ct_x25519 ‖ pk_x25519)[0..32]`. 두 공유 비밀과 두 암호문, 수신자의 X25519 공개키를 모두 넣으므로 한 KEM이 깨져도 키가 드러나지 않고, 암호문이나 수신자 키를 바꿔치기하면 다른 키가 나온다(X25519의 날 공유 비밀은 암호문도 공개키도 결속하지 않으므로 X-Wing 결합기와 같이 명시적으로 넣는다; ML-KEM의 공유 비밀은 FIPS 203 구성상 자기 암호문과 캡슐화 키를 이미 결속한다). X25519는 비기여(저위수) 결과를, ML-KEM은 모듈러스 범위를 벗어난 캡슐화 키를 거부한다.
- 봉인: 캡슐화 한 번에 메시지 하나. 유도된 키는 정확히 한 메시지만 봉인하므로 논스는 96비트 0으로 고정한다(새 메시지는 새 캡슐화). 연관 데이터 `aad` = `election_id ‖ box_id ‖ record_hash ‖ trustee_id ‖ transport ‖ pad_id ‖ pad_index`의 정규 인코딩(§9.3 항목의 공개 필드). `transport = 1`이면 `pad_id = 0`, `pad_index = 0`.
- 항목의 `ciphertext` = `ct_mlkem: [u8; 1568] ‖ ct_x25519: [u8; 32] ‖ AEAD 암호문(평문과 같은 길이)`, `tag` = Poly1305 태그 16바이트.
이 경로는 전송 녹취 후 두 KEM이 모두 깨지고 임계치 share가 복원되는 경우에만 노출되며, 사용 사실은 공개 기록에 남는다.

## 10. 투표함 마감과 보관

### 10.1 개시
`BoxOpened` 이벤트: `box_id`, 장치·모듈 ID와 봉인 번호 확인 결과, 초기 수량 0, 사무원 2인과 서로 다른 조직 참관인 2인의 서명. genesis에 없는 장치·모듈이면 개시할 수 없다(VC-037).

### 10.2 마감
마감 전에 투표소는 `IssuanceCount` 이벤트(공개: `station_id`, 교부 수, 훼손 수, 반납 수, 미사용 수, 사무원 2·참관인 2 서명)를 수록한다. 원본 회계표는 `restricted`다.

`BoxCloseBody`(스키마 0x0007; 이벤트 `BoxClose` 0x001A = 본문 바이트 + 장치·사무원·참관인 서명, `ENCODING.md` §8.16·§8.17), 공개: `election_id`, `box_id`, `paper_count`(사무원 2인이 독립 계수한 실물 투표지 수), `record_count`, `attested_count`, `no_record_count`(비상 투입구로 받은 수), `challenge_count`, `quarantine_count`, `record_set_root`(기록 해시 정렬 집합의 Merkle root), `journal_head: Hash512`, `seal_digest: Hash512`(적용된 봉인 번호 목록의 해시), `module_counters: Array<{module_id, final_counter}, 6>`, `open_batches: u8`, 장치 서명(장치가 살아 있을 때), 사무원 서명 2, 서로 다른 조직 참관인 서명 2 이상. 장치 서명이 없는 마감은 `BoxCloseManual`로 수록되며 자동으로 `HOLD_REVIEW`다. 뒤에 장치가 살아나 `LateBoxClose`(장치 서명 포함)를 수록하면 해소될 수 있다.

마감 불변식(VC-038): `paper_count == record_count + no_record_count`, `record_count == attested_count + (열린 배치의 기록 수)`, 격리 봉투 실물 수 `== challenge_count + quarantine_count`, 각 모듈의 `final_counter == record_count + challenge_count + quarantine_count`(틈 없음), `open_batches == 0`(아니면 `HOLD_REVIEW`이며 늦은 마감 대상), 관외면 봉투 수 `== record_count`, `no_record_count > 0`이면 대응하는 `FallbackDeclared`가 존재. 하나라도 어긋나면 마감은 수록되되 상태는 `HOLD_REVIEW`이며 참관인 진술 해시를 첨부한다. 마감 후 그 `box_id`로 새 기록은 수록되지 않는다(VC-039).

개표소에서 각인 판독기는 투표함별로 각인 없는 투표지 수와 중복 `cast_id` 수만 `ImprintAudit` 이벤트(공개)로 남기고, `cast_id` 목록 자체는 `restricted`다. 모듈 봉인 훼손이나 모듈 오동작은 `ModuleIncident` 이벤트(공개: 모듈 ID, 사유 코드, 참관인 2 서명)로 남기고 해당 장치를 교체한다.

### 10.3 인계 사슬
`CustodyHandoff`(스키마 0x0008): `election_id`, `box_id` 또는 용기 ID, `index`(1부터), `from_actor`, `to_actor`, `previous_handoff_hash`, `seal_digest`, `paper_count`, `time_bucket`, 송신자·수신자 서명. 송신자와 수신자는 서로 다른 조직이어야 하고 genesis의 `custody_routes`가 정한 순서를 따라야 한다(VC-040). 봉인 번호 변경은 사유 코드가 있는 `SealChange` 이벤트를 요구하며 그 이벤트가 없는 봉인 불일치는 `HOLD_REVIEW`다.

### 10.4 영상 앵커
`VideoAnchor` 이벤트(공개): 카메라 ID, `time_bucket`, 영상 구간 해시. 영상 원본과 대응표는 `restricted`다. 구간 누락은 `VideoGap` 이벤트로 남긴다.

### 10.5 우편 회차와 카세트
`PostalBatch` 이벤트: 발송 선관위, 회차, 발송 봉투 수(발송지 서명), 우체국 인수 수(우정 서명), 도착 수(수령지 서명), 보류 수. 세 수가 같지 않으면 `HOLD_POSTAL_RECONCILIATION`. `CassetteOpened`/`CassetteSealed` 이벤트로 일방향 접수 용기를 추적한다.

### 10.6 관외 수령 대조
1. 수령 선관위는 봉투를 열지 않고 라벨을 읽어 `ReceiptMark`(스키마 0x000C)를 수록한다. 공개부: 수령 선관위 ID, 회차, 라벨 수, 라벨 집합의 Merkle root. 라벨 목록 자체는 `restricted`이며 신뢰기관에 전달된다.
2. 집계 전 **수령 대조 의식**에서 정족수는 관외 기록의 `env_label` share만 복원해(선택·`cast_id`는 복원하지 않음) 수령 라벨 집합과 대조하고, 기록 해시별 상태 `RECEIVED` 또는 `CAST_NOT_RECEIVED`를 `ReceiptResolution` 이벤트로 공개한다. 복원된 라벨은 의식 종료 시 소거한다(VC-041).
3. 개봉은 회차 단위로 하며 봉투와 투표지를 분리해 섞은 뒤에만 투표지를 다룬다. (봉투, 투표지) 쌍을 기록하는 행위는 금지되며 참관인이 확인한다.

## 11. 집계

### 11.1 범위
`TallyScope` 이벤트(공개): 투표양식별로 집계에 포함되는 기록 해시 집합의 root와 수, 제외 목록(`CHALLENGED_SPOILED`, `QUARANTINED`, `CAST_NOT_RECEIVED`, `SHARE_MISSING`, `UNATTESTED`, `TEST_BALLOT`)을 기록 해시로 명시. `no_record_count`는 기록이 없으므로 수량으로만 공개한다. 제외는 사유 코드와 근거 이벤트 해시를 가진다(VC-042).

### 11.2 합계 열기
투표양식 s, 청크 j에 대해 `C_total,j = Σ_i C_{i,j}`(포함 기록 전체). 정족수는 구성원 share의 합을 모아 `R_j = Σ r_{i,j}`와 `S = Σ cast_id_i`를 복원하고 `AggregateOpening` 이벤트(공개)를 수록한다: `ballot_style_id`, `j`, `T_j`, `R_j`, `S`, 참여 구성원 목록, 각 참여 구성원의 서명. 누구나 `C_total,j == T_j·G_val + S·G_id + R_j·H`를 확인하고 `T_j`의 26비트 자릿수를 읽어 인덱스별 표 수를 얻는다(VC-043). `S`는 무작위 값들의 합이며 아무것도 드러내지 않는다.

### 11.3 불일치 처리
확인이 실패하면 어떤 기록의 share가 커밋먼트와 맞지 않는 것이다. 정족수는 투표함 단위 부분합으로 이분 탐색해 결함 투표함을 찾고, 그 투표함 안에서는 기록 단위로 연다. 이때 열린 기록의 선택은 정족수에게 드러나므로 `HOLD_REVIEW` 사건으로 기록하고 열린 기록 수를 공개한다. 결함 장치는 전수 대조 대상이다(VC-044).

### 11.4 법적 지위
암호 집계는 검증 보조수단이다. 법적 결과는 종이 계수이며, 둘이 다르면 §12·§13의 절차로 간다.

## 12. 감사

### 12.1 시드
`AuditSeed`(스키마 0x000D) 의식: 먼저 `AuditManifestFreeze` 이벤트로 표본 프레임(포함 기록 집합 root)과 추출 규칙(위험 한도, 표본 크기 공식, 확대 규칙)을 동결한다. 그 뒤 정당 참관 아래 주사위 의식을 공개 기록하고, 사전에 지정한 공개 분산 난수 비콘의 회차 값을 가져오며, 최종 체크포인트 해시와 함께 `seed = SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice_transcript_hash ‖ beacon_value ‖ final_checkpoint_hash)`로 만든다. 세 입력과 결과를 이벤트에 수록한다(VC-045).

### 12.2 표본
표본은 `seed`로 초기화한 SHAKE256 스트림에서 포함 기록 집합의 정렬 인덱스를 균등 추출한다(거부 샘플링으로 편향 제거). 누구나 재계산한다(VC-046). 표본 크기와 확대 규칙은 투표양식별 표차와 위험 한도에서 정해지며 `policy_hash` 문서가 공식을 고정한다.

### 12.3 기록 열기와 종이 대조
정족수는 표본 기록의 `(option_index, cast_id, r_j)`를 복원해 `SampleOpening` 이벤트(공개)를 수록한다. 누구나 커밋먼트를 재구성해 확인한다(VC-047). 감사인은 해당 투표함의 투표지에서 각인된 `cast_id`를 찾아 기표를 사람이 판정하고 `SampleComparison` 이벤트(감사인 2 조직 서명)로 일치·불일치를 기록한다. 열린 기록의 선택은 공개되지만 유권자와는 어떤 기록으로도 연결되지 않는다.

### 12.4 확대
불일치 수가 규칙의 임계를 넘으면 표본을 확대하고, 다시 넘으면 그 투표양식 전체를 수검표한다. 수검표 결과가 법적 결과다. 기록과 종이의 불일치 패턴(예: 특정 장치, 특정 보관 구간)은 `AuditFinding` 이벤트로 남겨 법적 절차의 증거가 된다.

### 12.5 전수 대조
`ScannerQuarantine` 또는 §9.5·§11.3에서 지목된 장치의 기록은 전부 열어 종이와 대조한다. 이때도 유권자와의 연결은 생기지 않는다.

## 13. 분쟁

`DisputeEvent`(스키마 0x000E), 공개: `election_id`, `dispute_type`(1 INCLUSION_MISSING, 2 COUNT_MISMATCH, 3 CUSTODY, 4 CHALLENGE_FAIL, 5 POSTAL, 6 OTHER), 대상(`box_id`, 선택적 `record_hash`), 증거 해시(슬립 이미지 등, 원본은 `restricted`), 접수 서명(선관위와 독립검증위원회 모두), 상태(OPEN, INVESTIGATING, RESOLVED_TECHNICAL, REFERRED_LEGAL), 처리 결과 해시.

포함 분쟁 절차(VC-048):
1. 슬립의 `device_sig`를 genesis의 장치 키로 검증한다. 실패하면 위조로 기각하고 그 사실을 이벤트에 남긴다.
2. 성공했는데 추적코드가 게시판에 없으면 시스템 장애다. 해당 투표함은 `HOLD_REVIEW`, 봉인 저널과 `ShareReceipt`, 마감 수량을 대조하는 조사를 연다.
3. "내 표 내용이 다르다"는 주장은 접수 대상이 아니다. 접수 화면과 문서는 그 이유(영수증 무증명성)를 설명한다.
4. 법적 판단은 `LegalDecisionRef`(스키마 0x000F: 결정 기관 ID, 결정문 해시, 대상 분쟁 해시, 기관 서명)로만 장부에 들어온다. 어떤 기계 상태도 `LEGAL_CERTIFIED`를 만들지 않는다(VC-049).

## 14. 공개 검증기

검증기는 호출자가 제공한 genesis 핀과 증인 명부 핀만 신뢰하고 다음을 순서대로 수행한다.
1. genesis 검증: 핀 일치, 선관위·위원회 서명, 증인 정족수·다양성, 임명 이벤트 참조(VC-005, VC-006, VC-009, VC-014).
2. 체크포인트 사슬: 각 체크포인트의 서명 정족수, `previous_checkpoint_hash`, `tree_size` 단조, 일관성 증명(VC-011..014).
3. 프레임과 이벤트: 모든 프레임의 해시 사슬, 이벤트 해시 일치, 스키마 정규성.
4. 투표함: `BoxOpened`/`BoxClose` 완전성(genesis의 모든 예상 투표함에 마감이 정확히 하나), 마감 불변식, 모듈 카운터 틈 없음, 인계 사슬 완전성(VC-037..040).
5. 투함 기록: 모든 기록의 정형성 증명, 기록 서명, `BatchAttest` 포함과 카운터 연속성, 기록 집합 root 일치, `UNATTESTED` 목록(VC-025..027, VC-053, VC-057).
6. 참여 장부: 가명 중복 없음, 수량 등식(VC-018).
7. 집계: `TallyScope` 제외 근거, `AggregateOpening` 등식과 자릿수 범위(VC-042..043).
8. 감사: 시드 재계산, 표본 재계산, `SampleOpening` 재구성(VC-045..047).
9. 분쟁: 미해결 분쟁 목록.

출력 상태는 상태 어휘만 쓴다. 1–5가 통과하면 `LOG_CONSISTENT`, 4의 완전성까지 통과하면 `SOURCE_COMPLETENESS_CHECKED`, 7까지 통과하면 `CRYPTO_TALLY_VERIFIED`, 8의 `SampleComparison`이 규칙상 종료되면 `PAPER_AUDITED`. 미해결 분쟁이나 어떤 실패도 `HOLD_REVIEW`. `LEGAL_CERTIFIED`는 `LegalDecisionRef`가 있을 때 그 참조를 표시할 뿐 검증기가 판정하지 않는다(VC-049). 상태는 서로 바꿔 표시할 수 없다(VC-050).

## 15. 파기와 보존

- 파기 의식은 인증과 이의 기간(법령 부속서 13번의 기한) 종료 후 독립검증위원회 주관으로 공개 진행한다. 구성원은 share·패드 사본·선거별 비밀키를 파기하고, 모듈은 0으로 덮어쓴 뒤 파쇄하며, 커밋먼트 유닛과 카운터·가명 유닛의 봉인 저널을 파기한다. `DestructionAttest` 이벤트(각 구성원·챔버 서명, 파기 항목 목록)를 수록한다(VC-051).
- 보존: 게시판 전체, genesis, 검증기 소스와 빌드 해시, `restricted` 보관 기록은 법령이 정한 기간 보존한다. 공개 게시판은 커밋먼트와 증명만 담으므로 영구 보존해도 비밀을 해치지 않는다.
- 알고리즘 전환: 보존 중 서명 알고리즘이 약해지면 최종 체크포인트에 새 알고리즘의 재서명을 추가하되 원 서명을 지우지 않는다. 커밋먼트는 정보이론적으로 숨겨져 있어 전환이 필요 없다.

## 16. 보안 논증 요약

| 주장 | 메커니즘 | 가정 | 잔여 위험 |
|---|---|---|---|
| 게시판은 영원히 선택을 드러내지 않는다 | Pedersen 커밋먼트(무조건적 숨김), 완전 증인 구별불가 OR 증명, 기록에 시간·순번 없음, `r`을 결정하는 어떤 값(해시 포함)도 공개하지 않음 | 없음(정보이론적) | 없음. 단, 공개된 `ChallengeOpening`과 `SampleOpening`은 폐기된 표와 감사 표본의 선택을 드러내며 유권자와 연결되지 않는다 |
| 선관위 단독으로 선택을 열 수 없다 | share는 챔버 접근구조로 분산, 패드는 선관위 부품에 없음, 가명 키는 모듈에 | X·Y 모듈과 챔버가 공모하지 않음 | 전원 공모(T4) |
| 집계가 포함 기록과 일치한다 | 준동형 합계와 공개 열기 등식 | DLOG(선거 당시) | 양자 시점 이후 위조는 종이와 감사 기록이 이미 확정된 뒤라 무의미 |
| 기록은 투입 시점의 해석과 같다 | 투입 전 검증, 모듈 카운터, 종이 비교 감사 | 검증 요구가 예측 불가 | 검증이 전혀 없는 투표소에서의 소수 조작은 감사 표본이 잡음 |
| 같은 수량 표갈이가 탐지된다 | 투함 시점 커밋먼트와 기록 우선 비교 감사 | 종이 보관 사슬이 감사 전까지 유지 | 종이와 기록을 함께 바꾸려면 정족수 공모와 각인 위조가 필요 |
| 추적코드는 강요에 쓰일 수 없다 | 추적코드는 기록 해시, 기록은 선택을 숨김, 봉투 라벨·투함 ID는 비공개 | §10.6의 분리·혼합 절차 준수 | 개표 현장에서 (봉투, 투표지) 쌍을 몰래 기록하는 내부자 |
| 커밋먼트 유닛의 은닉 채널이 없다 | 난수는 모듈 합, 모듈이 배치마다 카운터 연속성을 확인한 뒤 서명, 표본 태그 검사 | 모듈 두 챔버가 공모하지 않음 | 해석 유닛의 BLANK/UNREADABLE 분류 편향은 감사로만 탐지 |
| 배치 마감 전 창의 피해는 유계다 | 기록마다 Ed25519, 배치마다 하이브리드, 저널 fsync, 늦은 마감, `UNATTESTED` 공개 | 고전 공격자는 창을 이용할 수 없음 | 양자 공격자가 15분 안에 개입해도 잃는 것은 최대 64건의 양자내성 증명뿐이며 표·비밀·법적 결과는 무관(`docs/spec/FAILURE_CASES.md`) |
| 1인 1표가 외부에서 검증된다 | 가명 다중집합 공개, 참관인 공동 서명 카운터 | 서로 다른 블록의 참관인이 함께 공모하지 않음 | 신원 확인 유닛의 본인 확인 품질 |
| 누락된 투표함이 없다 | genesis 예상 투표함과 마감 1:1 | genesis 작성의 정직성(위원회·증인 서명) | genesis 자체가 틀리면 실물 재고 감사만이 잡음 |

## 17. 수집 프로필과 단계별 동작

| 단계 | 활성 요소 | 비활성 |
|---|---|---|
| 0 | §5 장부·게시판·체크포인트, §6 수량 부분(가명 없이 참관인 서명 카운터만), §10 보관·우편·영상 | §7–§9, §11–§13 |
| 1 | + 신뢰기관 DKG·임명·의식, 모듈 발급 의식(패드) | §7 기록 생성 |
| 2 | + §7 기록(슬립 제외), §8 검증, §9 share, §10.6 수령 대조, §11 집계, §12 감사, §6 가명 | §7.7 슬립 |
| 3 | + §7.7 슬립, §13 포함 분쟁 | — |

`RECEIPT_SCAN` 프로필(거소·선상): 투표지는 수령 선관위의 스캐너에서 `CastRecord`를 만든다. 유권자는 슬립을 받지 못하고 투입 전 검증도 없다. 기록의 `ballot_style_id`와 `box_id`는 수령 선관위의 전용 투표함을 가리키며, 검증기는 이 프로필의 기록 수를 별도로 표시하고 상태 어휘에 `RECEIPT_SCAN` 범위를 명시한다.

## 부록 A. 이벤트 사전

| 이벤트 | 스키마 | 서명자 | 등급 | 절 |
|---|---|---|---|---|
| `Genesis`, `GenesisAmendment` | 0x0002 | 선관위, 위원회, 증인 정족수 | public | §4 |
| `LegalAuthorizationBody` | 0x0003 | 선관위, 위원회 | public | §4.4 |
| `Appointment` | — | 추천 기관 | public | §4.5 |
| `LedgerFrame` | 0x0001 | 장부 운영자 | public | §5.1 |
| `SignedCheckpoint`(본문 `CheckpointBody` 0x0004 포함) | 0x0010 | 증인 정족수 | public | §5.4 |
| `PublicationBreach` | — | 위원회 | public | §5.5 |
| `RollFreeze`, `RollAmendment` | — | 선관위, 위원회 | public | §6.1 |
| `CheckinCounter` | 0x0009 | 카운터·가명 유닛, 모듈 X·Y | public | §6.3 |
| `ObserverCountAttest` | — | 참관인 2(다른 조직) | public | §6.3 |
| `ScanCountAttest`(본문 0x0013) | 0x001B | 참관인 2(다른 조직) | public | §7.8 |
| `ModuleProvisioned` | — | 위원회, 챔버, 참관인 | public | §9.4.2 |
| `BoxOpened` | — | 장치, 사무원 2, 참관인 2 | public | §10.1 |
| `IssuanceCount` | — | 사무원 2, 참관인 2 | public | §10.2 |
| `ImprintAudit` | — | 개표소, 참관인 2 | public | §10.2 |
| `ModuleIncident` | — | 사무원, 참관인 2 | public | §10.2 |
| `CastRecord`(본문 `CastRecordBody` 0x0005) | 0x0016 | 장치·모듈 Ed25519 기록 서명(양자내성은 BatchAttest) | public | §7.6 |
| `BatchAttest`(본문 0x0012), `LateBatchClose` | 0x0017, — | 커밋먼트 유닛, 모듈들 (+입회자) | public | §7.2.1 |
| `JournalMismatch` | — | 커밋먼트 유닛, 참관인 2 | public | §7.2.1 |
| `FallbackDeclared`, `FallbackEnded` | — | 사무원 2, 참관인 2 | public | §7.3 |
| `ImprintFailure` | — | 커밋먼트 유닛, 참관인 | public | §7.3 |
| `SharePackage` | 0x000B | 커밋먼트 유닛 | sealed | §9.3 |
| `ShareReceipt` | — | 신뢰기관 구성원 | public | §9.4.4 |
| `ChallengeOpening`(본문 0x0006) | 0x0018 | 커밋먼트 유닛 | public | §8 |
| `ScannerQuarantine` | — | 참관인 2, 사무원 | public | §8 |
| `BoxClose`, `BoxCloseManual`, `LateBoxClose`(본문 0x0007) | 0x001A | 장치(가능할 때), 사무원 2, 참관인 2 | public | §10.2 |
| `CustodyHandoff`, `SealChange` | 0x0008 | 송신자, 수신자 | public | §10.3 |
| `VideoAnchor`, `VideoGap` | — | 보관 책임자 | public(대응표 restricted) | §10.4 |
| `PostalBatch`, `CassetteOpened`, `CassetteSealed` | — | 발송·우정·수령 | public | §10.5 |
| `ReceiptMark` | 0x000C | 수령 선관위, 참관인 2 | public(라벨 restricted) | §10.6 |
| `ReceiptResolution` | — | 정족수 | public | §10.6 |
| `TallyScope`, `AggregateOpening` | — | 정족수 | public | §11 |
| `AuditManifestFreeze`, `AuditSeed` | 0x000D | 위원회, 참관인 | public | §12.1 |
| `SampleOpening`, `SampleComparison`, `AuditFinding` | — | 정족수 / 감사인 2 조직 | public | §12.3 |
| `DisputeEvent` | 0x000E | 선관위, 위원회 | public(증거 restricted) | §13 |
| `LegalDecisionRef` | 0x000F | 법정 권한 기관 | public | §13 |
| `DestructionAttest` | — | 구성원, 챔버, 위원회 | public | §15 |

"—"로 표시된 스키마 ID는 v0.2에서 `ENCODING.md` §6 등록부에 추가한다.

## 부록 B. 서명 purpose

`genesis`, `legal-auth`, `appointment`, `checkpoint`, `checkpoint-archive`(SLH-DSA 포함), `checkin`, `observer-count`, `cast-record`, `slip`, `challenge`, `box-open`, `box-close`, `handoff`, `seal-change`, `video-anchor`, `postal-batch`, `receipt-mark`, `receipt-resolution`, `tally-scope`, `aggregate-opening`, `audit-freeze`, `audit-seed`, `sample-opening`, `sample-comparison`, `dispute`, `legal-decision`, `destruction`, `share-receipt`, `module-provisioned`, `scanner-quarantine`, `publication-breach`, `scan-count`, `batch-attest`, `module-record`, `late-batch-close`, `late-box-close`, `fallback`, `issuance-count`, `imprint-audit`, `module-incident`.

## 부록 C. 검증 조건 목록

VC-001 투함 기록에 시간·순번·유권자 정보 없음 · VC-002 하이브리드 서명 둘 다 검증 · VC-003 알고리즘 협상 없음 · VC-004 미등록 키 무효 · VC-005 genesis 핀 일치 · VC-006 법적 승인 두 서명 · VC-007 승인 범위 없이 해당 객체 생성 불가 · VC-008 범위 전제 조건 · VC-009 임명 이벤트 참조 · VC-010 찢어진 꼬리 격리 · VC-011 Merkle 증명 알고리즘 · VC-012 증인 서명 전 확인 사항 · VC-013 같은 seq 이중 서명 금지 · VC-014 정족수·다양성 · VC-015 `voter_id` 소거 · VC-016 참관인 공동 서명 · VC-017 가명은 두 챔버 필요 · VC-018 참여 장부 공개 검증 · VC-019 가명·신원과 투함 ID·추적코드 분리 · VC-020 커밋먼트 유닛 소거 · VC-021 카운터 틈 공개 · VC-022 모듈 태그 검사 · VC-023 각인 실패 격리 · VC-024 자릿수 상한 · VC-025 OR 증명 검증 · VC-026 canonical 스칼라·점 · VC-027 투표함 기록은 정렬 집합으로만 공개 · VC-028 검증 공개값 재구성 · VC-029 폐기 봉투 수 일치 · VC-030 검증 실패 장치 격리·전수 대조 · VC-031 접근구조 밖 집합은 정보 없음 · VC-032 패키지 해시 결속 · VC-033 패드·해시 미게시 · VC-034 패드 구간 1회 사용·소거 · VC-035 선관위 부품에 패드 없음 · VC-036 share 수신 대조 · VC-037 미등록 장치 개시 불가 · VC-038 마감 불변식 · VC-039 마감 후 기록 금지 · VC-040 인계 조직 상이·경로 준수 · VC-041 라벨 복원 소거 · VC-042 제외 근거 · VC-043 합계 열기 등식 · VC-044 불일치 국소화 · VC-045 시드 구성 · VC-046 표본 재계산 · VC-047 표본 열기 재구성 · VC-048 포함 분쟁 절차 · VC-049 `LEGAL_CERTIFIED` 기계 생성 금지 · VC-050 상태 혼용 금지 · VC-051 파기 증명 · VC-052 스캔 카운터 참관 앵커와 마감의 단조 연속 · VC-053 모든 기록은 정확히 하나의 BatchAttest에 포함되고 카운터 구간이 틈 없이 이어짐 · VC-054 저널 영속화 전 각인·투입 금지 · VC-055 시험용 투표양식의 집계·참여 장부 제외 · VC-056 배치 서명 전 저널·메모리 대조 · VC-057 `UNATTESTED` 분류·제외·늦은 마감 복귀.
