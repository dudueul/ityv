# ityv 용어집 / Glossary

> English summary: Canonical vocabulary for the ityv election evidence and verification ecosystem. Korean is the official language of the documents; identifiers in code are English. Every other document must use these terms exactly.

| 한국어 | English | 식별자 | 정의 |
|---|---|---|---|
| ityv | ityv | `ityv` | 본 프로젝트. 손기표 종이 원본과 끝단 간 검증(E2E)을 결합한 한국 선거 증거·검증 생태계. K-Ballot(연구물, NO-GO)은 계보로만 인용한다. |
| 주 불변식 | master invariant | — | 시스템은 모든 표가 투표한 대로 집계되었음을 증명할 수 있어야 하며, 어떤 유권자가 어떤 선택을 했는지는 시스템 자신을 포함해 누구에게도, 기록이 존재하는 한 영원히 드러내지 않는다. |
| 증거 장부 | evidence ledger | `ledger` | 선거별 추가 전용 프레임 로그. 모든 서명 이벤트의 원본. UPDATE/DELETE 경로가 존재하지 않는다. |
| 공개 게시판 | public board | `board` | 장부 중 공개 등급 이벤트의 공표본. 증인 체크포인트로 고정된다. 양자컴퓨터 앞에서도 영원히 무해해야 한다. |
| 체크포인트 | checkpoint | `checkpoint` | 장부의 특정 길이에 대한 Merkle root, 이전 체크포인트 해시, 투표함 마감 root, 분쟁 root를 담은 객체(`CheckpointBody`). 증인단 정족수가 서명한다. |
| 서명된 체크포인트 | signed checkpoint | `SignedCheckpoint` | 체크포인트 본문 바이트와 증인 서명 묶음을 담은 장부 이벤트(스키마 0x0010). 모든 서명이 유효하고 정족수·다양성을 만족할 때만 유효하다. |
| 증인(단) | witness | `witness` | 체크포인트에 서명해 장부의 일관성을 보증하는 기관. 서명만 하며 비밀 자료를 갖지 않는다. |
| 신뢰기관 | trustee | `trustee` | 커밋먼트 여는 값의 share를 보유하는 기관. 챔버 접근구조로만 열 수 있다. |
| 챔버 | chamber | `chamber` | 신뢰기관의 묶음. 정당 챔버 P1…Pn(2 ≤ n ≤ 4), J(사법), A(학계·기술), C(시민), N(선관위). 열림 조건은 "정당 챔버 전부와 J·A·C·N 중 셋 이상"(ADR-0019). |
| 정당 챔버 | party chamber | `party_chamber` | 규모 기준을 넘은 정당마다 하나씩 두는 챔버 P1…Pn(2 ≤ n ≤ 4). genesis 시점에 국회 의석을 가진 정당 가운데 직전 국회의원선거의 비례대표 의석 배분 기준(득표율 3% 이상 또는 지역구 5석 이상)을 넘은 정당을 의석 순으로 넷까지 둔다. 모두 필수라 하나만 정직해도 비밀이 지켜진다. |
| 정당 명부 | party roster | `party_roster` | genesis에 고정되는 정당 챔버 목록. 챔버 코드, 정당 이름, 의석 수, 자격 근거 문서의 해시. 이후의 합당·해산은 챔버를 바꾸지 않는다(VC-067). |
| 독립검증위원회 | Independent Verification Committee | `ivc` | 신규 독립 법정기구. genesis와 법적 승인 객체의 공동 서명, 증인·신뢰기관 지정, 키 의식 주관, 분쟁 공동 접수, 감사 확대 명령, 소수의견을 포함한 보고서 공표. 결과를 바꿀 권한은 없다. |
| 미러 | mirror | `mirror` | 게시판 사본을 받아 검증하고 다시 공표하는 누구나. 신뢰 대상이 아니며 숨기거나 늦출 수만 있고 위조는 검증에서 드러난다(PROTOCOL §5.7). |
| 체크포인트 교환 | checkpoint gossip | — | 미러·검증자·유권자 앱이 자기가 본 최신 서명 체크포인트를 서로 주고받아 분기를 찾는 일. |
| 분기 증거 | split-view evidence | `SPLIT_VIEW` | 같은 순번의 다른 본문, 같은 크기의 다른 root, 성립하지 않는 일관성 증명을 보여 주는 서명된 체크포인트 둘. 운영자가 사람마다 다른 게시판을 보여 줬다는 자기 완결적 증거. |
| 체크포인트 지문 | checkpoint fingerprint | — | 체크포인트 해시 앞 20바이트를 Base32 32자로 적은 값. 관보·방송·신문에 공표해 사람이 읽고 대조한다. |
| 공개 검증자 | public verifier | `verifier` | 누구나 돌릴 수 있는 검증 프로그램과 그것을 운영하는 기관. 법으로 지정된 최소 3개 독립기관은 기한 내 결과 공표 의무를 진다. |
| 기준정보 | genesis | `genesis` | 선거 시작 전 고정되는 명부. 선거 ID, 정책 해시, 예상 투표함·장치·참관인·인계자·증인·신뢰기관 공개키, 보관 경로, 법적 승인 객체. 대역 외 핀으로 배포한다. |
| 법적 승인 객체 | legal authorization | `legal_authorization` | genesis 안의 객체. 승인 범위 집합, 조문 참조, 시행일, 선관위 서명, 독립검증위원회 서명. 모듈 활성화의 유일한 게이트. |
| 승인 범위 | authorization scope | `scope` | `PUBLIC_BOARD`, `TRUSTEE_BODY`, `BALLOT_MARK`, `CRYPTO_TALLY_AID`, `RLA`, `OBSERVER_ACCESS`, `DEPLOY_AUTH`, `STAGE_GATE`, `VOTER_CODE`. |
| 배포 프로필 | deployment profile | `L0`, `L1` | L0 증거 계층(현행법), L1 E2E 계층(법 개정 후). 한 코드베이스이며 게이트로만 구분된다. |
| 활성화 단계 | activation stage | `stage0`..`stage3` | 0 현행법, 1 신뢰기관 구성, 2 투표지 표식·암호 집계 보조·RLA, 3 유권자 검증코드. |
| 투함 스캐너 | casting scanner | `scanner` | 투표함 위의 장치. 해석 유닛(불신), 커밋먼트 유닛(검증), 챔버 모듈(챔버 공급)로 물리적으로 분할된다. |
| 해석 유닛 | interpretation unit | `interp` | 투표지 이미지를 해석해 선택 인덱스 몇 바이트를 커밋먼트 유닛에 넘긴다. 불신 대상. 단방향 링크로만 연결. |
| 커밋먼트 유닛 | commitment unit | `cunit` | `no_std` Rust 수백 줄. 커밋먼트, 정형성 증명, share, 장치 서명, 추적코드, 투함 ID 각인 명령을 만든다. 검증 사다리의 최상위 대상. |
| 챔버 모듈(봉인 모듈) | chamber module | `cmod` | 챔버가 공급하고 봉인한 물리 모듈. 정당 모듈 P1…Pn은 모두 필수이고, J·A·C는 자체 모듈 또는 독립검증위원회의 중립 모듈에 위임할 수 있으며, N(선관위)은 모듈이 없다. 기능: 난수 기여, 투함 ID·봉투 라벨 기여, 자기 챔버 구성원의 일회용 패드 보관과 XOR, 일회성 MAC 키 공급, 확인 장치용 가명 PRF, 카운터 서명. 발급 값을 보관하지 않는다. |
| 투함 기록 | cast record | `CastRecord` | 표 하나의 공개 기록. 본문(선거·투표함·투표양식·커밋먼트·정형성 증명·모듈 카운터·share 패키지 해시)과 기록 서명(장치·모듈의 Ed25519). 양자내성 서명은 64건 배치의 `BatchAttest`가 제공한다. 선택과 투함 ID는 커밋먼트 안에만 존재하며 시간과 순번은 없다. |
| 커밋먼트 | commitment | `commitment` | Ristretto255 위의 일반화 Pedersen 커밋먼트. 숨김은 무조건적, 결속은 계산적. |
| 투함 ID | cast id | `cast_id` | 투함 시 챔버 모듈들의 난수 기여를 해시해 만드는 192비트 값. 투표지에 각인되며 커밋먼트 안에만 존재하고 공개 기록에 노출하지 않는다. |
| 봉투 라벨 | envelope label | `env_label` | 관외·재외 전용. 챔버 모듈들의 기여를 해시해 만든 독립 무작위 24바이트 토큰을 봉투에 부착한다. 투함 ID나 추적코드에서 유도하지 않으므로 봉투와 투표지를 (라벨, 각인)으로 연결할 수 없다. 공개 기록에 노출하지 않고 share로만 전달하며, 수령 대조 의식에서 정족수가 라벨만 복원해 대조한다. |
| 추적코드 | tracking code | `tracking_code` | 투함 기록의 SHA3-512 해시. 서명된 슬립으로 유권자에게 인쇄한다. 포함 여부만 검증 가능하고 선택은 증명할 수 없다. |
| 코드 슬립 | code slip | `slip` | 추적코드, 투표소, 시간 구간과 하이브리드 서명이 인쇄된 종이. |
| 투입 전 검증 | pre-cast challenge | `challenge` | 유권자나 참관인이 투입 전에 요구. 스캐너가 난수를 공개하고 그 표는 폐기되며 새 표를 교부한다. |
| 여는 값 share | opening share | `share` | 커밋먼트 난수(모듈별 기여), 투함 ID, 봉투 라벨의 선형 비밀분산 조각. 챔버 접근구조로 분산되고 일회용 패드(기본) 또는 하이브리드 KEM(대체)으로 전송된다. |
| 집계 열기 | aggregate opening | — | 신뢰기관이 share를 합산해 합계 커밋먼트만 연다. 개별 표는 감사 표본 외에 열지 않는다. |
| 파기 의식 | destruction ceremony | — | 인증과 이의 기간 종료 후 share와 선거 키를 공개적으로 파기한다. |
| 확인 장치 | check-in device | `checkin` | 신원 확인 유닛(불신), 카운터·가명 유닛(검증), 정당 모듈 P1…Pn으로 분할된 장치. 모든 투표소에 둔다. |
| 참여 장부 | participation ledger | `participation` | 확인마다 서명된 카운터 이벤트와 가명. 교차 중복과 수량 검증용. 투표지 또는 투함 ID와 절대 연결하지 않는다. |
| 가명 | pseudonym | `pseudonym` | 모든 정당 모듈의 PRF 출력을 결합해 만든 유권자 식별 대체값. 정당 모듈이 하나라도 빠지면 계산할 수 없다. 선거 후 순서 없는 다중집합으로만 공개한다. |
| 상태 어휘 | status vocabulary | — | `UNVERIFIED`, `LOG_CONSISTENT`, `SOURCE_COMPLETENESS_CHECKED`, `CRYPTO_TALLY_VERIFIED`, `PAPER_AUDITED`, `HOLD_REVIEW`, `LEGAL_CERTIFIED`. 자동 상호 전환을 금지한다. |
| 투함 기록 상태 | cast record status | — | `CAST_COMMITTED`, `RECEIVED`, `RECEIVED_DAMAGED`(훼손 봉투로 수령), `RECEIVED_LATE`(기한 후 수령), `WRONG_DISTRICT`(다른 선거구 투표양식), `CAST_NOT_RECEIVED`, `CHALLENGED_SPOILED`, `QUARANTINED`, `UNATTESTED`(기록 서명은 유효하나 배치 증명 없음), `SHARE_MISSING`. |
| 수집 프로필 | capture profile | `IN_PERSON_SCAN`, `RECEIPT_SCAN` | 전자는 선거일·관내·관외·재외(투표 시점 커밋먼트), 후자는 거소·선상(수령 시점 스캔, 보장 수준이 낮음을 명시). |
| 보관 경로 | custody route | `route` | genesis에 고정된 인계 순서. 우편 회송(P1)과 현지 개표(P4)를 같은 코드로 표현한다. |
| 기록 우선 표본 | record-first sampling | — | 비교 감사에서 공개 기록을 먼저 뽑아 열고 종이를 찾는 순서. 공개 태그가 필요 없어 강요 통로를 만들지 않는다. |
| 신뢰 기반 | trusted computing base | `TCB` | 정규 인코딩, 암호 래퍼, 커밋먼트·증명, 장부·Merkle, 상태기계, 공개 검증기, 커밋먼트 유닛, 카운터·가명 유닛, 신뢰기관 집계. |
| 일괄 증명 | batch attestation | `BatchAttest` | 기록 64건(또는 15분, 또는 마감)마다 기록 해시 Merkle root와 모듈 카운터 구간에 장치와 모듈이 하이브리드 서명한 공개 이벤트. 모듈은 카운터 연속성을 확인한 뒤에만 서명한다. |
| 봉인 저널 | sealed journal | `journal` | 커밋먼트 유닛이 기록 해시·share 패키지·검증·격리·마감을 순서대로 담아 fsync하는 해시 체인(`JournalEntry` 0x0014). `sealed` 등급이며 투함 순서를 드러내므로 공개하지 않는다. |
| 늦은 마감 | late close | `LateBatchClose`, `LateBoxClose` | 멈췄던 장치를 입회 아래 되살려 저널에서 미결 배치·마감을 닫는 절차. |
| 비상 투입 | fallback deposit | `FallbackDeclared` | 스캐너와 예비 장치가 모두 없을 때 봉인된 비상 투입구로 기록 없이 받는 투표지. 마감의 `no_record_count`로 센다. |
| 검증 사다리 | verification ladder | `V1`..`V5` | V1 속성·퍼징·변이, V2 Kani, V3 Verus 또는 Creusot, V4 TLA+·Tamarin, V5 독립 2차 구현. |
| 정규 인코딩 | canonical encoding | `ityv-encoding` | 재귀 없는 고정폭 이진 형식. 모든 서명·해시 대상 객체의 유일한 바이트 표현. |
