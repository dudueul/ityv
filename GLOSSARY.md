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
| 독립검증위원회 | Independent Verification Committee | `ivc` | 신규 독립 법정기구. genesis와 법적 승인 객체의 공동 서명, 증인·신뢰기관 지정, 키 생성·파기 절차 주관, 분쟁 공동 접수, 감사 확대 명령, 소수의견을 포함한 보고서 공표. 결과를 바꿀 권한은 없다. |
| 입회 절차 | ceremony, key ceremony | `ceremony` | 정해진 순서대로, 참관인과 위원회 직원 앞에서 진행하고 전 과정을 기록하는 절차. 키 생성, 모듈 발급, 정당 열쇠 생성, 감사 시드 추첨, 수령 대조, 파기 절차가 여기에 든다. 개인정보와 비밀 자료는 기록에 담지 않는다. |
| 정당 열쇠 생성 절차 | party key ceremony | `PartyKeyCeremony` | 선거마다 정당 챔버가 가명 PRF 키를 네트워크 없는 장비에서 만들고 2-of-3 몫으로 USB HSM에 나눠 두며, 그 정당의 모든 확인 모듈에 감싸 넣는 절차. 키 자료는 기록하지 않는다(PROTOCOL §6.4, ADR-0024). |
| 보안 칩 | secure element | `se` | 키를 칩 밖으로 내보내지 않고 칩 안에서 계산하는 별도 칩. 카운터·가명 유닛의 정당 모듈에만 두고 가명 PRF(HMAC-SHA-256)를 계산한다. |
| 키 확인값 | key check value | `prf_key_check` | 정당 PRF 키로 계산한 공개 확인값. 한 정당의 모든 확인 모듈이 같은 키를 받았는지 누구나 대조한다. |
| 변조 스위치 | tamper switch | — | 모듈 외함이 열리면 키 영역을 지우는 스위치. 코인 전지로 선거 기간에만 살아 있다. |
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
| 기준점·투표양식 표지 | fiducials, ballot-style mark | — | 투표지 네 귀퉁이의 위치 기준 사각형과 `ballot_style_id`만 담은 작은 2차원 코드. 같은 투표양식이면 모든 투표지에 같은 값이라 개별 투표지를 구별하지 않는다. 해석 유닛은 사전투표지의 일련번호 바코드를 해독하지 않고 이것만 읽는다(VC-071). |
| 해석 유닛 | interpretation unit | `interp` | 투표지 이미지를 해석해 선택 인덱스 몇 바이트를 커밋먼트 유닛에 넘긴다. 불신 대상. 단방향 링크로만 연결. |
| 커밋먼트 유닛 | commitment unit | `cunit` | `no_std` Rust 수백 줄. 커밋먼트, 정형성 증명, share, 장치 서명, 추적코드, 투함 ID 각인 명령을 만든다. 검증 사다리의 최상위 대상. |
| 챔버 모듈(봉인 모듈) | chamber module | `cmod` | 챔버가 공급하고 봉인한 물리 모듈. 정당 모듈 P1…Pn은 모두 필수이고, J·A·C는 자체 모듈 또는 독립검증위원회의 중립 모듈에 위임할 수 있으며, N(선관위)은 모듈이 없다. 기능: 난수 기여, 투함 ID·봉투 라벨 기여, 자기 챔버 구성원의 일회용 패드 보관과 XOR, 일회성 MAC 키 공급, 확인 장치용 가명 PRF, 카운터 서명. 발급 값을 보관하지 않는다. |
| 패드 카드 | pad card | `pad_card` | 일회용 패드를 담는 NOR 플래시 카드. 모듈 본체에 꽂아 봉인하며, 파기 절차에서 0으로 덮은 뒤 파쇄한다. 모듈 본체는 소거·검사·측정을 거쳐 다음 선거에 다시 발급한다(PROTOCOL §9.4.2, VC-072). |
| 투함 기록 | cast record | `CastRecord` | 표 하나의 공개 기록. 본문(선거·투표함·투표양식·커밋먼트·정형성 증명·모듈 카운터·share 패키지 해시)과 기록 서명(장치·모듈의 Ed25519). 양자내성 서명은 64건 배치의 `BatchAttest`가 제공한다. 선택과 투함 ID는 커밋먼트 안에만 존재하며 시간과 순번은 없다. |
| 커밋먼트 | commitment | `commitment` | Ristretto255 위의 일반화 Pedersen 커밋먼트. 숨김은 무조건적, 결속은 계산적. |
| 투함 ID | cast id | `cast_id` | 투함 시 챔버 모듈들의 난수 기여를 해시해 만드는 192비트 값. 투표지에 각인되며 커밋먼트 안에만 존재하고 공개 기록에 노출하지 않는다. |
| 봉투 라벨 | envelope label | `env_label` | 관외·재외 전용. 챔버 모듈들의 기여를 해시해 만든 독립 무작위 24바이트 토큰을 봉투에 부착한다. 투함 ID나 추적코드에서 유도하지 않으므로 봉투와 투표지를 (라벨, 각인)으로 연결할 수 없다. 공개 기록에 노출하지 않고 share로만 전달하며, 수령 대조 절차에서 정족수가 라벨만 복원해 대조한다. |
| 라벨 스티커 | label sticker | `sticker` | 관외·재외 방문당 한 장. 그 방문에서 넣은 표들의 봉투 라벨 값 목록을 2차원 코드로 담는다. 다시 찍은 투표지의 스티커는 같은 봉투에 붙인다. 수령지 판독기는 값을 낱개 집합으로만 남긴다(PROTOCOL §10.6). |
| 추적코드 | tracking code | `tracking_code` | 투함 기록의 SHA3-512 해시. 서명된 슬립으로 유권자에게 인쇄한다. 포함 여부만 검증 가능하고 선택은 증명할 수 없다. |
| 코드 슬립 | code slip | `slip` | 방문당 한 장. 그 방문에서 넣은 표의 추적코드 목록(1–8개), 투표소, 시간 구간과 하이브리드 서명이 인쇄된 종이(ADR-0021). |
| 투입 전 검증 | pre-cast challenge | `challenge` | 유권자가 방문의 결정에서 확인할 투표지를 고르면(일부 또는 전부) 스캐너가 그 표의 난수를 공개하고 그 표는 폐기되며 그 투표양식만 새로 교부한다. 참관인은 시험용 투표지로 요구한다. |
| 가림 봉투 | privacy sleeve | `sleeve` | 기표한 투표지를 스캐너까지 가려 주는 재사용 폴더. 인주가 잘 묻지 않는 코팅 재질에 안쪽은 어두운 무늬다. 아무것도 기록하지 않으며 봉투와 유권자를 잇는 기록도 남기지 않는다. 안쪽에 인주 자국이 보이면 그날은 다시 쓰지 않는다(`BALLOT_LAYOUT.md` §4). |
| 방문 | visit | `visit` | 유권자가 받은 투표지 전부(1–8장)를 가림 봉투 하나로 한 번에 넣는 투입 단위. 확인 뒤 다시 찍은 투표지는 다음 방문이다(ADR-0021). |
| 방문 결정 | visit decision | — | 방문의 모든 기록이 장치·모듈 기록 서명으로 묶인 뒤에 받는 위치별 넣기·확인 선택. 저널에 방문 결정 항목(종류 7)으로 영속화되어야 성립한다(VC-068, VC-069). |
| 결정 전 결속 | pre-decision binding | — | 모듈이 한 카운터에 본문 해시 하나만 서명하고, 그 서명을 결정 전에 받는 규칙. 장치가 어느 표가 확인될지 안 뒤에 기록을 바꾸지 못하게 한다(PROTOCOL §7.2.1). |
| 여는 값 share | opening share | `share` | 커밋먼트 난수(모듈별 기여), 투함 ID, 봉투 라벨의 선형 비밀분산 조각. 챔버 접근구조로 분산되고 일회용 패드(기본) 또는 하이브리드 KEM(대체)으로 전송된다. |
| 집계 열기 | aggregate opening | — | 신뢰기관이 share를 합산해 합계 커밋먼트만 연다. 개별 표는 감사 표본 외에 열지 않는다. |
| 파기 절차 | destruction ceremony | — | 인증과 이의 기간 종료 후 share와 선거 키를 공개적으로 파기한다. |
| 확인 장치 | check-in device | `checkin` | 신원 확인 단말(불신) 여러 대와, 투표소마다 하나인 카운터·가명 유닛(검증)과 거기 꽂힌 정당 모듈 P1…Pn으로 구성된 장치. 단말은 유선으로 유닛에 연결된다. 봉인된 예비 유닛을 하나 둔다(PROTOCOL §6.2). |
| 중복 가명 조사 | duplicate-pseudonym identification | `DuplicateIdentification` | 공개된 중복 가명의 주인을 찾는 입회 절차. 법원 결정과 모든 정당 모듈이 있어야 하며, 명부 전체로 가명을 계산하되 결정문의 가명과 같은 사람만 내보낸다. 표와는 이어지지 않는다(PROTOCOL §6.6). |
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
| 보고 단위 | reporting unit | `reporting_unit` | 종이 개표 결과가 법령에 따라 공개되는 단위(선거일 투표구, 관내·관외 사전투표 단위 등). 암호 합계를 이 단위로 열고 `PaperCountReport`와 대조한다(PROTOCOL §11.2, §11.5, VC-075). |
| 감사 사유 코드 | audit reason code | — | `SampleComparison`의 불일치 종류 0–6. 확정 판정 불일치(1·2)는 그 장치 전수 대조, `UNREADABLE`·`BLANK`인데 종이가 유효(3·4)는 비율 공개(PROTOCOL §12.3, VC-074). |
| 늦은 마감 | late close | `LateBatchClose`, `LateBoxClose` | 멈췄던 장치를 입회 아래 되살려 저널에서 미결 배치·마감을 닫는 절차. |
| 비상 투입 | fallback deposit | `FallbackDeclared` | 스캐너와 예비 장치가 모두 없을 때 봉인된 비상 투입구로 기록 없이 받는 투표지. 마감의 `no_record_count`로 센다. |
| 검증 사다리 | verification ladder | `V1`..`V5` | V1 속성·퍼징·변이, V2 Kani, V3 Verus 또는 Creusot, V4 TLA+·Tamarin, V5 독립 2차 구현. |
| 연결 공개(분리망 주장 대신) | declared connectivity | `ConnectivityManifest` | 어떤 장비도 "분리돼 있다"고 주장하지 않고, 모든 연결의 방향·매체·상대·시간대를 genesis의 연결 목록에 적어 서로 다른 주체가 확인하게 하는 원칙(PROTOCOL §5.8, ADR-0022). |
| 단방향 장치 | one-way device link | — | 수신 소자 없이 송신기만 있는 광 포트. 스캐너와 카운터·가명 유닛의 유일한 바깥 연결이며, 들어오는 경로가 물리적으로 없다. |
| 관찰 탭 | observer tap | — | 투표소 게이트웨이의 장치 쪽과 바깥 회선 쪽에 있는 수동 분기 장치. 참관인과 등록 감시 단체가 자기 기록 장치를 붙여 프레임을 받아 두고 공개 사슬과 맞춰 본다. 회선에 아무것도 넣을 수 없다. |
| 릴리스 목록 | release manifest | `ReleaseManifest` | 선거에 쓰는 모든 펌웨어 이미지의 버전·빌드·소스·툴체인·해시·문구 표 해시와 구성 해시. 독립 빌더 셋 이상이 재현해 서명하고 genesis에 고정한다(PROTOCOL §4.6). |
| 소프트웨어 지문 | software fingerprint | — | 이미지 해시나 구성 해시의 앞 20바이트를 Base32 32자로 적은 값. 신원 줄에는 앞 16자를 보인다. |
| 신원 줄 | identity line | — | 모든 장치 화면 맨 아래에 늘 있는 줄: 프로그램 이름, 버전, 빌드, 지문 앞 16자, "소프트웨어 확인". 장치 자신의 주장이며 증명은 현장 증명이 한다(`docs/ui/SCREENS.md`). |
| 현장 증명 | on-site attestation | `DeviceAttestation` | 참관인이 만든 신선한 도전값에 대해, 실행 이미지에 결속된 증명 키로 장치가 서명한 소프트웨어 진술. 요약은 QR로 인쇄해 그 자리에서 확인한다(PROTOCOL §7.9). |
| 증명 키 | attestation key | — | 부트 ROM이 기기 고유 비밀과 실행 이미지 해시에서 유도하는 키. 다른 이미지로 부팅하면 다른 키가 나온다. |
| 확인 카드 | challenge card | `AttestChallenge` | 참관인 앱이 난수와 서명을 QR로 인쇄한 카드. 스캐너가 읽고 되돌려 준다. 투표지가 아니다(`BALLOT_LAYOUT.md` §14). |
| 고정 크기 프레임 | fixed-size frame | `UplinkFrame` | 10분 슬롯마다 정해진 수만큼 보내는 본문 1,048,576바이트짜리 송신 단위. 보낼 것이 없으면 0으로 채워 트래픽 모양이 아무 정보도 담지 않게 한다. |
| 세 출처 대조 | three-source reconciliation | `CarrierReconciliation` | 참관인 탭 캡처, 통신사 회선 기록, 게이트웨이 `UplinkSession`을 서로 맞춰 보는 선거 뒤 감사. |
| 정규 인코딩 | canonical encoding | `ityv-encoding` | 재귀 없는 고정폭 이진 형식. 모든 서명·해시 대상 객체의 유일한 바이트 표현. |
