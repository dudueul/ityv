# 요구사항 수확 등록부 / Requirements Harvest Register

> English summary: All 153 K-Ballot requirements re-numbered as ITYV-REQ-<DOMAIN>-<nnn> (same domain codes and numbers as the originals for traceability), restated for the ityv design (detached credential strips become cast ids inside commitments, HMAC device auth becomes hybrid signatures, JSON canonicalization becomes the fixed-width binary encoding, the in-memory core becomes the framed ledger), each labelled with its legal status (deployable-now, needs-rule, needs-statute), its activation stage (0-3 per ADR-0002), an acceptance-test summary, and the governing ADR. A second section adds 37 new requirements for the E2E layer (domains SCN, CRY, TRU, PTL, RCV, AUD, DSP, GOV, BRD). Every requirement starts in status 미인수 (not accepted); acceptance needs the evidence named in VERIFICATION_LADDER.md.

상태: 초안 v0.1 (ADR-0008). 모든 행의 인수 상태는 `미인수`다.

## 0. 라벨

- 법적 상태: `deployable-now`(현행법·내부 절차로 가능), `needs-rule`(선관위 규칙 필요), `needs-statute`(법률 개정 필요, LEGAL_ANNEX 참조).
- 활성화 단계: ADR-0002의 0..3.
- 도메인 코드는 원 ID를 그대로 쓴다. 신규 도메인: SCN(투함 스캐너), CRY(암호), TRU(신뢰기관), PTL(참여 장부), RCV(관외 수령), AUD(감사), DSP(분쟁), GOV(거버넌스 확장), BRD(게시판).

## 1. 계승 요구사항 (153)

| ITYV ID | 원 ID | 도메인 | 재서술된 요구 | 법적 상태 | 단계 | 수용 시험 | ADR |
|---|---|---|---|---|---|---|---|
| ITYV-REQ-GOV-001 | KB-GOV-001 | GOV | 연구·시범·실선거 기능을 배포 프로필과 법적 승인 범위로 분리하고 승인 없는 범위 확대를 타입과 계약 양쪽에서 금지한다 | deployable-now | 0 | genesis 승인 범위 밖 기능이 활성화되지 않음을 trybuild와 시뮬레이터로 확인 | ADR-0002 |
| ITYV-REQ-GOV-002 | KB-GOV-002 | GOV | 독립검증위원회의 구성·권한·이해충돌 공시를 정의하고 임명을 추천 기관 서명 이벤트로 장부에 남긴다 | needs-statute | 1 | 임명 이벤트 없는 위원 서명은 genesis 검증 실패 | ADR-0012 |
| ITYV-REQ-GOV-003 | KB-GOV-003 | GOV | 투표 처리, 증인 서명, 신뢰기관 share 보유, 보관, 법적 확정의 주체를 분리하고 한 조직이 두 역할의 키를 갖지 못하게 한다 | needs-statute | 1 | 역할 간 키 재사용이 genesis 검증에서 거부됨 | ADR-0012 |
| ITYV-REQ-GOV-004 | KB-GOV-004 | GOV | 투표지 표식, 슬립, 신원 연결에 영향을 주는 변경은 ADR과 법적 승인 범위 변경을 요구한다 | deployable-now | 0 | ADR 없는 설계 변경 PR 거부, 범위 변경은 genesis 재서명 | ADR-0002 |
| ITYV-REQ-GOV-005 | KB-GOV-005 | GOV | 후보·정당에 무관하게 같은 오류·감사·복구 정책을 적용한다 | deployable-now | 0 | 후보 이름을 교환한 대칭 시뮬레이션에서 결과 동일 | ADR-0011 |
| ITYV-REQ-GOV-006 | KB-GOV-006 | GOV | 투표사무원 단독으로 확인·교부·마감·보관·폐기를 모두 수행할 수 없게 역할별 서명을 요구한다 | needs-rule | 0 | 단일 역할 키로 전 단계 이벤트 생성 시 거부 | ADR-0010 |
| ITYV-REQ-GOV-007 | KB-GOV-007 | GOV | 어떤 시험 통과도 인증으로 표기하지 않으며 `NO_GO`를 모든 산출물에 게시한다 | deployable-now | 0 | 문서·UI·API 문구 검사 | CONSTITUTION §5 |
| ITYV-REQ-GOV-008 | KB-GOV-008 | GOV | 모든 보안 주장은 테스트·증명 ID로 추적되고 원시 데이터와 재현 절차를 제출한다 | deployable-now | 0 | 추적 없는 주장을 CI가 거부 | CONSTITUTION §5 |
| ITYV-REQ-GOV-009 | KB-GOV-009 | GOV | 프로토콜·소스·시험 결과를 공개하고 이의 접수 창구를 둔다 | deployable-now | 0 | 공개본과 접수 이력의 변조 방지 확인 | ADR-0011 |
| ITYV-REQ-LAW-001 | KB-LAW-001 | LAW | 투표지 표식과 일련번호 처리의 변경은 법적 승인 범위 `BALLOT_MARK` 없이 활성화되지 않는다 | needs-statute | 2 | 범위 없는 genesis에서 각인 명령 타입 생성 불가 | ADR-0002, ADR-0005 |
| ITYV-REQ-LAW-002 | KB-LAW-002 | LAW | 관내·관외 투표함과 회송용 봉투 흐름을 제158조와 대조하고 보관 경로로 genesis에 고정한다 | deployable-now | 0 | 경로 밖 인계 이벤트 거부 | ADR-0010 |
| ITYV-REQ-LAW-003 | KB-LAW-003 | LAW | 우편 접수와 투입·보관에 정당추천위원 참여를 이중 서명 이벤트로 기록한다 | deployable-now | 0 | 단일 조직 서명 접수 이벤트 거부 | ADR-0010 |
| ITYV-REQ-LAW-004 | KB-LAW-004 | LAW | 법정 영상 보존과 구간 해시 앵커의 보존 분리 원칙을 문서화한다 | needs-rule | 0 | 보존 정책 문서와 앵커 이벤트 주기 검사 | ADR-0010 |
| ITYV-REQ-LAW-005 | KB-LAW-005 | LAW | `CRYPTO_TALLY_VERIFIED`는 법적 확정이 아니며 `LEGAL_CERTIFIED`는 법정 권한의 결정 참조로만 생성된다 | needs-statute | 2 | 상태 전이 타입 검사, 자동 전환 경로 부재 | ADR-0011 |
| ITYV-REQ-LAW-006 | KB-LAW-006 | LAW | 스캐너, 카세트, 각인, 투입 절차의 변경은 규칙 검토와 시범 승인 뒤에만 활성화된다 | needs-statute | 2 | `STAGE_GATE` 범위 검사 | ADR-0002 |
| ITYV-REQ-LAW-007 | KB-LAW-007 | LAW | 가명 모듈, 참여 장부, 게시판의 개인정보 영향평가를 단계 전환 조건으로 둔다 | needs-rule | 0 | PIA 보고서 제출 없이는 단계 전환 불가 | ADR-0002, ADR-0009 |
| ITYV-REQ-LAW-008 | KB-LAW-008 | LAW | 장애인·고령자·외국어 지원 범위를 사전에 정의하고 BMD 출력도 같은 스캐너를 통과하게 한다 | needs-rule | 2 | 접근성 평가 보고 | ADR-0005 |
| ITYV-REQ-LAW-009 | KB-LAW-009 | LAW | 해외 표준은 참조로만 표기하고 국내 인증으로 오인되지 않게 한다 | deployable-now | 0 | 문구 검사 | — |
| ITYV-REQ-REG-001 | KB-REG-001 | REG | 투표소, 투표함, 장치, 봉인 모듈, 참관인, 인계자, 보관 경로를 genesis 인벤토리에 사전 등록한다 | deployable-now | 0 | 미등록 주체의 이벤트는 수록 거부 | ADR-0010 |
| ITYV-REQ-REG-002 | KB-REG-002 | REG | genesis는 선관위·독립검증위원회 서명과 증인 정족수로 승인되고 대역 외 핀으로 배포된다 | needs-statute | 1 | 서명·핀 결여 시 검증 실패 | ADR-0002, ADR-0012 |
| ITYV-REQ-REG-003 | KB-REG-003 | REG | 후보·선거구·투표양식 매핑을 버전·효력시점과 함께 genesis에 동결한다 | deployable-now | 0 | 다른 매핑의 기록은 양식 ID 불일치로 거부 | ADR-0006 |
| ITYV-REQ-REG-004 | KB-REG-004 | REG | 확인 수, 교부·훼손·반납 수, 투함 기록 수, 종이 수를 서로 다른 출처에서 대조한다 | deployable-now | 0 | 1건 차이 주입 시 `HOLD_REVIEW` | ADR-0009 |
| ITYV-REQ-REG-005 | KB-REG-005 | REG | 신원 확인 데이터와 투함 기록은 공통 식별자가 없고 가명·투함 ID를 같은 줄에 기록하는 경로가 존재하지 않는다 | deployable-now | 0 | 교차 DB 조회 경로 부재 증명, 카운터·가명 유닛 V3 | ADR-0009 |
| ITYV-REQ-REG-006 | KB-REG-006 | REG | TCB는 벽시계를 쓰지 않고 순번·이전 해시로 순서를 정하며 시간은 15분 구간 참고값이다 | deployable-now | 0 | 시계 역행 주입 시 검증 결과 불변 | CONSTITUTION §1.8 |
| ITYV-REQ-REG-007 | KB-REG-007 | REG | genesis 해시를 서로 다른 통신·물리 경로로 모든 장치와 검증기에 배포한다 | needs-rule | 0 | 한 경로 변조 시 핀 불일치 탐지 | ADR-0002 |
| ITYV-REQ-REG-008 | KB-REG-008 | REG | 선거 종료 이벤트 뒤 신규 교부·투함은 예외 심사 경로로만 간다 | deployable-now | 0 | 종료 후 이벤트는 `QUARANTINED` | ADR-0005 |
| ITYV-REQ-REG-009 | KB-REG-009 | REG | 오교부·훼손·투입 전 검증 폐기·선거구 변경의 처리 규칙을 typestate로 규정한다 | deployable-now | 0 | 정정 전후 수량 대조, 잘못된 전이 컴파일 불가 | CONSTITUTION §1.4 |
| ITYV-REQ-BAL-001 | KB-BAL-001 | BAL | 유권자가 확인한 종이 기표가 유일한 법적 원본이며 커밋먼트는 검증 보조수단이다 | needs-statute | 2 | 종이 수검표 결과가 암호 집계를 항상 우선함을 절차와 상태 전이로 확인 | ADR-0005, ADR-0011 |
| ITYV-REQ-BAL-002 | KB-BAL-002 | BAL | 슬립은 선택을 증명할 수 없고 제3자가 유권자와 기표를 연결하는 데 쓰일 수 없다 | needs-statute | 3 | Tamarin 영수증 무증명성, 강요 시나리오 재현 평가 | ADR-0001, ADR-0006 |
| ITYV-REQ-BAL-003 | KB-BAL-003 | BAL | 자격 확인과 투함 기록은 별도 장치·키·보존기간·접근 경로로 운영된다 | deployable-now | 0 | 재식별 위험평가 제출 | ADR-0009 |
| ITYV-REQ-BAL-004 | KB-BAL-004 | BAL | 2단계 이전에는 동일 수량 교체를 탐지한다고 주장하지 않으며, 2단계 이후에도 감사 집행 없이는 주장하지 않는다 | deployable-now | 0 | 상태 어휘와 보고서 문구 검사 | ADR-0005 |
| ITYV-REQ-BAL-005 | KB-BAL-005 | BAL | 투입 전 검토·취소 기회를 보장하고 투입 전 검증 요구권을 안내한다 | needs-statute | 2 | 사용성 시험에서 검증 요구 성공률 측정 | ADR-0005 |
| ITYV-REQ-BAL-006 | KB-BAL-006 | BAL | 접근성 장치(BMD) 경로의 출력도 같은 커밋먼트 흐름을 거치며 동등하게 시험한다 | needs-rule | 2 | 장애 유형별 독립 투표·비밀성 시험 | ADR-0005 |
| ITYV-REQ-BAL-007 | KB-BAL-007 | BAL | 후보 순서·강조·오류 안내가 편향되지 않도록 genesis 투표양식과 대조한다 | deployable-now | 0 | 스냅샷 비교 | ADR-0006 |
| ITYV-REQ-BAL-008 | KB-BAL-008 | BAL | 투함 기록에는 시각·순번이 없고 게시는 추적코드 순이며 소규모 집계는 억제한다 | deployable-now | 0 | 재식별 모의 공격 | ADR-0009, ITYV-THR-209 |
| ITYV-REQ-BAL-009 | KB-BAL-009 | BAL | E2E 계층은 공개 검토·독립 평가·법적 승인 범위 없이는 필수 기능으로 켜지지 않는다 | needs-statute | 2 | 범위 없는 genesis에서 커밋먼트 타입 생성 불가 | ADR-0002 |
| ITYV-REQ-PHY-001 | KB-PHY-001 | PHY | 종이, 각인 수, 미사용·훼손·검증 폐기, 봉투, 투표함별 합계를 독립 계수한다 | deployable-now | 0 | 상호 배타 수량 불일치 시 `HOLD_REVIEW` | ADR-0005 |
| ITYV-REQ-PHY-002 | KB-PHY-002 | PHY | 봉인 해시를 모든 인계 이벤트에 결속하고 단계마다 대조한다 | deployable-now | 0 | 봉인 교체가 인계 검증 실패 | ADR-0010 |
| ITYV-REQ-PHY-003 | KB-PHY-003 | PHY | 인계는 송신자·수신자 쌍방 서명이며 한쪽 서명만 있으면 수령 확정이 아니다 | deployable-now | 0 | 단일 서명 인계 거부 | ADR-0010 |
| ITYV-REQ-PHY-004 | KB-PHY-004 | PHY | 참관인·인계자 독립성은 추천 기관 서명 임명 이벤트로 검사한다 | needs-rule | 0 | 같은 조직 복수 서명 거부 | ADR-0012 |
| ITYV-REQ-PHY-005 | KB-PHY-005 | PHY | 모든 개함은 법적 근거, 입회자, 전후 수량, 새 봉인을 담은 이벤트를 남긴다 | deployable-now | 0 | 사유 없는 개함 이벤트는 `HOLD_REVIEW` | ADR-0010 |
| ITYV-REQ-PHY-006 | KB-PHY-006 | PHY | 동일 수량 교체는 투함 시 커밋먼트와 기록 우선 감사로 탐지하며 감사 미집행은 상태에 표기한다 | needs-statute | 2 | 합성 교체 사례가 감사 불일치로 드러남 | ADR-0005, ADR-0011 |
| ITYV-REQ-PHY-007 | KB-PHY-007 | PHY | 프린터 미세 표식, 각인 패턴, 인쇄 로그가 투함 순서나 신원을 드러내지 않는지 점검한다 | needs-rule | 2 | 법과학 상관 실험 보고 | ADR-0005 |
| ITYV-REQ-PHY-008 | KB-PHY-008 | PHY | 보관시설 접근은 이중 신원 확인과 CCTV 구간 해시 앵커를 요구한다 | needs-rule | 0 | 앵커 공백 시 분쟁 절차 발동 | ADR-0010 |
| ITYV-REQ-PHY-009 | KB-PHY-009 | PHY | 수검표 결과와 커밋먼트 집계의 비교표를 감사 이벤트로 보존한다 | needs-statute | 2 | 1장 차이 사례 재현 | ADR-0011 |
| ITYV-REQ-POST-001 | KB-POST-001 | POST | 봉투 라벨은 투함 ID에서 유도되고 공개 기록에 노출되지 않으며 share로만 전달된다 | needs-statute | 2 | 공개 데이터에서 라벨 미검출 | ADR-0010 |
| ITYV-REQ-POST-002 | KB-POST-002 | POST | 관외 투표함 개함 봉투 수, 우체국 인계 수, 투함 기록 수를 별도 기관이 대조한다 | deployable-now | 0 | 고의 누락·과다 차이 탐지 | ADR-0010 |
| ITYV-REQ-POST-003 | KB-POST-003 | POST | 인계 수와 수령 라벨 수와 예외 사유를 회차별로 대조하고 미수령은 `CAST_NOT_RECEIVED`로 공개 집계한다 | needs-statute | 2 | 불일치 상태에서 집계 열기 불가 | ADR-0010 |
| ITYV-REQ-POST-004 | KB-POST-004 | POST | 야간 접수의 적법성은 접수 이벤트의 입회·회차·봉인 기록으로 판단한다 | deployable-now | 0 | 야간 접수와 무단 개함의 구별 | ADR-0010 |
| ITYV-REQ-POST-005 | KB-POST-005 | POST | 봉투 중복·유실은 분쟁 절차로 보내며 정상표 자동 무효로 이어지지 않는다 | deployable-now | 0 | 중복 사례에서 양쪽 보존 | ADR-0011 |
| ITYV-REQ-POST-006 | KB-POST-006 | POST | 일방향 카세트는 법률 검토 후 별도 실증하며 미승인 구조는 비활성화된다 | needs-statute | 2 | 미승인 장치 이벤트 거부 | ADR-0010 |
| ITYV-REQ-POST-007 | KB-POST-007 | POST | 선거일·관내·관외·재외·거소·선상 흐름은 수집 프로필과 투표함별 보관 경로로 분리 집계한다 | deployable-now | 0 | 경로 오염 시 불일치 탐지 | ADR-0013 |
| ITYV-REQ-POST-008 | KB-POST-008 | POST | 우편 실명·주소 자료는 장부·게시판 어디에도 복사되지 않는다 | deployable-now | 0 | 공개 데이터 DLP 검색 | ADR-0010 |
| ITYV-REQ-POST-009 | KB-POST-009 | POST | 반송·훼손·미도착은 각각의 상태로 기록되고 정상 배송으로 처리되지 않는다 | deployable-now | 0 | 예외 상태별 처리 확인 | ADR-0010 |
| ITYV-REQ-BOX-001 | KB-BOX-001 | BOX | 커밋먼트 유닛은 정규 이진 형식 외 어떤 입력도 거부하며 해석 유닛 입력은 선택 인덱스와 양식 ID 몇 바이트로 제한된다 | deployable-now | 0 | 퍼징으로 거부 확인, Kani 정규성 | ENCODING.md, ADR-0005 |
| ITYV-REQ-BOX-002 | KB-BOX-002 | BOX | 네트워크 없이 투함 기록을 내구 저장하고 중앙 확정은 보류하며 표를 폐기하지 않는다 | deployable-now | 0 | 24시간 오프라인 후 무손실 재생 | ADR-0004 |
| ITYV-REQ-BOX-003 | KB-BOX-003 | BOX | 각 커밋먼트 유닛은 고유 하이브리드 키로 투함 기록·마감을 서명한다 | needs-statute | 2 | 다른 장치 키 서명 거부 | ADR-0006 |
| ITYV-REQ-BOX-004 | KB-BOX-004 | BOX | 기록 생성, 순번 부여, 각인 명령, 슬립 인쇄는 내구 기록 성공 뒤에만 일어나는 단일 전이다 | deployable-now | 0 | 강제 종료 시 부분 기록 없음, V3 | CONSTITUTION §4.4 |
| ITYV-REQ-BOX-005 | KB-BOX-005 | BOX | 마감 뒤 신규 투함 기록은 받지 않고 동일 바이트 재전송만 멱등 처리한다 | deployable-now | 0 | 마감 후 신규 100회 거부 | ADR-0005 |
| ITYV-REQ-BOX-006 | KB-BOX-006 | BOX | 중복 투함 ID는 양쪽 기록을 `QUARANTINED`로 보존하고 즉시 무효로 확정하지 않는다 | deployable-now | 0 | 중복 사례 양쪽 보존 | ADR-0011 |
| ITYV-REQ-BOX-007 | KB-BOX-007 | BOX | 해석 유닛과 커밋먼트 유닛 사이는 좁은 단방향 링크이며 주변장치 허가 목록 밖 장치는 연결되지 않는다 | needs-rule | 2 | 위장 장치 연결 실험에서 감사 이벤트 | CONSTITUTION §4 |
| ITYV-REQ-BOX-008 | KB-BOX-008 | BOX | 마감·재시작·예외 개봉은 독립 사무원과 다른 조직 참관인의 서명을 요구한다 | deployable-now | 0 | 같은 사용자 이중 승인 거부 | ADR-0010 |
| ITYV-REQ-BOX-009 | KB-BOX-009 | BOX | 정전·배터리 소진·저장소 가득 참에서 기록 유실 여부를 시험한다 | deployable-now | 0 | 내구 경계마다 오류 주입 | VERIFICATION_LADDER |
| ITYV-REQ-LED-001 | KB-LED-001 | LED | 장부 API는 append/read/verify/checkpoint만 가지며 update/delete 경로가 없다 | deployable-now | 0 | API 표면 검사 | ADR-0008 |
| ITYV-REQ-LED-002 | KB-LED-002 | LED | 모든 이벤트는 선거 ID, 발행자 ID, 순번, 이전 해시, 하이브리드 서명을 갖는다 | deployable-now | 0 | 변조·중복·역순·교차 선거 거부 | ENCODING.md |
| ITYV-REQ-LED-003 | KB-LED-003 | LED | 독립 검증기는 모든 이벤트로 Merkle root를 재계산하고 일관성 증명을 확인한다 | deployable-now | 0 | 독립 2차 구현과 결과 비교(V5) | ADR-0007 |
| ITYV-REQ-LED-004 | KB-LED-004 | LED | 단일 작성자 장부, 찢긴 프레임은 복구하지 않고 격리한다 | deployable-now | 0 | 강제 종료 고장 주입 | ADR-0008 |
| ITYV-REQ-LED-005 | KB-LED-005 | LED | 외부 앵커·증인 체크포인트·슬립으로 장부 전체 교체를 탐지한다 | deployable-now | 0 | 스냅샷 치환 후 탐지 | ADR-0011 |
| ITYV-REQ-LED-006 | KB-LED-006 | LED | 장치 서명과 genesis 등록 없는 이벤트는 수록하지 않는다 | deployable-now | 0 | 무인증 1만 이벤트 삽입 거부 | ADR-0010 |
| ITYV-REQ-LED-007 | KB-LED-007 | LED | 정정·판정 취소는 기존 기록을 바꾸지 않고 사건 링크와 승인자를 가진 새 이벤트다 | deployable-now | 0 | 정정 이력 연속성 | ADR-0011 |
| ITYV-REQ-LED-008 | KB-LED-008 | LED | 선거별 키·root·데이터를 분리하고 모든 객체 첫 필드가 선거 ID다 | deployable-now | 0 | 다른 선거 이벤트 재생 거부 | ENCODING.md §4 |
| ITYV-REQ-LED-009 | KB-LED-009 | LED | 조회 DB는 검증된 장부에서 재구축 가능한 폐기 가능한 투영이다 | deployable-now | 0 | DB 삭제 후 동일 투영 재생성 | ADR-0008 |
| ITYV-REQ-WIT-001 | KB-WIT-001 | WIT | 증인 공개키·기관·알고리즘·효력 시점과 명단 해시를 genesis와 별도 경로로 배포한다 | needs-rule | 0 | 가짜 명단 거부 | ADR-0012 |
| ITYV-REQ-WIT-002 | KB-WIT-002 | WIT | 체크포인트 서명은 ML-DSA-87과 Ed25519 둘 다 검증하고 서명자 ID를 중복 계산하지 않는다 | deployable-now | 0 | 정상·위조·중복·교차 선거 시험 | ADR-0006 |
| ITYV-REQ-WIT-003 | KB-WIT-003 | WIT | 각 증인은 승인한 마지막 체크포인트를 영속 보관하고 확장만 승인한다 | deployable-now | 0 | 분기 체크포인트 서명 거부 | ADR-0012 |
| ITYV-REQ-WIT-004 | KB-WIT-004 | WIT | 정족수 9 외에 조직 7·공급자 4·지역 3 다양성과 임명 이벤트를 검사한다 | needs-rule | 0 | 한 조직 복수 키 통과 불가 | ADR-0012 |
| ITYV-REQ-WIT-005 | KB-WIT-005 | WIT | 알고리즘·정족수·선거 ID·`proof_system_id` 변경 시 이전 서명은 무효다 | deployable-now | 0 | 다운그레이드 거부 | ADR-0006 |
| ITYV-REQ-WIT-006 | KB-WIT-006 | WIT | 증인·신뢰기관 키는 선거별 공개 절차에서 생성·사용·파기하고 다자 승인으로 접근한다 | needs-statute | 1 | 절차 기록과 파기 증빙 | ADR-0012 |
| ITYV-REQ-WIT-007 | KB-WIT-007 | WIT | 정족수 미달 시 체크포인트는 `UNVERIFIED`이며 현장 증거는 보존된다 | deployable-now | 0 | 증인 5곳 차단 시 안전한 미확정 | ADR-0004 |
| ITYV-REQ-WIT-008 | KB-WIT-008 | WIT | 서명 실패·키 교체·분기 사건을 원본과 함께 기록한다 | deployable-now | 0 | 사건 보고 자동 생성 | ADR-0011 |
| ITYV-REQ-WIT-009 | KB-WIT-009 | WIT | 알고리즘 전환 시 과거 검증 결과와 시점을 보존한다 | needs-statute | 2 | 키 회전 후 과거 검증 재현 | ADR-0006 |
| ITYV-REQ-ARC-001 | KB-ARC-001 | ARC | 체크포인트와 장부 세그먼트를 운영자 밖 불변 저장소에 기록한다 | needs-rule | 0 | 운영 관리자의 삭제 권한 부재 확인 | ADR-0010 |
| ITYV-REQ-ARC-002 | KB-ARC-002 | ARC | 보관소는 삭제 불가 모드와 법정 보존기간을 적용한다 | needs-statute | 2 | 설정 증빙 | LEGAL_ANNEX 9 |
| ITYV-REQ-ARC-003 | KB-ARC-003 | ARC | 보관 객체의 버전 ID·해시·크기를 검증기에 기록한다 | deployable-now | 0 | 삭제 마커·덮어쓰기 탐지 | — |
| ITYV-REQ-ARC-004 | KB-ARC-004 | ARC | 서로 다른 관리자·공급자에 원본 복제본을 둔다 | needs-rule | 0 | 단일 계정 폐쇄 가정 복구 | ADR-0004 |
| ITYV-REQ-ARC-005 | KB-ARC-005 | ARC | 공개 미러는 권위가 없고 검증은 클라이언트 측에서 한다 | deployable-now | 0 | 위조 미러 데이터가 상태를 만들지 않음 | ADR-0003 |
| ITYV-REQ-ARC-006 | KB-ARC-006 | ARC | 외부 앵커와 복제가 실패한 구간은 `LOG_CONSISTENT`로 표시하지 않는다 | deployable-now | 0 | 단절 중 상태 불변 | ADR-0011 |
| ITYV-REQ-ARC-007 | KB-ARC-007 | ARC | 가명 키·share는 유한 보존 후 파기하고 커밋먼트·체크포인트는 영구 보존한다 | needs-statute | 2 | 파기 절차 이벤트 | ADR-0006 |
| ITYV-REQ-ARC-008 | KB-ARC-008 | ARC | 계정 삭제·리전 장애 시 원본 재구축 시간을 측정한다 | deployable-now | 0 | RTO/RPO 실험 | — |
| ITYV-REQ-ARC-009 | KB-ARC-009 | ARC | 보관·배포 비용 상한 경보를 둔다 | deployable-now | 0 | 10배 리허설 | — |
| ITYV-REQ-PUB-001 | KB-PUB-001 | PUB | 공식 서버 없이 공개키·체크포인트·게시판으로 집계를 재현하는 검증기를 제공한다 | deployable-now | 0 | 망 분리 PC 재검증 | ADR-0012 |
| ITYV-REQ-PUB-002 | KB-PUB-002 | PUB | 게시판에는 신원, 시각, 투함 ID, 봉투 라벨, 암호문이 없다 | deployable-now | 0 | 정적·동적 검출 | ADR-0006 |
| ITYV-REQ-PUB-003 | KB-PUB-003 | PUB | 상태 어휘 7종을 혼동 없이 표시하고 자동 전환하지 않는다 | deployable-now | 0 | UI 스냅샷 | CONSTITUTION §5.3 |
| ITYV-REQ-PUB-004 | KB-PUB-004 | PUB | 예상 투표함 수, 마감 수, 보류 수, 미수령 수를 공개한다 | deployable-now | 0 | 누락 시 보류 상태 노출 | ADR-0010 |
| ITYV-REQ-PUB-005 | KB-PUB-005 | PUB | 서로 다른 미러·증인의 체크포인트를 자동 비교한다 | deployable-now | 0 | 분기 탐지 | ADR-0012 |
| ITYV-REQ-PUB-006 | KB-PUB-006 | PUB | 시민 포털은 현장 장치와 망·권한·키를 공유하지 않는다 | deployable-now | 0 | 포털 탈취로 장치 API 호출 불가 | CONSTITUTION §0 |
| ITYV-REQ-PUB-007 | KB-PUB-007 | PUB | 공개 배포본마다 해시·서명·데이터셋 버전을 제공한다 | deployable-now | 0 | 바이트 수정 시 검증 실패 | ADR-0006 |
| ITYV-REQ-PUB-008 | KB-PUB-008 | PUB | 시민 검증 UI는 접근성·다국어 규칙을 지킨다 | deployable-now | 0 | 스크린리더·고대비 확인 | — |
| ITYV-REQ-PUB-009 | KB-PUB-009 | PUB | 신고자 신원을 보호하며 제보·처리 현황을 관리한다 | deployable-now | 0 | 공개 미러 노출 방지 | ADR-0011 |
| ITYV-REQ-INF-001 | KB-INF-001 | INF | 현장 장치는 인터넷 연결 서버와 물리·논리적으로 분리된다 | needs-rule | 0 | 역방향 연결 불가 증빙 | CONSTITUTION §4 |
| ITYV-REQ-INF-002 | KB-INF-002 | INF | 현장 장치에 무선 기능이 없다 | needs-rule | 2 | RF 시험 | CONSTITUTION §4.3 |
| ITYV-REQ-INF-003 | KB-INF-003 | INF | 측정 부팅과 펌웨어 해시 검증 경로를 제공한다 | needs-rule | 2 | 변조 이미지 부팅 차단 | CONSTITUTION §4.3 |
| ITYV-REQ-INF-004 | KB-INF-004 | INF | 재현 이중 빌드, SBOM, in-toto 증명, 하이브리드 서명 릴리스 | deployable-now | 0 | 독립 재현 빌드 해시 일치 | CONSTITUTION §3 |
| ITYV-REQ-INF-005 | KB-INF-005 | INF | 키 생성·파기 절차·마감 승인·HOLD 해제에 다요소·다자 승인 | needs-rule | 0 | 단일 자격으로 실패 | ADR-0012 |
| ITYV-REQ-INF-006 | KB-INF-006 | INF | 허가된 주변장치와 포트만 활성화 | needs-rule | 2 | 미허가 USB 삽입 시험 | CONSTITUTION §4.3 |
| ITYV-REQ-INF-007 | KB-INF-007 | INF | 취약점 접수·패치 심사·선거 중 변경 금지 정책 | deployable-now | 0 | 리허설 | SECURITY.md |
| ITYV-REQ-INF-008 | KB-INF-008 | INF | 각인기·해석 유닛·봉인 모듈·라이브러리의 공급망 실사 | needs-rule | 2 | 자산·펌웨어 해시 명세 | P0-02 |
| ITYV-REQ-INF-009 | KB-INF-009 | INF | 환경 시험(정전·온습도·충격) | needs-rule | 2 | 시험 성적 | P0-02 |
| ITYV-REQ-ACC-001 | KB-ACC-001 | ACC | 전 구간 동등 접근, BMD 경로 포함 | needs-rule | 2 | 실제 사용자 평가 | ADR-0005 |
| ITYV-REQ-ACC-002 | KB-ACC-002 | ACC | 오류 안내가 선택을 암시하거나 책임을 전가하지 않는다 | deployable-now | 0 | 문구 사용성 검증 | — |
| ITYV-REQ-ACC-003 | KB-ACC-003 | ACC | 비시각 경로에서 조작 결과 재확인 | needs-rule | 2 | 비시각 이용자 시험 | — |
| ITYV-REQ-ACC-004 | KB-ACC-004 | ACC | 다국어 후보·정당 명칭 독립 검수 | deployable-now | 0 | 다국어 시험 | — |
| ITYV-REQ-ACC-005 | KB-ACC-005 | ACC | 색상 외 표현, 확대, 고대비 | deployable-now | 0 | 200% 확대 시험 | — |
| ITYV-REQ-ACC-006 | KB-ACC-006 | ACC | 사무원 화면의 승인·마감·봉인 재확인 | deployable-now | 0 | 오조작 비율 시뮬레이션 | — |
| ITYV-REQ-ACC-007 | KB-ACC-007 | ACC | 접근성 장치 장애 시 동등한 대체 절차 | needs-rule | 2 | 모의 장애 시험 | — |
| ITYV-REQ-ACC-008 | KB-ACC-008 | ACC | 감사 결과·이의 안내의 접근성 | deployable-now | 0 | 이중 검증 | — |
| ITYV-REQ-ACC-009 | KB-ACC-009 | ACC | 도움 요청과 비밀투표 유지 안내문 | deployable-now | 0 | 이해도 조사 | — |
| ITYV-REQ-TST-001 | KB-TST-001 | TST | 요구사항·위협·테스트·증명·결함의 양방향 추적 | deployable-now | 0 | 무작위 30건 폐쇄성 검사 | CONSTITUTION §5.1 |
| ITYV-REQ-TST-002 | KB-TST-002 | TST | 투표함 수·기록 수·게시판 크기·오프라인 기간·복구량의 경계조건 | deployable-now | 0 | 부하 시험 | P0-04 |
| ITYV-REQ-TST-003 | KB-TST-003 | TST | 내구 기록 경계에서 강제 종료 1000회 | deployable-now | 0 | 손실·중복 분석 | VERIFICATION_LADDER |
| ITYV-REQ-TST-004 | KB-TST-004 | TST | 조회 DB 전체 변조·삭제·복원이 장부 증거에 영향 없음 | deployable-now | 0 | DROP/ROLLBACK 모의 | ADR-0008 |
| ITYV-REQ-TST-005 | KB-TST-005 | TST | 증인 5곳 장애 시 조용한 승인 없음 | deployable-now | 0 | 불가용 서명자 5개 케이스 | ADR-0004 |
| ITYV-REQ-TST-006 | KB-TST-006 | TST | 분기 로그 탐지 | deployable-now | 0 | 분기 시나리오 | ADR-0012 |
| ITYV-REQ-TST-007 | KB-TST-007 | TST | 동일 수량 교체와 원본 훼손 사례의 탐지·한계를 시험 결과에 기록 | deployable-now | 0 | 합성 교체가 감사 불일치로 | ADR-0011 |
| ITYV-REQ-TST-008 | KB-TST-008 | TST | 시간 구간·순서·거주지 결합 재식별 침투 테스트 | deployable-now | 0 | 공격 보고서 | ADR-0009 |
| ITYV-REQ-TST-009 | KB-TST-009 | TST | 장애 유권자·사무원 포함 사용성 평가 | needs-rule | 2 | 신뢰구간·실패율 | — |
| ITYV-REQ-OPS-001 | KB-OPS-001 | OPS | 전 단계 권한자·대리자·참관인을 genesis에 등록 | deployable-now | 0 | 미등록 사용자 승인 불가 | ADR-0010 |
| ITYV-REQ-OPS-002 | KB-OPS-002 | OPS | 선거 전 공개 논리·정확성 시험 | deployable-now | 0 | 기록과 참관 서명 보존 | ADR-0005 |
| ITYV-REQ-OPS-003 | KB-OPS-003 | OPS | 오프라인 기간과 미전송 기록 수를 현장과 중앙 모두 표시 | deployable-now | 0 | 단절·복구 후 누락 0 | ADR-0004 |
| ITYV-REQ-OPS-004 | KB-OPS-004 | OPS | 분쟁 접수 시 증거와 종이를 보존하고 조사 책임자를 기록 | deployable-now | 0 | 접근 통제 검증 | ADR-0011 |
| ITYV-REQ-OPS-005 | KB-OPS-005 | OPS | 선거 종료·권한 남용 후 신속 폐기 | deployable-now | 0 | 철회 후 작업 거부 | — |
| ITYV-REQ-OPS-006 | KB-OPS-006 | OPS | 3출처 공개 난수로 표본 추출 | needs-statute | 2 | 시드·표본 재현 | ADR-0011 |
| ITYV-REQ-OPS-007 | KB-OPS-007 | OPS | 표준 인계 서식(봉인 해시, 수량, 위치, 쌍방 서명) | deployable-now | 0 | 누락 서식 자동 보류 | ADR-0010 |
| ITYV-REQ-OPS-008 | KB-OPS-008 | OPS | 운영 로그에 선택·실명·투함 ID·가명 없음 | deployable-now | 0 | DLP 규칙 | ADR-0009 |
| ITYV-REQ-OPS-009 | KB-OPS-009 | OPS | 법적 심사기관에 재현 가능한 증거 패키지 제출 | deployable-now | 0 | 체크섬·열람 이력 | ADR-0011 |
| ITYV-REQ-INC-001 | KB-INC-001 | INC | 결과 변경 가능성이 있는 침해는 증거 보존과 `HOLD_REVIEW` | deployable-now | 0 | 중대 침해 모의 | ADR-0011 |
| ITYV-REQ-INC-002 | KB-INC-002 | INC | 운영팀이 포렌식 기록을 삭제하거나 사건을 자체 종결할 수 없다 | needs-statute | 1 | 운영 계정 종결 거부 | ADR-0012 |
| ITYV-REQ-INC-003 | KB-INC-003 | INC | 영향 장치·저장매체의 읽기전용 이미지와 해시 확보 | deployable-now | 0 | 포렌식 해시 | — |
| ITYV-REQ-INC-004 | KB-INC-004 | INC | 사건 순서를 시각만으로 확정하지 않는다 | deployable-now | 0 | 다중 시계 엇갈림 | CONSTITUTION §1.8 |
| ITYV-REQ-INC-005 | KB-INC-005 | INC | 신고자 자료를 공개 데이터와 분리 | deployable-now | 0 | 추출 불가 확인 | — |
| ITYV-REQ-INC-006 | KB-INC-006 | INC | 재검표 숫자만으로 의혹을 종결하지 않으며 커밋먼트 대조를 포함한다 | deployable-now | 0 | 원본 훼손 시 별도 절차 | ADR-0011 |
| ITYV-REQ-INC-007 | KB-INC-007 | INC | 사고 대응 변경은 승인·독립 시험·새 서명 없이 실선거 반영 금지 | deployable-now | 0 | 긴급 패치 차단 | CONSTITUTION §3 |
| ITYV-REQ-INC-008 | KB-INC-008 | INC | 조사 보고에 재현 단계·불확실성·반대 의견 보존 | deployable-now | 0 | 보고서 검사 | ADR-0012 |
| ITYV-REQ-INC-009 | KB-INC-009 | INC | 기술 판정과 법적 판단을 혼동하지 않으며 법적 결정은 `LegalDecisionRef`로만 | needs-statute | 2 | 관할 기관 서명 요구 | ADR-0011 |
| ITYV-REQ-DEL-001 | KB-DEL-001 | DEL | 연구·실증·실선거 인수의 합격 기준 분리 | deployable-now | 0 | 단계별 산출물 검토 | ADR-0002 |
| ITYV-REQ-DEL-002 | KB-DEL-002 | DEL | 독점 도구 없이 소스·빌드·검증 방법 납품 | deployable-now | 0 | 클린룸 빌드 성공 | CONSTITUTION §3 |
| ITYV-REQ-DEL-003 | KB-DEL-003 | DEL | 보안 연구자·지정 실험실의 열람권 | deployable-now | 0 | 접근 점검 | — |
| ITYV-REQ-DEL-004 | KB-DEL-004 | DEL | `NO_GO` 항목 재정의 금지 | deployable-now | 0 | 게이트 변경 3자 결재 | P0_GATES |
| ITYV-REQ-DEL-005 | KB-DEL-005 | DEL | 사무원·참관인·감사인 교육과 평가 | deployable-now | 0 | 이수증 | — |
| ITYV-REQ-DEL-006 | KB-DEL-006 | DEL | 결함마다 최소 재현 입력·회귀시험 | deployable-now | 0 | 무증빙 종결 차단 | CONSTITUTION §5 |
| ITYV-REQ-DEL-007 | KB-DEL-007 | DEL | 장기 보존 검증기 유지와 알고리즘 수명 책임 | needs-statute | 2 | 책임자 서명 | ADR-0006 |
| ITYV-REQ-DEL-008 | KB-DEL-008 | DEL | 공급자 중립 평가 | deployable-now | 0 | 동등 기능 시험 | LEGAL_ANNEX 11 |
| ITYV-REQ-DEL-009 | KB-DEL-009 | DEL | 개발업체 상시 접근 폐기, 키 통제권은 챔버와 위원회로 | needs-statute | 1 | 외부 계정 차단 | ADR-0012 |

### 1.1 법적 상태 집계

| 법적 상태 | 건수 |
|---|---|
| deployable-now | 103 |
| needs-rule | 25 |
| needs-statute | 25 |

## 2. E2E 계층 신규 요구사항 (37)

| ITYV ID | 도메인 | 요구 | 법적 상태 | 단계 | 수용 시험 | ADR |
|---|---|---|---|---|---|---|
| ITYV-REQ-SCN-001 | SCN | 투함 스캐너는 해석 유닛, 커밋먼트 유닛, 봉인 모듈 세 물리 유닛으로 분할되며 해석 유닛에서 커밋먼트 유닛으로의 링크는 단방향이고 전달 데이터는 양식 ID와 선택 인덱스로 고정된 몇 바이트다 | needs-rule | 2 | 링크 역방향 전송 불가 하드웨어 시험, 전달 스키마 퍼징 | ADR-0005 |
| ITYV-REQ-SCN-002 | SCN | 커밋먼트 유닛은 `no_std`·힙 없음이며 선택, 투함 ID, 난수를 처리 직후 소거하고 어떤 영속 저장소에도 쓰지 않는다 | deployable-now | 2 | V3 증명(무보존), 메모리 덤프 시험 | CONSTITUTION §4.4 |
| ITYV-REQ-SCN-003 | SCN | 투입 전 검증 요청 시 커밋먼트 유닛은 해당 표의 난수와 해석 결과를 `ChallengeOpening` 이벤트로 공개하고 그 표를 `CHALLENGED_SPOILED`로 전이시키며 집계에서 제외한다 | needs-statute | 2 | 공개값으로 커밋먼트 재계산 일치, 폐기 표 집계 제외 | ADR-0005 |
| ITYV-REQ-SCN-004 | SCN | 투함 ID는 봉인 모듈 난수로 투함 시 생성되어 투표지에 각인되고 커밋먼트 안에만 존재하며 발급·확인 장치는 알 수 없다 | needs-statute | 2 | 발급 로그에 투함 ID 부재, 공개 기록에 부재 | ADR-0005 |
| ITYV-REQ-SCN-005 | SCN | 각인 실패·중복 각인·두 장 겹침은 해당 표를 `QUARANTINED`로 보존하고 수량 일치에서 제외하지 않는다 | needs-rule | 2 | 결함 주입 시험 | ITYV-THR-207 |
| ITYV-REQ-SCN-006 | SCN | 투표함 마감 시 종이 수, 각인 수, 투함 기록 수, 검증 폐기 수가 일치해야 하며 어긋나면 `HOLD_REVIEW`다 | needs-statute | 2 | 1건 차이 주입 | ADR-0005 |
| ITYV-REQ-SCN-007 | SCN | 커밋먼트 유닛의 상태기계는 `IDLE → INTERPRETED → DURABLE → IMPRINTED → SLIP_PRINTED → DROPPED`이며 `DURABLE` 전에는 각인·슬립 전이가 타입상 불가능하다 | deployable-now | 2 | trybuild, Kani 상태 불변식 | CONSTITUTION §1.4 |
| ITYV-REQ-SCN-008 | SCN | 검증 실패(공개 난수가 커밋먼트와 불일치)는 스캐너 격리, 예비 교체, 해당 장치 기록 전수 감사를 자동으로 요구하는 이벤트를 만든다 | needs-rule | 2 | 시뮬레이터 시나리오 | ADR-0011 |
| ITYV-REQ-CRY-001 | CRY | 표 커밋먼트는 `C = G_val^{M^v} · G_id^{cast_id} · H^r`(M = 2^26, 9개 선택지 단위 분할)이며 정형성은 1-of-m OR 증명으로 입증된다 | needs-statute | 2 | 알려진 답 벡터, 독립 2차 구현 교차 검증 | ADR-0006 |
| ITYV-REQ-CRY-002 | CRY | 게시판에는 어떤 암호문도 게시하지 않으며 정보이론적으로 숨겨지는 커밋먼트와 증명만 게시한다 | needs-statute | 2 | 스키마 검사, 게시 전 정적 검출 | ADR-0006 |
| ITYV-REQ-CRY-003 | CRY | 여는 값은 챔버 접근구조(X·Y 필수, 6개 중 5개)에 맞는 선형 비밀분산으로 나뉘며 합산 share로 합계만 열린다 | needs-statute | 1 | 접근구조 밖 집합으로 복원 실패, 합계 복원 정확성 | ADR-0006, ADR-0012 |
| ITYV-REQ-CRY-004 | CRY | share 전송은 봉인 모듈 일회용 패드가 기본이고 패드 유도 MAC을 붙이며, 고갈 시 하이브리드 KEM 대체 경로를 쓰되 기록에 `KEM_FALLBACK`을 표기한다 | needs-rule | 2 | 패드 인덱스 단조·재사용 불가 Kani, 대체 경로 표기 확인 | ADR-0006 |
| ITYV-REQ-CRY-005 | CRY | 봉인 모듈은 매 표의 난수 `r`을 생성하고 `SHA3-512(r)`에 서명하며 신뢰기관은 집계 전 share에서 복원한 값과 대조한다 | needs-rule | 2 | 모듈 난수를 쓰지 않은 기록이 대조에서 거부됨 | ITYV-THR-203 |
| ITYV-REQ-CRY-006 | CRY | 모든 서명은 ML-DSA-87과 Ed25519를 둘 다 검증하고, 장기 보존 체크포인트에는 SLH-DSA 추가 서명을 요구한다 | deployable-now | 0 | 한쪽 서명만 유효한 객체 거부 | ADR-0006 |
| ITYV-REQ-CRY-007 | CRY | 투함 기록은 `proof_system_id`를 가지며 genesis의 허용 집합 밖 ID는 거부된다 | deployable-now | 2 | 다운그레이드 거부 | ADR-0006 |
| ITYV-REQ-CRY-008 | CRY | 합계는 투표양식별 `Π C_i`를 열어 26비트 자릿수로 읽고, 9개 선택지를 넘는 양식은 커밋먼트를 분할한다. 자릿수 넘침은 설계상 불가능해야 한다 | needs-statute | 2 | 유권자 수 상한 4,400만 가정의 넘침 검사 Kani | ADR-0006 |
| ITYV-REQ-CRY-009 | CRY | 암호 구현은 검증된 백엔드(libcrux, fiat-crypto 계열)를 쓰고 독립 2차 구현과 차분 테스트한다 | deployable-now | 0 | V5 차분 테스트 | ADR-0007 |
| ITYV-REQ-TRU-001 | TRU | 신뢰기관 키는 선거마다 검증 가능한 분산 키 생성으로 만들고 절차 기록을 장부에 남긴다 | needs-statute | 1 | 절차 기록 검증 | ADR-0012 |
| ITYV-REQ-TRU-002 | TRU | 개별 표의 여는 값 복원은 공개 추첨된 감사 표본과 공개 절차에서만 허용되며 모든 열기는 장부 이벤트다 | needs-statute | 2 | 열기 이벤트 없는 복원 경로 부재 | ADR-0011 |
| ITYV-REQ-TRU-003 | TRU | 인증과 이의 기간 종료 후 share와 선거 키를 공개 파기 절차에서 파기하고 파기 이벤트를 남긴다 | needs-statute | 1 | 파기 이벤트 기한 검사 | ADR-0006 |
| ITYV-REQ-TRU-004 | TRU | 챔버 거부는 암호 계층만 멈추고 종이 개표를 멈추지 않으며 거부 사실을 장부에 기록한다 | needs-statute | 1 | 거부 시나리오에서 종이 절차 계속 | ADR-0012 |
| ITYV-REQ-TRU-005 | TRU | 집계 열기 불일치 시 이분 탐색은 투표함 단위까지만 허용되고 표 단위 열기는 감사 표본 규칙을 따른다 | needs-rule | 2 | 절차 시험 | ITYV-THR-215 |
| ITYV-REQ-PTL-001 | PTL | 모든 투표소에 확인 장치를 두며 확인마다 서명 카운터 이벤트(가명, 15분 구간)를 만들고 50건마다 서로 다른 정당 참관인 둘이 공동 서명한다 | needs-statute | 2 | 공동 서명 누락 시 카운터 검증 실패 | ADR-0009 |
| ITYV-REQ-PTL-002 | PTL | 가명은 봉인 모듈의 선거별 키로만 계산되며 선관위 소프트웨어는 키에 접근할 수 없다 | needs-rule | 2 | 모듈 밖 가명 계산 경로 부재 | ADR-0009 |
| ITYV-REQ-PTL-003 | PTL | 가명 다중집합은 개표 종료 후 시간·순서 없이 공개되고 누구나 중복과 수량 일치를 검증한다 | needs-statute | 2 | 중복 주입 탐지 | ADR-0009 |
| ITYV-REQ-PTL-004 | PTL | 교부·확인·장치 로그 어디에도 투함 ID·추적코드가 가명이나 신원과 함께 기록되지 않는다 | deployable-now | 0 | 카운터·가명 유닛 V3, DLP | ADR-0009 |
| ITYV-REQ-PTL-005 | PTL | 명부 동결 commitment와 투표구별 총수를 선거 전 게시하고 이후 변경은 사유 있는 추가 전용 이벤트다 | needs-rule | 0 | 동결 후 무사유 변경 거부 | ADR-0009 |
| ITYV-REQ-RCV-001 | RCV | 관외·재외 투표지는 투입 전 스캔 후 봉투에 밀봉되며 봉투 라벨은 커밋먼트 유닛이 인쇄하고 공개 기록에 노출되지 않는다 | needs-statute | 2 | 공개 데이터 라벨 부재 | ADR-0010 |
| ITYV-REQ-RCV-002 | RCV | 관할 선관위는 봉투를 열지 않고 라벨만 읽어 `ReceiptMark` 이벤트를 올리며, 신뢰기관은 share에서 복원한 라벨과 대조해 미수령 기록을 `CAST_NOT_RECEIVED`로 공개 집계한다 | needs-statute | 2 | 미수령 주입 시 집계 제외와 공개 | ADR-0010 |
| ITYV-REQ-RCV-003 | RCV | 봉투 개봉은 회차 단위로 라벨 분리 후 투표지를 혼합하며 (봉투, 투표지) 쌍 기록은 금지된다 | needs-rule | 2 | 절차 감사 | ADR-0010 |
| ITYV-REQ-AUD-001 | AUD | 위험제한감사는 기록 우선 표본추출의 표 단위 비교 감사이며 공개 태그로 종이에서 기록을 찾는 경로를 두지 않는다 | needs-statute | 2 | 공개 데이터에 토큰 태그 부재 | ADR-0011 |
| ITYV-REQ-AUD-002 | AUD | 시드는 명세 동결 후 주사위 추첨 기록, 공개 비콘 회차, 최종 체크포인트 해시의 SHA3-512이며 누구나 표본을 재계산한다 | needs-statute | 2 | 재계산 일치 | ADR-0011 |
| ITYV-REQ-DSP-001 | DSP | 슬립은 추적코드·투표소·시간 구간과 커밋먼트 유닛 하이브리드 서명을 담고 장치 키별 발행 수 상한을 둔다 | needs-statute | 3 | 위조 슬립 거부, 상한 초과 탐지 | ADR-0011 |
| ITYV-REQ-DSP-002 | DSP | 유효 서명 슬립의 코드가 게시판에 없으면 해당 투표함은 즉시 `HOLD_REVIEW`이고 분쟁은 선관위와 독립검증위원회가 공동 접수한다 | needs-statute | 3 | 시뮬레이터 분쟁 흐름 | ADR-0011 |
| ITYV-REQ-GOV-010 | GOV | 증인·신뢰기관·위원의 독립성은 추천 기관이 서명한 임명 이벤트로만 인정되며 자기 선언 문자열은 쓰지 않는다 | needs-statute | 1 | 임명 이벤트 없는 서명 거부 | ADR-0012 |
| ITYV-REQ-BRD-001 | BRD | 공개 등급 이벤트는 법정 기한 내 게시판에 공표되고 투함 기록은 추적코드 순으로 정렬되며 기한 초과는 위반 이벤트로 기록된다 | needs-statute | 2 | 기한 검사, 정렬 속성 테스트 | ADR-0003, ITYV-THR-209 |
| ITYV-REQ-BRD-002 | BRD | 법으로 지정된 최소 3개 독립 공개 검증자가 기한 내 검증 결과를 공표한다 | needs-statute | 2 | 공표 기록 | ADR-0012 |
