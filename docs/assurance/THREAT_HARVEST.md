# 위협 수확 등록부 / Threat Harvest Register

> English summary: All 202 K-Ballot threat scenarios re-numbered as ITYV-THR-001..202 with their original IDs, each given a disposition under the ityv design (CLOSED_BY_DESIGN, CHANGED, UNCHANGED, OUT_OF_SCOPE) with the mechanism or ADR that justifies it and the residual risk. A second section lists 28 new threats that the ityv design itself introduces (ITYV-THR-203..230), each with attack path, detection signal, design response, residual risk and the verification level that must evidence the response. Dispositions are design claims, not test results; every CLOSED_BY_DESIGN row still needs the evidence named in VERIFICATION_LADDER.md and P0_GATES.md.

상태: 초안 v0.1 (ADR-0008 수확 계획). 처분은 설계상의 주장이며 시험 결과가 아니다. 어떤 행도 실선거 안전성을 입증하지 않는다.

## 0. 처분 어휘

| 처분 | 뜻 |
|---|---|
| `CLOSED_BY_DESIGN` | ityv 설계의 명시된 메커니즘이 공격 경로를 막거나 탐지 가능하게 만든다. 잔여 위험 열의 조건에서는 여전히 실패할 수 있다 |
| `CHANGED` | 위협은 남지만 공격면·탐지 수단·잔여 위험의 모양이 K-Ballot과 다르다 |
| `UNCHANGED` | 설계가 바뀌어도 같은 수단(물리·절차·거버넌스)으로만 대응한다 |
| `OUT_OF_SCOPE` | ityv에는 해당 구성요소가 없어 위협이 성립하지 않는다. 대체되는 위협이 있으면 신규 위협 절에 적는다 |

## 1. 계승 위협 (ITYV-THR-001..202)

| ITYV ID | 원 ID | 영역 | 요약 | 처분 | 근거 | 잔여 위험 |
|---|---|---|---|---|---|---|
| ITYV-THR-001 | TH-01 | 발급 | 발급 권한 없이 투표지가 교부되어 투함된다 | CHANGED | 사전 발급 credential이 없다. 확인 수·교부 수·투함 기록 수의 3자 일치(ADR-0009 참여 장부, ADR-0005 마감 수량 일치) | 확인 장치·참관인 양 블록이 모두 공모 |
| ITYV-THR-002 | TH-02 | 발급 | 서명 없는 기준정보가 받아들여진다 | CLOSED_BY_DESIGN | genesis는 선관위·독립검증위원회 서명과 증인 정족수 없이는 타입상 존재하지 않음(ADR-0002 capability, ADR-0012) | 대역 외 핀 배포 경로 침해 |
| ITYV-THR-003 | TH-03 | 발급 | 미사용 식별자를 복제해 위조 투표지를 만든다 | CHANGED | 미사용 식별자 자체가 없다. 위조 용지는 수량 3자 일치와 용지 재고 통제로 탐지 | 확인·교부·투함 전 구간 공모 |
| ITYV-THR-004 | TH-04 | 발급 | 식별자 난수가 약해 충돌·추측된다 | CLOSED_BY_DESIGN | 투함 ID는 챔버 모듈 CSPRNG 192비트, 장부에서 유일성 검사(ADR-0005, ADR-0006) | 챔버 모듈 난수 백도어(ITYV-THR-204) |
| ITYV-THR-005 | TH-05 | 발급 | 문자 정규화 차이로 같은 식별자가 다르게 보인다 | CLOSED_BY_DESIGN | 텍스트 식별자가 없다. 정규 이진 인코딩만 허용(ENCODING.md §5) | 감사 시 각인 판독 오류 |
| ITYV-THR-006 | TH-06 | 암호 | 서명키 탈취·백업키 무단 사용 | CHANGED | 하이브리드 서명, 선거별 키, HSM, 챔버 분산(ADR-0006, ADR-0012). 증인 키 탈취는 서명 보류 이상 불가 | 여러 챔버의 키가 동시에 탈취 |
| ITYV-THR-007 | TH-07 | 암호 | 약한 알고리즘으로 강제 협상 | CLOSED_BY_DESIGN | 허용 목록 고정. ML-DSA-87과 Ed25519 둘 다 필요, `proof_system_id` 버전 고정(ADR-0006) | 라이브러리 구현 결함 |
| ITYV-THR-008 | TH-08 | 발급 | 다른 선거구·투표양식의 표가 섞인다 | CLOSED_BY_DESIGN | 투표양식 ID가 투함 기록과 genesis에 결속, 집계는 양식별(ADR-0006) | 해석 유닛의 양식 오분류는 `UNREADABLE`로 보류 |
| ITYV-THR-009 | TH-09 | 발급 | 기준정보 root가 바꿔치기된다 | CLOSED_BY_DESIGN | genesis 대역 외 핀, 공동 서명, 증인 정족수(ADR-0002, ADR-0012) | 핀 배포 경로 침해 |
| ITYV-THR-010 | TH-10 | 현장 | 응답 유실 후 같은 표를 다시 스캔한다 | CHANGED | 이미 각인된 투함 ID는 재투입 시 중복으로 격리, 기록은 바이트 단위 멱등(ADR-0005) | 용지 걸림으로 각인 전 유실 |
| ITYV-THR-011 | TH-11 | 현장 | 조정기 없이 단말이 단독 승인한다 | CHANGED | 조정기 개념이 없다. 커밋먼트 유닛은 내구 기록 전에 슬립을 내지 않으며 모든 승인은 장부 포함 전까지 잠정 | 장치 플래시 손상 |
| ITYV-THR-012 | TH-12 | 현장 | 마감 뒤에도 투입이 받아들여진다 | CLOSED_BY_DESIGN | 투표함 typestate `CLOSED`에서 투입 전이는 컴파일 불가(CONSTITUTION §1.4) | 물리적 재개봉은 보관 위협으로 처리 |
| ITYV-THR-013 | TH-13 | 현장 | 같은 식별자가 두 투표함에서 받아들여진다 | CHANGED | 투함 ID는 장부 전역에서 유일, 중복은 `QUARANTINED`로 양쪽 보존(ADR-0011 자동 무효 금지) | 동기화 전 지역별 선공개 |
| ITYV-THR-014 | TH-14 | 현장 | 종이 없이 기록만 만들어진다 | CLOSED_BY_DESIGN | 마감 시 종이 수 = 각인 수 = 기록 수(ADR-0005), 기록 우선 감사가 종이를 찾음(ADR-0011) | 계수 담당과 참관인 공모는 감사로만 탐지 |
| ITYV-THR-015 | TH-15 | 현장 | 한 장 빼고 한 장 넣어 수량을 유지한다 | CLOSED_BY_DESIGN | 투함 시 커밋먼트가 내용을 봉인, 기록 우선 비교 감사(ADR-0006, ADR-0011) | 감사 집행 방해, 증인 5곳 이상 공모 |
| ITYV-THR-016 | TH-16 | 현장 | 바코드에 URL·명령이 담긴다 | OUT_OF_SCOPE | 텍스트 바코드 입력 경로가 없다. 이미지 입력 공격은 ITYV-THR-219 | — |
| ITYV-THR-017 | TH-17 | 현장 | 현장 웹 UI 스크립트 주입 | OUT_OF_SCOPE | TCB에 웹 UI가 없고 UI 결함은 증거를 바꾸지 못함(CONSTITUTION §0) | — |
| ITYV-THR-018 | TH-18 | 현장 | 외부 웹페이지가 로컬 API를 호출 | OUT_OF_SCOPE | 로컬 HTTP API가 없다 | — |
| ITYV-THR-019 | TH-19 | 현장 | 스캐너 펌웨어가 악성 | CHANGED | 해석 유닛은 불신 전제. 투입 전 검증과 기록 우선 감사로 탐지(ADR-0005) | 검증 빈도가 낮으면 통계적 탐지력 저하 |
| ITYV-THR-020 | TH-20 | 현장 | 시계 조작으로 재생·순서 조작 | CLOSED_BY_DESIGN | TCB에 벽시계 없음, 순번·이전 해시가 순서 정의, 시간은 15분 구간 참고값(ADR-0009) | 법적 사건 시각 판단은 별도 |
| ITYV-THR-021 | TH-21 | 현장 | 장치 저널 마지막 기록 삭제·되감기 | CLOSED_BY_DESIGN | 장부 외부 앵커·증인 체크포인트·유권자 슬립이 분산 앵커 역할(ADR-0011) | 장부 업로드 전 장치 단독 상태에서는 슬립만이 증거 |
| ITYV-THR-022 | TH-22 | 현장 | 기록 뒤 내구 저장 실패 | CHANGED | 커밋먼트 유닛은 내구 기록 성공 전 슬립 인쇄·각인 명령을 내지 않음(V3 증명 대상) | 플래시 마모·전원 차단 하드웨어 시험 필요 |
| ITYV-THR-023 | TH-23 | 현장 | 같은 이벤트 ID에 다른 내용 | CLOSED_BY_DESIGN | 장부 멱등성은 바이트 동일성 기준(ityv-ledger) | — |
| ITYV-THR-024 | TH-24 | 현장 | 순번 누락·역전 | CLOSED_BY_DESIGN | 발행자별 단조 순번과 이전 해시(ENCODING.md, ityv-ledger) | — |
| ITYV-THR-025 | TH-25 | 서버 | 재시작 시 중앙 상태 소실 | CLOSED_BY_DESIGN | 권위 있는 메모리 상태가 없다. 장부는 파일 기반 프레임 로그 | — |
| ITYV-THR-026 | TH-26 | 서버 | 복제본 경쟁으로 중복 승인 | CLOSED_BY_DESIGN | 선거별 단일 작성자 장부, 발행자별 순번 | 다중 작성자 설계는 P0-13 |
| ITYV-THR-027 | TH-27 | 서버 | 중복 중 첫 표만 인정하고 흔적 삭제 | CLOSED_BY_DESIGN | 양쪽 모두 보존, `HOLD_REVIEW`, 자동 무효 금지(ADR-0011) | — |
| ITYV-THR-028 | TH-28 | 서버 | 발급·사용 회계 불일치 | CHANGED | 참여 장부의 서명 카운터와 투함 기록 수의 공개 대조(ADR-0009) | 양 출처 공모 |
| ITYV-THR-029 | TH-29 | 서버 | 위조 마감 보고 | CLOSED_BY_DESIGN | 장치 하이브리드 서명 + 서로 다른 조직 참관인 2 서명(ADR-0010) | 키 탈취·참관인 공모 |
| ITYV-THR-030 | TH-30 | 서버 | 누락 투표함을 빼고 확정 | CLOSED_BY_DESIGN | genesis 예상 투표함 전수 대조, `SOURCE_COMPLETENESS_CHECKED` | genesis 자체의 누락은 명부 열람으로 |
| ITYV-THR-031 | TH-31 | 서버 | 관리자가 기록을 수정·삭제 | CLOSED_BY_DESIGN | UPDATE/DELETE 경로 없음, 정정은 추가 이벤트 | — |
| ITYV-THR-032 | TH-32 | 서버 | 대량 요청으로 공개 서비스 마비 | CHANGED | 공개원장은 서명된 정적 청크, 가용성은 보장 대상 아님(ADR-0004) | 공개 지연이 신뢰 훼손으로 이어질 수 있음 |
| ITYV-THR-033 | TH-33 | 미러 | 미러가 위조 root를 공개 | CHANGED | 모든 미러는 불신, 검증은 클라이언트 측 서명 검사(ADR-0003) | 사용자가 검증기를 쓰지 않음 |
| ITYV-THR-034 | TH-34 | 미러 | 로그 일부 삭제·재기록 | CLOSED_BY_DESIGN | Merkle 일관성 증명과 증인 체크포인트 | — |
| ITYV-THR-035 | TH-35 | 미러 | 서로 다른 집단에 다른 root 제시 | CLOSED_BY_DESIGN | 증인 1시퀀스 1헤드 정책, 가십, 슬립(ADR-0012) | 증인 5곳 이상 공모(ITYV-THR-210) |
| ITYV-THR-036 | TH-36 | 미러 | 오래된 체크포인트만 반복 제공 | CLOSED_BY_DESIGN | 단조 증가와 신선도, 다중 채널 비교 | 전면 통신 두절 |
| ITYV-THR-037 | TH-37 | 미러 | 단일 클라우드 장애·검열 | UNCHANGED | 누구나 미러 운영, 오프라인 배포 | 전국 검열 |
| ITYV-THR-038 | TH-38 | 미러 | 큐 재전송 순서 뒤섞임 | OUT_OF_SCOPE | 큐 전송 계층이 TCB 밖이며 장부 순서는 내용 주소로 정해짐 | — |
| ITYV-THR-039 | TH-39 | 미러 | 서명 검증 없이 확정 표시 | CLOSED_BY_DESIGN | 검증 결과는 타입, 상태 어휘 자동 전환 금지(CONSTITUTION §5.3) | — |
| ITYV-THR-040 | TH-40 | 미러 | 증인이 사실상 한 조직·클라우드 | UNCHANGED | 다양성 요건과 추천 기관 서명 임명 이벤트(ADR-0012) | 실소유 위장 |
| ITYV-THR-041 | TH-41 | 개인정보 | 카메라·로그 시각 상관으로 참여자 추론 | CHANGED | 투함 기록에 시각 없음, 확인은 15분 구간, 게시는 추적코드 순 정렬(ADR-0009, ITYV-THR-209) | 현장 육안 관찰 |
| ITYV-THR-042 | TH-42 | 개인정보 | 개별 식별자 조회로 참여 추적 | CHANGED | 조회 API 없음, 추적코드는 해시, 검증은 로컬 다운로드(ADR-0011) | 유권자가 코드를 스스로 공개 |
| ITYV-THR-043 | TH-43 | 개인정보 | 영수증이 후보 선택을 증명 | CLOSED_BY_DESIGN | 커밋먼트 무조건적 숨김, 개별 여는 값 미제공, 검증 표는 폐기(ADR-0001, ADR-0006) | 은닉 채널(ITYV-THR-203) |
| ITYV-THR-044 | TH-44 | 개인정보 | 소규모 집계로 재식별 | CHANGED | 합계만 열림, 최소 집계 단위 규칙(ADR-0006) | 극소 투표구 |
| ITYV-THR-045 | TH-45 | 개인정보 | 운영 로그에 원시 식별자 출력 | CLOSED_BY_DESIGN | 커밋먼트 유닛 무보존 성질 V3 증명(CONSTITUTION §4.4) | 해석 유닛의 이미지 보존(ITYV-THR-222) |
| ITYV-THR-046 | TH-46 | 개인정보 | 운영 노트북 악성코드 | CHANGED | TCB에 범용 노트북 없음, 장치 봉인·측정 부팅 | 챔버 모듈·장치 공급망 |
| ITYV-THR-047 | TH-47 | 감사 | 집계값은 두고 종이 내용을 바꾼다 | CLOSED_BY_DESIGN | ITYV-THR-015와 동일 | 감사 방해 |
| ITYV-THR-048 | TH-48 | 감사 | 예외를 일괄 승인 | CLOSED_BY_DESIGN | HOLD 해제는 독립검증위원회 공동 결정, 추가 전용 기록(ADR-0011) | 선관위·위원회 공모 |
| ITYV-THR-049 | TH-49 | 감사 | 정전·분리망 | CHANGED | 커밋먼트 유닛은 오프라인 동작, 확정은 보류(ADR-0004 가용성) | 장기 정전 |
| ITYV-THR-050 | TH-50 | 감사 | 표본 난수 조작 | CLOSED_BY_DESIGN | 3출처 시드(ADR-0011) | 세 출처 동시 침해 |
| ITYV-THR-051 | TH-51 | 감사 | 배포 소프트웨어 교체 | CHANGED | 재현 이중 빌드, 서명 펌웨어, 선거 중 변경 금지(CONSTITUTION §3) | 빌드 체인 공모 |
| ITYV-THR-052 | TH-52 | 감사 | 독립 시험 없이 실선거 사용 | UNCHANGED | P0 게이트 전부 통과 전 `NO_GO` | 정치적 압력 |
| ITYV-THR-053 | ST-01 | 표 교체 | 같은 수량으로 기표 내용 전체 교체 | CLOSED_BY_DESIGN | 투함 시 커밋먼트 + 기록 우선 감사 | 감사 미집행 |
| ITYV-THR-054 | ST-02 | 표 교체 | 투표함 통째 교체 | CLOSED_BY_DESIGN | genesis 인벤토리, 투표함 ID 결속 기록, 감사 시 종이·기록 불일치(ADR-0010) | 봉인 위조와 감사 방해 결합 |
| ITYV-THR-055 | ST-03 | 표 교체 | 운송 전 선별 교체 | CLOSED_BY_DESIGN | 커밋먼트가 보관 사슬보다 먼저 생성 | 투입 전 유권자 수중 교체는 자기 표에 한정 |
| ITYV-THR-056 | ST-04 | 표 교체 | 이동 중 교체·봉인 재부착 | CLOSED_BY_DESIGN | 이중 서명 인계 + 커밋먼트 대조(ADR-0010) | 감사 표본 밖 소규모 교체는 위험 한도 내 |
| ITYV-THR-057 | ST-05 | 표 교체 | 식별 스트립을 분리한 뒤 교체 | CLOSED_BY_DESIGN | 분리형 스트립이 없다. 투함 ID는 종이에 각인되고 커밋먼트에 결속 | — |
| ITYV-THR-058 | ST-06 | 표 교체 | 묶음 사이 동일 수량 교체 | CLOSED_BY_DESIGN | 기록 우선 감사 | 위험 한도 |
| ITYV-THR-059 | ST-07 | 표 교체 | 배치 재편성으로 일부 격리 | CLOSED_BY_DESIGN | genesis 인벤토리 전수 대조 | — |
| ITYV-THR-060 | ST-08 | 표 교체 | 수검표 전 위조 내용을 디지털 스캔 | CHANGED | 개표 스캔 이미지는 권위 없음. 종이와 투함 시 커밋먼트만 증거 | 개표 스캐너 오독은 수검표로 |
| ITYV-THR-061 | ST-09 | 기표 훼손 | 투표지에 추가 인쇄·도장 | CLOSED_BY_DESIGN | 추가 표식은 투함 시 커밋먼트와 불일치해 감사에서 드러남 | 해석 유닛의 모호 표 처리(ITYV-THR-221) |
| ITYV-THR-062 | ST-10 | 기표 훼손 | 무효표를 유효로 오판하게 조작 | CHANGED | 판정은 사람. 커밋먼트의 잠정 해석이 대조 증거 | 판정 기준 불균등은 절차 |
| ITYV-THR-063 | ST-11 | 기표 훼손 | 이미지 편집 뒤 원본으로 제시 | CHANGED | 이미지는 증거 지위 없음 | — |
| ITYV-THR-064 | ST-12 | 표 제거 | 일부 정상표 미입력·파쇄 | CLOSED_BY_DESIGN | 확인 수·교부 수·기록 수·종이 수 불일치는 `HOLD_REVIEW` | 전 구간 공모 |
| ITYV-THR-065 | ST-13 | 표 제거 | 배치 전체를 집계에서 배제 | CLOSED_BY_DESIGN | genesis 예상 투표함 전수 | — |
| ITYV-THR-066 | ST-14 | 표 추가 | 미사용 식별자로 대량 삽입 | CHANGED | 사전 식별자 없음. 확인 수와 기록 수 불일치로 탐지 | 확인 장치와 참관인 공모 |
| ITYV-THR-067 | ST-15 | 표 추가 | 식별자 복제 | CHANGED | 투함 ID 중복은 장부에서 격리 | 각인기 결함(ITYV-THR-207) |
| ITYV-THR-068 | ST-16 | 자격 | 명부 부정확·무자격 참여 | CHANGED | 명부 동결 commitment, 열람, 투표소별 서명 수량(ADR-0009). 암호로는 막지 못함 | 명부 작성 단계 조작 |
| ITYV-THR-069 | ST-17 | 자격 | 같은 사람이 두 곳에서 투표 | CLOSED_BY_DESIGN | 가명 다중집합 중복 검사(ADR-0009) | 가명 모듈 침해 |
| ITYV-THR-070 | ST-18 | 자격 | 보조 투표 악용 | UNCHANGED | 절차·참관 | — |
| ITYV-THR-071 | ST-19 | 자격 | 재발급 오류로 중복 교부 | CHANGED | 교부·훼손·취소 상태기계와 참여 장부 대조 | — |
| ITYV-THR-072 | ST-20 | 자격 | 우편·거소 중복 인정 | CLOSED_BY_DESIGN | 모든 경로가 같은 가명 공간(ADR-0009, ADR-0013) | `RECEIPT_SCAN` 경로의 발급 시점 가명 기록 품질 |
| ITYV-THR-073 | ST-21 | 인쇄 | 용지 추가 인쇄 | CHANGED | 재고 통제 + 수량 3자 일치 | 인쇄소 내부자 |
| ITYV-THR-074 | ST-22 | 인쇄 | 잘못된 후보 순서·양식 | CHANGED | genesis 투표양식 해시, 선거 전 논리·정확성 시험 | 현장 교부 오류 |
| ITYV-THR-075 | ST-23 | 인쇄 | 판독 교란 인쇄 | CHANGED | `UNREADABLE` 커밋먼트와 수검표 | — |
| ITYV-THR-076 | ST-24 | 인쇄 | 악성 QR 페이로드 | OUT_OF_SCOPE | QR 입력 없음. 이미지 공격은 ITYV-THR-219 | — |
| ITYV-THR-077 | ST-25 | 물리 | 카메라가 기표 방향 촬영 | UNCHANGED | 가림 봉투, CCTV 구도 규칙(ADR-0010) | — |
| ITYV-THR-078 | ST-26 | 물리 | 봉인 사진 복제로 인계 조작 | CHANGED | 봉인 해시가 이중 서명 인계에 결속 | 봉인 자체 위조 |
| ITYV-THR-079 | ST-27 | 물리 | 참관인 둘이 사실상 같은 조직 | CLOSED_BY_DESIGN | 추천 기관 서명 임명 이벤트(ADR-0012) | 추천 기관 공모 |
| ITYV-THR-080 | ST-28 | 물리 | 영상 저장장치 동시 손상 | CHANGED | 구간 해시 앵커로 공백이 드러남 | 영상 자체 손실 |
| ITYV-THR-081 | ST-29 | 물리 | 임의 개봉 후 재봉인 | UNCHANGED | 개봉 이벤트 의무, `HOLD_REVIEW` | — |
| ITYV-THR-082 | ST-30 | 물리 | 증인 매수 | UNCHANGED | 다조직·챔버 분산 | — |
| ITYV-THR-083 | ST-31 | 개표 | 수검표와 스캐너 불일치 | CHANGED | 종이가 법적 결과, 커밋먼트는 증거(ADR-0011) | — |
| ITYV-THR-084 | ST-32 | 개표 | 같은 종이를 두 번 집계 | CLOSED_BY_DESIGN | 투함 ID 유일성, 계수 세션 고정 | — |
| ITYV-THR-085 | ST-33 | 개표 | 잘못된 선거구에 배정 | CLOSED_BY_DESIGN | 투표양식별 집계, 양식 ID 결속 | 양식 오분류 보류 |
| ITYV-THR-086 | ST-34 | 개표 | 무효·기권 조합으로 수량 맞춤 | CHANGED | `BLANK`·`UNREADABLE`도 커밋먼트, 수량 일치 | 분류 남용(ITYV-THR-221) |
| ITYV-THR-087 | ST-35 | 개표 | 판독 알고리즘 편향 | CHANGED | 투입 전 검증, 감사, 논리·정확성 시험 | 편향이 검증 미대상 표에 집중 |
| ITYV-THR-088 | ST-36 | 개표 | 종료 전 집계 노출 | CLOSED_BY_DESIGN | 합계는 신뢰기관 챔버가 선거 후에만 엶 | 해석 유닛 누출(ITYV-THR-222) |
| ITYV-THR-089 | ST-37 | 감사 | 감사 대상 종이가 이미 교체됨 | CLOSED_BY_DESIGN | 기준선이 투함 시 생성 | 증인 공모로 공개원장 재작성 |
| ITYV-THR-090 | ST-38 | 감사 | 표본 난수 예측 | CLOSED_BY_DESIGN | 3출처 시드 | — |
| ITYV-THR-091 | ST-39 | 감사 | 감사 범위 과장 | UNCHANGED | 감사 이벤트에 범위 명시 | — |
| ITYV-THR-092 | ST-40 | 감사 | 불일치에도 자동 인증 | CLOSED_BY_DESIGN | 타입화된 상태, `HOLD_REVIEW` | — |
| ITYV-THR-093 | ST-41 | 감사 | 의혹만으로 인증 전면 정지 | CHANGED | 서명 슬립 필터, 증거 기준, 투표함 단위 HOLD(ADR-0011) | 대량 허위 신고 |
| ITYV-THR-094 | ST-42 | 암호 | 기표 이미지 해시 공개로 추적 | CLOSED_BY_DESIGN | 해시·암호문 어떤 것도 게시하지 않음. 커밋먼트만(ADR-0006) | — |
| ITYV-THR-095 | ST-43 | 암호 | 영수증에 후보 정보·예측 가능 난수 | CLOSED_BY_DESIGN | 챔버 모듈 난수와 해시 서명 대조 | 은닉 채널(ITYV-THR-203) |
| ITYV-THR-096 | ST-44 | 암호 | 공개 순서와 입장 시각 상관 | CLOSED_BY_DESIGN | 시각 없음, 추적코드 순 정렬 게시, 종료 후 일괄 공개 | 현장 관찰 |
| ITYV-THR-097 | ST-45 | 암호 | 서명 미검증 유효 표시 | CLOSED_BY_DESIGN | 타입화된 검증 결과 | — |
| ITYV-THR-098 | ST-46 | 암호 | 증인이 한 공급자에 종속 | UNCHANGED | 다양성 요건 | — |
| ITYV-THR-099 | ST-47 | 암호 | 로그 일관성을 종이 진정성으로 오인 | CLOSED_BY_DESIGN | 상태 어휘 분리 의무 | — |
| ITYV-THR-100 | ST-48 | 암호 | 체크포인트 분기·되감기 | CLOSED_BY_DESIGN | 증인 1헤드 정책, 모니터, 슬립 | 증인 5곳 이상 |
| ITYV-THR-101 | ST-49 | 네트워크 | 공개 미러 장애 | UNCHANGED | 가용성 비보장 | — |
| ITYV-THR-102 | ST-50 | 네트워크 | 로컬 API 재바인딩 | OUT_OF_SCOPE | 로컬 API 없음 | — |
| ITYV-THR-103 | ST-51 | 네트워크 | 오류를 성공으로 오인 | CLOSED_BY_DESIGN | typestate: 내구 기록 없이 슬립 상태로 전이 불가 | — |
| ITYV-THR-104 | ST-52 | DB | 전역 중복이 샤드로 갈라짐 | CLOSED_BY_DESIGN | 선거별 단일 장부 | 규모(P0-04) |
| ITYV-THR-105 | ST-53 | DB | 스냅샷 복원으로 되감기 | CLOSED_BY_DESIGN | 외부 앵커·증인·슬립 | — |
| ITYV-THR-106 | ST-54 | DB | 수동 SQL 수정 | CLOSED_BY_DESIGN | 조회 DB는 폐기 가능한 투영 | — |
| ITYV-THR-107 | ST-55 | 접근성 | 접근 장애로 배제 | UNCHANGED | BMD 접근 경로, 수작업 대체 | — |
| ITYV-THR-108 | ST-56 | 운영 | 법정 양식·절차 위반 | CLOSED_BY_DESIGN | 법적 승인 객체 없이는 L1 모듈 활성화 불가(ADR-0002) | 승인 객체 위조(ITYV-THR-224) |
| ITYV-THR-109 | ST-57 | 운영 | 허위 장애 알림 | UNCHANGED | 증거 기준 | — |
| ITYV-THR-110 | ST-58 | 운영 | 악성 업데이트 | CHANGED | CONSTITUTION §3 | 빌드 체인 공모 |
| ITYV-THR-111 | ST-59 | 운영 | 공개 데이터에 개인정보 삽입 | CLOSED_BY_DESIGN | 정규 인코딩에 문자열 필드가 없음 | 식별자 필드에 부호화 시도는 길이·알파벳 제한으로 축소 |
| ITYV-THR-112 | ST-60 | 운영 | UI가 참여 확인을 선택 확인으로 과장 | UNCHANGED | 상태 어휘 | — |
| ITYV-THR-113 | KR-01 | 관외 | 관외 개함에 참관 없음 | CHANGED | 개함은 서로 다른 조직 이중 서명 이벤트(ADR-0010) | 양 조직 공모 |
| ITYV-THR-114 | KR-02 | 관외 | 인계 수량 조작 | CLOSED_BY_DESIGN | 3중 대조 + 투함 기록 수 | 전 구간 공모 |
| ITYV-THR-115 | KR-03 | 관외 | 우편 중 분실 | CHANGED | `CAST_NOT_RECEIVED` 공개 집계 | 분실 자체는 막지 못함 |
| ITYV-THR-116 | KR-04 | 관외 | 봉투 중복 | CHANGED | 봉투 라벨 유일성 대조(신뢰기관) | — |
| ITYV-THR-117 | KR-05 | 관외 | 야간 무단 개봉 | CHANGED | 일방향 카세트, CCTV 해시 앵커 | 센서·카메라 동시 침해 |
| ITYV-THR-118 | KR-06 | 관외 | 정당한 야간 접수 오인 | UNCHANGED | 접수 이벤트가 입회·회차를 기록 | — |
| ITYV-THR-119 | KR-07 | 관외 | 봉인번호 바꿔치기 | CHANGED | 봉인 해시 결속 인계 | 봉인 위조 |
| ITYV-THR-120 | KR-08 | 관외 | 카세트 분실 | CHANGED | 인벤토리 | — |
| ITYV-THR-121 | KR-09 | 관외 | 발송 합계 조작 | CHANGED | 독립 집계 + 기록 수 | — |
| ITYV-THR-122 | KR-10 | 관외 | 도착 봉투 미등록 | CLOSED_BY_DESIGN | 라벨 대조로 미수령 기록이 드러남 | 수령 표기 고의 누락(ITYV-THR-223) |
| ITYV-THR-123 | KR-11 | 관외 | 경로 혼합 | CLOSED_BY_DESIGN | 수집 프로필과 투표함별 보관 경로 | — |
| ITYV-THR-124 | KR-12 | 관외 | 등기 ID 공개 유출 | CLOSED_BY_DESIGN | 라벨은 공개 기록에 없음 | 수령처 내부 유출(ITYV-THR-222) |
| ITYV-THR-125 | KR-13 | 관외 | 기표지 사진 유출 | UNCHANGED | 가림 봉투·CCTV 구도 | — |
| ITYV-THR-126 | KR-14 | 관외 | 동일 수량 교체 | CLOSED_BY_DESIGN | ITYV-THR-053 | — |
| ITYV-THR-127 | KR-15 | 관외 | 묶음 모양 오인 | UNCHANGED | 법과학 | — |
| ITYV-THR-128 | KR-16 | 관외 | 인쇄 겹침 오인 | UNCHANGED | 법과학 | — |
| ITYV-THR-129 | KR-17 | 관외 | CCTV 녹화 누락 | CHANGED | 구간 해시 공백 탐지 | — |
| ITYV-THR-130 | KR-18 | 관외 | 카세트 과다 적재 | UNCHANGED | 용량 임계 새 카세트 | — |
| ITYV-THR-131 | KR-19 | 관외 | 법정 기한 지연 | CHANGED | 수령 표기 시간 구간 + 법적 판정 분리 | — |
| ITYV-THR-132 | KR-20 | 관외 | 이의 봉투 무단 폐기 | CHANGED | 라벨 대조로 폐기가 미수령으로 드러남 | — |
| ITYV-THR-133 | V7-001 | 자격 | 탈취된 확인 장치가 투표 완료로 표기 | CHANGED | 서명 카운터, 키 폐기, 참관인 공동 서명(ADR-0009) | 참관인 공모 |
| ITYV-THR-134 | V7-002 | 자격 | 중복 등재 | UNCHANGED | 명부 동결·열람 | — |
| ITYV-THR-135 | V7-003 | 자격 | 명부 갱신 후 누락 | CHANGED | 추가 전용 변경 이벤트 | — |
| ITYV-THR-136 | V7-004 | 자격 | 내부자 자격 사유 수정 | CHANGED | 추가 전용 사유 기록 | — |
| ITYV-THR-137 | V7-005 | 자격 | 투표소 장애로 대기 불평등 | UNCHANGED | 운영 | — |
| ITYV-THR-138 | V7-006 | 자격 | 확인 대기열 사생활 | CHANGED | 15분 구간 | 육안 |
| ITYV-THR-139 | V7-007 | 발급 | 약한 난수 | CHANGED | 챔버 모듈 + 해시 서명 + 신뢰기관 대조 | 모듈 백도어 |
| ITYV-THR-140 | V7-008 | 발급 | 인쇄 일련번호가 신원과 결합 | CLOSED_BY_DESIGN | 투함 ID는 투함 시 생성, 발급기는 알 수 없음(ADR-0005) | 기존 법정 일련번호는 기록에 넣지 않음 |
| ITYV-THR-141 | V7-009 | 발급 | 프린터 미세 표식 | UNCHANGED | 법과학 점검 | — |
| ITYV-THR-142 | V7-010 | 발급 | 열전사 인쇄 퇴색 | CHANGED | 각인 내구성 요구사항 | — |
| ITYV-THR-143 | V7-011 | 발급 | 잘못된 양식 배부 | CHANGED | ITYV-THR-074 | — |
| ITYV-THR-144 | V7-012 | 발급 | 공백 용지 재고 실종 | UNCHANGED | 재고 통제 | — |
| ITYV-THR-145 | V7-013 | 발급 | 훼손표 재스캔 중복 | CLOSED_BY_DESIGN | `CHALLENGED_SPOILED` 상태, 각인 ID 유일 | — |
| ITYV-THR-146 | V7-014 | 발급 | 대량 무단 인쇄 | CHANGED | 수량 3자 일치 | — |
| ITYV-THR-147 | V7-015 | 종이 | 정상 발급표의 동일 수량 교체 | CLOSED_BY_DESIGN | ITYV-THR-053 | — |
| ITYV-THR-148 | V7-016 | 종이 | 수량 변동 없이 기표 변경 | CLOSED_BY_DESIGN | 커밋먼트 대조 | — |
| ITYV-THR-149 | V7-017 | 종이 | 동일 외형 용기 교체 | CLOSED_BY_DESIGN | ITYV-THR-054 | — |
| ITYV-THR-150 | V7-018 | 종이 | 봉인 위조 | UNCHANGED | 봉인 규격 | — |
| ITYV-THR-151 | V7-019 | 종이 | 영상 공백 전 미기록 인계 | CHANGED | 해시 앵커 공백 탐지 | — |
| ITYV-THR-152 | V7-020 | 종이 | 구겨진 표 오독 | CHANGED | `UNREADABLE` | — |
| ITYV-THR-153 | V7-021 | 종이 | 완벽한 묶음의 위조표 | CHANGED | 수량 + 감사 | — |
| ITYV-THR-154 | V7-022 | 종이 | 배치 라벨 뒤바뀜 | CHANGED | 인벤토리 | — |
| ITYV-THR-155 | V7-023 | 종이 | 스트립이 다른 표와 분리 | CLOSED_BY_DESIGN | 스트립 없음 | — |
| ITYV-THR-156 | V7-024 | 종이 | 검사 중 표 파손 | UNCHANGED | 보존 절차 | — |
| ITYV-THR-157 | V7-025 | 장치 | 키보드 웨지 제어문자 | OUT_OF_SCOPE | HID 입력 없음 | — |
| ITYV-THR-158 | V7-026 | 장치 | QR에 실행 URL | OUT_OF_SCOPE | — | — |
| ITYV-THR-159 | V7-027 | 장치 | 유니코드 동형문자 | OUT_OF_SCOPE | 이진 인코딩 | — |
| ITYV-THR-160 | V7-028 | 장치 | 펌웨어가 특정 기표를 누락 | CHANGED | 투입 전 검증 + 감사로 탐지 | 검증 표본 수 |
| ITYV-THR-161 | V7-029 | 장치 | 인증 후 펌웨어 변경 | CHANGED | 측정 부팅, 서명 펌웨어 | 루트 신뢰 침해 |
| ITYV-THR-162 | V7-030 | 장치 | DMA 주변장치 | CHANGED | 외부 DMA 없음, 분할 하드웨어 | — |
| ITYV-THR-163 | V7-031 | 장치 | 전원 글리치 찢긴 기록 | CHANGED | 커밋먼트 유닛 내구 기록 규칙 | — |
| ITYV-THR-164 | V7-032 | 장치 | 메모리 비트플립 | CHANGED | 뒤집힌 커밋먼트는 증명 검증에 실패해 `QUARANTINED`, ECC | — |
| ITYV-THR-165 | V7-033 | 장치 | 시계 되감기 | CLOSED_BY_DESIGN | 시계 없음 | — |
| ITYV-THR-166 | V7-034 | 장치 | 희미한 표식을 공백으로 | CHANGED | `UNREADABLE`, 수검표 | — |
| ITYV-THR-167 | V7-035 | 장치 | 자동 반복으로 이중 계수 | CLOSED_BY_DESIGN | 투함 ID 유일 | — |
| ITYV-THR-168 | V7-036 | 저장 | 복제본 경쟁 | CLOSED_BY_DESIGN | 단일 작성자 | — |
| ITYV-THR-169 | V7-037 | 저장 | 오래된 스냅샷 재생 | CLOSED_BY_DESIGN | 앵커·증인·슬립 | — |
| ITYV-THR-170 | V7-038 | 저장 | 복원이 미전송 기록 폐기 | CHANGED | 장치 저널과 슬립이 증거 | — |
| ITYV-THR-171 | V7-039 | 저장 | 부분 업로드를 완전한 증거로 제공 | CLOSED_BY_DESIGN | 내용 주소 청크 + 체크포인트 | — |
| ITYV-THR-172 | V7-040 | 저장 | 커밋과 전송 사이 전원 손실 | CHANGED | 단일 내구 기록 후 전송, 멱등 재전송 | — |
| ITYV-THR-173 | V7-041 | 저장 | 디스크 가득 참 | UNCHANGED | 용량 설계 | — |
| ITYV-THR-174 | V7-042 | 저장 | 보존 정책이 분쟁 기록 삭제 | CLOSED_BY_DESIGN | 추가 전용, WORM | — |
| ITYV-THR-175 | V7-043 | 네트워크 | 증인이 두 root에 서명 | CLOSED_BY_DESIGN | 1헤드 정책, 공개 책임 | 5곳 이상 공모 |
| ITYV-THR-176 | V7-044 | 네트워크 | 일부 미러에만 오래된 체크포인트 | UNCHANGED | 가십 | 장기 분할 |
| ITYV-THR-177 | V7-045 | 네트워크 | CDN 캐시 오염 | CLOSED_BY_DESIGN | 클라이언트 서명 검증 | 사용자 오인 |
| ITYV-THR-178 | V7-046 | 네트워크 | DNS·BGP 우회 | CLOSED_BY_DESIGN | 핀 고정 키 | — |
| ITYV-THR-179 | V7-047 | 네트워크 | 큐 재정렬 | OUT_OF_SCOPE | — | — |
| ITYV-THR-180 | V7-048 | 네트워크 | 미러 상태 되감기 | OUT_OF_SCOPE | 특정 제품 구성요소 없음 | — |
| ITYV-THR-181 | V7-049 | 네트워크 | 보존 규칙이 헤드 삭제 | CHANGED | 다중 독립 보관소 | — |
| ITYV-THR-182 | V7-050 | 네트워크 | 조회 API로 시각 연결 | CLOSED_BY_DESIGN | 개별 조회 API 없음 | — |
| ITYV-THR-183 | V7-051 | 네트워크 | 미러 장애가 스캔들로 | UNCHANGED | 상태 공개 | — |
| ITYV-THR-184 | V7-052 | 네트워크 | 미러가 비공개 표 유출 | CLOSED_BY_DESIGN | 어떤 미러에도 비공개 표가 존재하지 않음 | — |
| ITYV-THR-185 | V7-053 | 암호 | 키 교체로 신뢰 앵커 바꿔치기 | CLOSED_BY_DESIGN | genesis 공동 서명·핀 | — |
| ITYV-THR-186 | V7-054 | 암호 | 서명 다운그레이드 | CLOSED_BY_DESIGN | ITYV-THR-007 | — |
| ITYV-THR-187 | V7-055 | 암호 | 비정규 JSON | CLOSED_BY_DESIGN | 이진 정규 인코딩 | — |
| ITYV-THR-188 | V7-056 | 암호 | 서명기 부채널 | UNCHANGED | HSM | — |
| ITYV-THR-189 | V7-057 | 암호 | 난수기 재사용 | CHANGED | 장치별 챔버 모듈, 신뢰기관 대조 | — |
| ITYV-THR-190 | V7-058 | 암호 | 다른 선거 식별자 재사용 | CLOSED_BY_DESIGN | 모든 객체 첫 필드가 선거 ID | — |
| ITYV-THR-191 | V7-059 | 암호 | 한 조직의 정족수 | CHANGED | 임명 이벤트 | — |
| ITYV-THR-192 | V7-060 | 암호 | 불리언 검증 필드 | CLOSED_BY_DESIGN | 타입화된 결과 | — |
| ITYV-THR-193 | V7-061 | 감사 | 중복 주입으로 정상표 거부 유도 | CLOSED_BY_DESIGN | 자동 무효 금지 원칙 | — |
| ITYV-THR-194 | V7-062 | 감사 | 결과를 본 뒤 표본 선정 | CLOSED_BY_DESIGN | 명세 동결 후 시드 | — |
| ITYV-THR-195 | V7-063 | 감사 | 판정 기준 불균등 | UNCHANGED | 절차 | — |
| ITYV-THR-196 | V7-064 | 감사 | 접근성 장치가 기표 양식 변경 | CHANGED | BMD 출력도 같은 스캐너 통과 | — |
| ITYV-THR-197 | V7-065 | 감사 | 사건 확대가 투표를 무기한 봉쇄 | CHANGED | 투표함 단위 HOLD, 종이 절차 계속 | — |
| ITYV-THR-198 | V7-066 | 감사 | 맥락 없는 영상 유포 | UNCHANGED | 보관 타임라인 공개 | — |
| ITYV-THR-199 | V7-067 | 감사 | 부당 거부에 이의 불가 | CHANGED | 분쟁 흐름과 기한(ADR-0011) | — |
| ITYV-THR-200 | V7-068 | 감사 | 조기 투표구 총계 공개 | CLOSED_BY_DESIGN | 합계는 선거 후 챔버만 엶 | — |
| ITYV-THR-201 | V7-069 | 감사 | 기준선 전 동일 수량 교체 | CLOSED_BY_DESIGN | 기준선이 투함 시 | — |
| ITYV-THR-202 | V7-070 | 감사 | 식별자만으로 집계 보장 주장 | CLOSED_BY_DESIGN | 상태 어휘 | — |

### 1.1 처분 집계

| 처분 | 건수 |
|---|---|
| CLOSED_BY_DESIGN | 91 |
| CHANGED | 70 |
| UNCHANGED | 30 |
| OUT_OF_SCOPE | 11 |

## 2. ityv 설계가 새로 만드는 위협 (ITYV-THR-203..230)

각 행의 "검증 수단"은 설계 대응이 실제로 작동한다는 증거를 어느 사다리 단계가 내야 하는지를 뜻한다. 증거가 없으면 해당 대응은 주장일 뿐이다.

| ITYV ID | 영역 | 위협 | 공격 경로 | 탐지 신호 | 설계 대응 | 잔여 위험 | 검증 수단 |
|---|---|---|---|---|---|---|---|
| ITYV-THR-203 | 스캐너 | 커밋먼트 난수에 선택을 실어 흘리는 은닉 채널 | 커밋먼트 유닛이 `r = PRF(k, v)`로 난수를 고르고 공모자가 `k`로 공개원장에서 선택을 읽음 | 배치 증명의 카운터 틈, 표본 기록의 `r_c`와 챔버 모듈 일회성 MAC 태그의 불일치 | 난수는 챔버 모듈들의 기여 합이고 커밋먼트 유닛은 자기 난수를 더하지 않음. 모듈은 카운터 연속성을 확인한 뒤에만 배치에 서명하고, 비공개 태그를 정족수가 표본 검사(PROTOCOL §7.2, §9.5). `r`을 결정하는 값은 해시라도 공개하지 않음 | X·Y 두 챔버 모듈이 함께 결탁하면 탐지 불가. 해석 유닛의 분류 편향은 감사로만 탐지 | V3(커밋먼트 유닛이 모듈 난수 합만 쓴다는 증명), V4(Tamarin 비밀성), 표본 태그 검사 절차 시험 |
| ITYV-THR-204 | 공급망 | 챔버 모듈 공급망 침해 | 난수 백도어, 패드 사본 유출, 가명 키 유출이 제조·배송 단계에서 발생 | 모듈 출하 해시·봉인 번호와 genesis 등록 불일치, 서로 다른 챔버의 교차 검사 실패 | 모듈은 서로 다른 챔버가 분할 공급하고 공개 봉인 절차로 등록, 부품 단위 SBOM | 제조사 내부자 | P0-02, 공급망 감사, V1 통계적 난수 검사 |
| ITYV-THR-205 | 패드 | 선거 전 패드 유출 | 신뢰기관 HSM 또는 운송 중 패드 묶음 복사 | 복사 자체는 탐지 불가. 패드 보관 사슬의 봉인·인계 기록 공백 | 패드는 HSM에서 생성해 모듈에 직접 주입, 생성자와 운송자가 다른 조직, 인계 이벤트 이중 서명 | 복사된 패드로는 해당 투표소 share를 풀 수 있으나 임계치 챔버 수만큼의 패드가 모두 필요 | P0-19 패드 보관 사슬 감사 |
| ITYV-THR-206 | 패드 | 패드 고갈로 KEM 대체 경로 강제 | 대량 투입·검증 요청으로 패드를 소모시켜 하이브리드 KEM 경로로 떨어뜨림 | 투함 기록의 `transport=KEM_FALLBACK` 표기 급증 | 패드 길이는 해당 장치 최대 표 수의 2배 이상(`docs/spec/PROTOCOL.md` §9.4.2), 대체 경로는 공개 상태로 표기, 녹취 후 미래 해독 위험을 문서화 | 대체 경로 구간은 ML-KEM·X25519 동시 파괴 시 노출 | V2(패드 인덱스 단조·고갈 처리 Kani), 운영 시험 |
| ITYV-THR-207 | 스캐너 | 각인기 결함으로 투함 ID 누락·중복·오각인 | 각인 헤드 고장, 잉크 소진, 두 장 겹침 | 종이 수와 각인 수 불일치, 장부의 중복 ID 격리, 감사 시 판독 불가 | 각인 전 사전 점검, 각인 실패 시 해당 표는 `QUARANTINED`로 보존하고 수검표, 두 장 겹침 감지 센서 | 겹친 두 장 중 한 장은 커밋먼트 없이 투함될 수 있음. 마감 수량 불일치로 드러남 | P0-21 각인기 하드웨어 인증, V1 결함 주입 |
| ITYV-THR-208 | 강요 | 종이 위 투함 ID와 촬영된 슬립을 연결 | 강요자가 유권자에게 슬립 사진을 요구하고 개표 참관 중 각인 ID로 종이를 찾음 | 슬립에는 투함 ID가 없고 추적코드(해시)만 있음. 공개 기록에도 투함 ID 없음 | 투함 ID는 커밋먼트 안에만 존재해 추적코드와 종이를 공개 정보로 잇는 경로가 없음(ADR-0006) | 신뢰기관 임계치가 공모해 여는 경우 | V4(Tamarin 영수증 무증명성) |
| ITYV-THR-209 | 개인정보 | 투표소 내 확인 장치와 스캐너의 시각·순서 상관 | 확인 순번과 투함 순번을 맞춰 유권자와 투함 기록을 연결 | 공개 데이터에 순번이 있으면 즉시 가능 | 투함 기록은 추적코드 순으로 정렬해 게시(`docs/spec/PROTOCOL.md` §7.8, VC-027), 장치 내부 순번은 봉인 저널에만, 확인은 15분 구간 | 현장 관찰자는 여전히 연결 가능하나 선택은 숨겨짐 | V1(게시 순서 속성 테스트), 개인정보 영향평가 |
| ITYV-THR-210 | 거버넌스 | 챔버 공모가 접근구조 Γ에 도달 | X·Y 블록과 3개 챔버 이상이 결탁해 개별 표를 엶 | 열기 절차 기록 없이 복원이 일어나면 외부에서 탐지 불가 | share는 파기 절차까지만 존재, 열기는 공개 절차와 장부 이벤트 의무, 임명 이벤트로 독립성 공개 | 비밀 공모는 암호로 막지 못함. 파기 이후에는 불가능 | P0-20 접근구조 검증, 파기 절차 감사 |
| ITYV-THR-211 | 거버넌스 | 한 챔버가 거부해 암호 계층을 멈춤 | 정당 블록이 share 제출을 거부 | 집계 열기 실패, 거부 챔버가 장부에 기록됨 | 거부는 종이 개표를 멈추지 못하고 공개됨(ADR-0012), X·Y 외 챔버는 5-of-6로 대체 | X 또는 Y 블록의 거부는 암호 검증 전체를 멈춤. 법적 의무와 벌칙으로 대응 | 거버넌스 모의훈련 |
| ITYV-THR-212 | 거버넌스 | 독립검증위원회 포획 | 위원 다수가 특정 세력에 종속 | 소수의견 기록 부재, 감사 확대 명령 거부 패턴 | 위원회는 결과를 바꿀 권한이 없고 정확성은 암호와 종이가, 비밀은 접근구조가 지킴 | 감독 성실성 저하로 분쟁 처리 지연 | 거버넌스 설계 검토 |
| ITYV-THR-213 | 암호 | DKG 중단·편향 | 참여자가 분산 키 생성을 반복 중단하거나 편향 기여 | 절차 기록의 중단 횟수, 기여 commitment 불일치 | 검증 가능한 DKG, 기여 commitment 공개, 중단자 공개 | 가용성 공격 | V4(DKG 프로토콜 모델), 절차 기록 공개 |
| ITYV-THR-214 | 전송 | share 패키지 전송 중 변조 | 패드는 기밀성만 제공하므로 비트 반전으로 share 오염 | 집계 열기 실패, 패키지 해시(투함 기록 포함)와 불일치 | 패드 유도 MAC과 장치 하이브리드 서명, 패키지 해시를 투함 기록에 기록 | 오염 투표함 특정에 시간 소요 | V2(MAC 검증 Kani), V1 |
| ITYV-THR-215 | 암호 | 집계 열기 불일치의 이분 탐색이 표 단위 값을 노출 | 결함 스캐너를 찾기 위해 투표함·표 단위로 열다가 개별 표가 열림 | 열기 이벤트 수가 표본 수를 초과 | 이분 탐색은 투표함 단위 합계까지만, 표 단위는 감사 표본 규칙과 같은 공개 추첨 절차 필요 | 결함 투표함의 합계가 노출됨(투표함 단위 공개는 원래 허용 범위) | 절차 규정, 열기 이벤트 감사 |
| ITYV-THR-216 | 감사 | 기록 우선 감사가 표본 표의 선택을 감사인에게 노출 | 표본 기록을 열면 그 표의 선택과 투함 ID가 감사인에게 보임 | 설계상 허용. 유권자와는 연결되지 않음 | 표본은 공개 추첨, 열기 값은 감사 보고서에 집계만, 투함 ID는 비공개 | 감사인이 현장 관찰 기록과 결합하면 유권자 추정 가능. 감사인 선서와 접근 통제 | 개인정보 영향평가 |
| ITYV-THR-217 | 분쟁 | 슬립 위조 대 장치 키 탈취 | 장치 키가 탈취되면 "유효한 서명의 누락 코드"를 양산해 투표함 HOLD를 유발 | 같은 장치 키의 슬립이 비정상적으로 많이 신고됨 | 장치 키는 챔버 모듈 내부, 키별 발행 수 상한, 탈취 의심 시 키 폐기 이벤트 | 탈취 후 폐기 전 구간의 허위 HOLD | V2(발행 카운터), 키 관리 절차 |
| ITYV-THR-218 | 현장 | 대량 검증 요청으로 투표소 마비 | 조직적으로 투입 전 검증을 반복해 투표지를 소모 | 검증 비율과 폐기 표 수 급증 | 검증은 권리이되 1인당 횟수와 투표소별 예비 용지 계획, 참관인 검증은 사전 배정 | 가용성 저하 | 운영 시험 |
| ITYV-THR-219 | 스캐너 | 해석 유닛 입력 이미지 공격 | 특수 인쇄·스티커로 해석 유닛을 오동작시켜 특정 후보로 분류 | 투입 전 검증 불일치, 감사 불일치 | 해석 유닛 불신 전제, 검증·감사, 비정상 이미지는 `UNREADABLE` | 공격이 검증 미대상 표에만 성공하면 위험 한도 내 | V1 퍼징(해석 유닛 입력), 감사 |
| ITYV-THR-220 | 스캐너 | 후보 편향 오독 | 해석 유닛이 특정 후보 표식을 체계적으로 다른 후보로 읽음 | 검증 실패율의 후보별 편차, 감사 불일치 | ITYV-THR-219와 같음, 후보 이름을 바꾼 대칭 시험 | — | 논리·정확성 시험, V1 |
| ITYV-THR-221 | 스캐너 | `BLANK`·`UNREADABLE` 분류 남용 | 정상 기표를 `UNREADABLE`로 커밋먼트해 집계에서 빼고 수검표에서는 사람이 유효로 판정하도록 하여 불일치를 유발하거나 그 반대 | 분류 비율의 투표소별 이상치, 감사 불일치 | 분류 비율 공개, 상한 초과 시 투표함 HOLD, 종이가 법적 결과 | 분류 기준의 모호성 | 통계 감시, 감사 |
| ITYV-THR-222 | 개인정보 | 해석 유닛·수령처의 비밀 데이터 보존 | 해석 유닛이 이미지를 저장하거나 수령처 직원이 봉투 라벨과 투표지를 함께 기록 | 저장소 포렌식, 절차 위반 신고 | 해석 유닛은 영속 저장소 없이 설계, 봉투 개봉 시 라벨 분리 후 혼합 규칙(ADR-0010) | 해석 유닛은 불신 대상이라 무보존을 증명하지 못함. 하드웨어 설계로 저장 매체 제거 | P0-22 해석 유닛 격리 증거 |
| ITYV-THR-223 | 관외 | 수령 표기 고의 누락 | 수령처가 특정 봉투의 라벨을 읽지 않아 `CAST_NOT_RECEIVED`로 만들어 집계에서 제외 | 우체국 인계 수 대비 수령 표기 수 불일치, 미수령률 이상치 | 3중 대조, 미수령 봉투는 물리적으로 존재하므로 개봉 시 라벨 재스캔으로 대조 | 봉투 자체를 파기하면 수량 불일치로만 드러남 | 운영 시험, 통계 감시 |
| ITYV-THR-224 | 법적 게이트 | 법적 승인 객체 위조·범위 확장 | 선관위가 위원회 서명 없이 또는 조문 참조를 조작해 L1 범위를 켬 | 서명 검증 실패, 조문 참조 해시 불일치 | 두 서명 모두 필수, 조문 참조 해시 공개, capability 타입 | 양 기관 공모 | V2(genesis 검증기 Kani), trybuild |
| ITYV-THR-225 | 암호 | 증명 체계 다운그레이드 | `proof_system_id`를 낮춰 약한 증명으로 검증 통과 | 허용 목록 밖 ID | genesis가 허용 ID 집합을 고정 | — | V2 |
| ITYV-THR-226 | 가용성 | 공개원장 크기·검증 비용 공격 | 표당 약 2.7KB, 전국 약 120GB의 배포·검증을 방해 | 공표 기한 초과 | 청크 서명 배포, 표본 검증 모드, 기관 검증자 병렬 처리 | 공표 지연의 신뢰 비용 | 성능 시험(P0-04) |
| ITYV-THR-227 | 거버넌스 | 파기 절차 생략 | share와 선거 키를 파기하지 않고 보관 | 파기 이벤트 부재 | 파기 절차는 장부 이벤트 의무, 기한 초과는 법적 위반 | 비밀 사본 보관은 탐지 불가 | P0-25 파기 절차 시험 |
| ITYV-THR-228 | 암호 | share 보존으로 영구 비밀성 훼손 | 신뢰기관이 share를 파기 후에도 보관해 미래에 개별 표를 엶 | 탐지 불가 | 파기 절차, 챔버 분산으로 단일 기관 보관은 무의미 | 임계치 챔버 전부가 보관 | 거버넌스 |
| ITYV-THR-229 | 채널 | `RECEIPT_SCAN` 경로의 낮은 보장 남용 | 거소·선상 표를 투표 시점 커밋먼트 없이 처리하는 점을 이용해 수령 전 교체 | 해당 채널의 통계 이상치 | 보장 수준을 상태 어휘에 명시, 채널별 분리 집계, 해당 채널은 기존 절차 통제 유지 | 채널 규모가 작아도 접전 시 결정적일 수 있음 | 절차, 통계 감시 |
| ITYV-THR-230 | 강요 | 검증 공개값을 이용한 선택 증명 | 유권자가 일부러 검증을 요구해 공개된 난수와 해석 결과를 강요자에게 제시 | 공개값은 폐기된 표에만 대응 | 검증된 표는 `CHALLENGED_SPOILED`로 폐기되고 집계에 포함되지 않으므로 실제 선택을 증명하지 못함 | 강요자가 "검증 후 같은 선택으로 재투표"를 요구하면 심리적 압박은 남음 | V4(영수증 무증명성 모델에 검증 흐름 포함) |

## 3. 수확하지 않은 것

- K-Ballot의 구현 상태 열(PATCHED, PARTIAL 등)은 ityv와 무관하므로 가져오지 않았다. ityv의 상태는 VERIFICATION_LADDER.md와 P0_GATES.md로만 표현한다.
- 특정 제품(Cloudflare Worker, Durable Object, R2 큐)에 결속된 위협은 `OUT_OF_SCOPE`로 두고, 같은 성질의 일반 위협은 계승 행에서 다뤘다.
| ITYV-THR-231 | 서명 | 배치 마감 전 창에서 장치 파괴 | 양자 능력 공격자가 Ed25519를 위조해 고아 기록을 만들거나, 장치를 파괴해 열린 배치의 양자내성 증명을 없앰 | `open_batches > 0`, 종이 수와 증명 수 차이, 배치 없는 고아 기록 | 기록마다 Ed25519, 배치마다 하이브리드, 늦은 마감, `UNATTESTED` 공개(ADR-0014, FAILURE_CASES §2, §7) | 장치당 최대 64건의 양자내성 증명 상실. 표·비밀·법적 결과 무관 | V2(배치 포함·카운터 연속 검사), 운영 시험(늦은 마감) |
| ITYV-THR-232 | 운영 | 비상 투입구 남용 | 스캐너가 멀쩡한데 비상 투입을 선언해 기록 없는 표를 늘림 | `FallbackDeclared`의 사유와 `ModuleIncident` 불일치, 예비 장치 재고 기록 | 선언에 사무원 2·참관인 2 서명, 예비 장치 우선 의무, `no_record_count` 공개, 감사 우선 대상(FAILURE_CASES §3) | 참관인 포함 공모 시 기록 없는 표 증가. 종이 수는 그대로 | V1(수량 등식), 운영 감사 |
| ITYV-THR-233 | 서명 | 늦은 마감으로 사후 기록 삽입 | 장치를 되살리는 척하며 저널에 없던 기록을 배치에 넣음 | 모듈의 미결 카운터 목록 불일치, 종이 수 초과, `ScanCountAttest`와 불연속 | 모듈은 미결 카운터 목록이 일치할 때만 늦은 마감에 서명, 입회자 서명, 저널 head 연속성(VC-052, VC-057) | 모듈과 장치가 함께 장악된 경우는 종이 수 등식으로만 탐지 | V2, V3(커밋먼트 유닛 저널 불변식) |
