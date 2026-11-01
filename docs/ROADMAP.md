# 로드맵 / Roadmap

> English summary: Milestones after the first deliverable. Each crate must climb the verification ladder before the next depends on it. Nothing here changes the NO_GO status until every P0 gate is closed by independent evidence.

## M0 (이번 산출물)
- 헌법, CI 게이트, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, `ityv-encoding`(V1·V2).

## M1 암호 래퍼 `ityv-crypto` (산출 완료, ADR-0015)
- 산출: `crates/ityv-crypto`. SHA3-512 도메인 해시(객체·서명 다이제스트·Fiat-Shamir·해시-투-그룹), 하이브리드 서명(ML-DSA-87 **그리고** Ed25519, `Verified` 토큰), 기록 서명(Ed25519, 용도를 타입으로 제한), SLH-DSA-SHAKE-256s 보존 서명, 하이브리드 KEM(ML-KEM-1024 + X25519)과 `ChaCha20-Poly1305` 봉인, Ristretto255 일반화 Pedersen과 26비트 자릿수 묶음·해제·합계 열기, 1-of-(m+2) OR 표현 증명, 챔버 접근구조 Γ의 선형 비밀분산(정족수 판정·일관성 검사·준동형 합산), Poly1305 일회성 MAC, 패드 XOR. 모든 공개 객체는 `ityv-encoding` 고정폭 인코딩을 구현한다. 백엔드는 `backend` 모듈의 trait 뒤에 있으며 초기 구현은 순수 Rust(RustCrypto·dalek)다.
- 검증: V1(단위·속성·독립 KAT·회귀 벡터·변이 테스트), V2(Kani 하네스 21개: 자릿수 지수·비트 묶음·해제, 청크 수와 `OptionCount`, 접근구조 판정, share 인덱스 산술, 패드 XOR, purpose 검증, 길이 접두, 서명 접두 바이트 배치; `kani/proofs.rs`). 2026-10-31 기준 결과: 워크스페이스 테스트 114개 통과(crypto 66, encoding 48, 9초), Kani 33개 하네스 전부 통과(crypto 21, encoding 12, 6분), cargo-mutants(CI) `ityv-crypto` 509개 중 잡힘 269·놓침 0·unviable 236·타임아웃 0(동치 변이 2건은 `.cargo/mutants.toml`에서 이름으로 제외, 사유는 crate README), `ityv-encoding` 203개 중 놓침 0. 독립 리뷰(명세 대조)에서 나온 수정: `Verified<T>`가 검증 입력 전부를 참조, KEM `SealKey`/`OpenKey` 분리와 수신자 공개키 결속, `verify_opening`의 선택지 범위 검사, `Proof::decode`의 청크 수 검사, 오류 경로 소거, 하네스의 `src/` 밖 이동. CI: 빌드·clippy·docs·`no_std` 타깃·deny·vet·Kani(하네스당 10분 상한)·mutants(자문).
- 남은 것: 증명 생성 재배열과 KEM 사전 계산(ADR-0020 결정 8·11; 출력 분포·인코딩은 명세와 같음, 독립 암호 검토·상수 시간 검사·분포 비교 차분 테스트 조건); 백엔드 형식 검증 교체(libcrux ML-KEM·ML-DSA, HACL*, fiat-crypto 백엔드 cfg)와 교차 백엔드 벡터; 곡선 산술·Σ-프로토콜 V3(M2 이후); `slh-dsa` 정식판으로 교체(현재 0.2.0-rc.5); 증인 정족수 정책(ITYV-BEH-110·111·112·283·284)은 암호 연산이 아니므로 M2 `ityv-ledger`로 이관.

## M2 장부 `ityv-ledger` (산출 완료, ADR-0016)
- 산출: `crates/ityv-ledger`. `merkle`(RFC 9162 모양의 SHA3-512 트리, 봉우리 40개의 누산기, 포함 증명 ≤ 40·일관성 증명 ≤ 41의 생성·검증, 정렬 집합 root), `frame`(사슬 규칙, `u32_be 길이 ‖ 프레임` 디스크 스트림과 찢어진 꼬리 격리, 동일 바이트 재전송 멱등·다른 바이트 충돌), `checkpoint`(`SignedCheckpoint` 0x0010, 후속 검증, 기억을 소비하고 전진한 기억을 돌려주는 증인 `may_sign`, `WitnessMemory` 0x0011), `policy`(정족수 프로필 `2q − n > f`, 명부, 서명 전수 검증과 다양성 7·4·3), `publication`(앵커 +4·공개원장 +96 구간, 수신 3곳). `no_std`, `alloc` 없음, 저장소·네트워크·시계 없음. 독립 벡터 생성기 `vectors/generate.py`(표준 라이브러리만).
- 검증(2026-10-31): 워크스페이스 테스트 168개 통과(ledger 50, 약 2초), Kani 하네스 10개 전부 통과(가장 무거운 세 개 161–210초; 기호적 트리 크기는 메모리 초과라 크기·인덱스는 열거, 리프는 기호), cargo-mutants 479개 중 잡힘 312·unviable 163·놓침 0(초기 놓침 19건은 경계 테스트와 시프트 재작성으로 해소, 동치 변이 없음). 독립 리뷰(명세·RFC 9162 대조, Python 참조 모델)에서 나온 수정: 증인 확인과 기억 전진의 원자화(`may_sign`이 기억을 소비), `Signable` 복제 불가, 식별자 연속성 `ids_hash`, `WitnessMemory` 객체화, 앵커 수 상수화, 재생 상태 타입의 `Default` 제거. V3(Merkle 연역 증명)는 미해결.

## M3 커밋먼트 유닛 `ityv-cunit` (진행 중, ADR-0017)
- `no_std`, 힙 없음. 투함 기록 생성, 투입 전 검증 공개, share 패키지, 일회용 패드 소비, 슬립 서명. 소거 성질 V3.
- 1단계(완료, 2026-10-31): `ityv-encoding`에 공유 스키마 14개(0x0005·0x0006·0x0007·0x000A·0x000B·0x0012·0x0013·0x0015·0x0016·0x0017·0x0018·0x0019·0x001A·0x001B). 워크스페이스 테스트 203개, Kani 20개 하네스 통과(배열 필드 본문의 객체 수준 왕복은 도구 한계로 V1이 담당, crate README 참조), cargo-mutants 557개 중 놓침 0. 독립 리뷰 수정: 첫 위반 순서, 하한 개수의 오류 종류, 미공표 규칙의 명세 반영, 결측 거부 벡터, `MemberShare`의 `Copy` 제거. 2단계: `ityv-cunit`(링크 디코더 0x0101·0x0103, 표별 typestate, share 패키지와 패드·KEM 전송, 봉인 저널 0x0014, 배치·투표함 회계, 검증 공개, 슬립).
- 방문 단위 투입 반영(ADR-0021): `ityv-cunit` 방문 흐름(작업 영역 최대 8, `VisitEnd` 링크 객체 0x0104 디코더, 모든 위치의 장치·모듈 기록 서명 뒤에만 결정을 받는 typestate, 위치별 넣기·확인 결정, 저널 종류 7 방문 결정·8 라벨 출력과 그 순서, §7.3의 재개 판정 네 경우, 방문당 라벨 스티커와 슬립), `ityv-encoding`(`SlipBody.tracking_codes: Array<Hash512, 8>`와 `Slip.body` 상한 1024, `BoxCloseBody`의 `visit_count`·`envelope_count`·`sticker_count`), 마감 검사(관외 `sticker_count == visit_count`, 봉투 수와 교부 회계, `visit_count ≤ record_count ≤ 8·visit_count`), 모듈 측 "카운터당 본문 하나" 규칙의 참조 구현과 시험. Kani: 결정 입력이 모든 위치의 서명 뒤에만 가능함. 문서는 반영됨, 코드는 같은 PR에서 맞춘다.
- 정당 챔버 n개 반영(ADR-0019): `ityv-crypto` shares(챔버 P1–P4·J·A·C·N, 정당 챔버 전부 필수 접근구조), `ityv-encoding` ChamberCode·배열 상한(모듈 7, `MemberShare.shares` 58), `ityv-cunit` 모듈 상한 7과 필수 정당 모듈 검사. 문서는 반영됨, 코드는 같은 PR에서 맞춘다.
- 소프트웨어 신원(ADR-0023): `ityv-encoding`에 `ReleaseManifestBody`·`ReleaseManifest`(0x0021·0x0022), `DeviceAttestationBody`·`DeviceAttestation`(0x0023·0x0024), `AttestationSummary`(0x0025), 링크 객체 `AttestChallenge`(0x0105). `ityv-cunit`에 `attest(challenge)` API: 주어진 증명 키로 서명만 하고 투표 상태(작업 영역, 저널, 배치, 카운터)를 읽거나 바꾸지 않으며, 열린 방문 중과 30초 안 재요청을 거부하는 typestate(VC-088). 재현 빌드 절차 문서와 CI의 이미지 해시 공개(VC-091).

## M4 상태기계 `ityv-state` (산출 완료, ADR-0025)
- 산출: `crates/ityv-state`. `auth`(법적 승인 객체의 두 서명 토큰 확인, 범위 전제와 단계 건너뛰기 금지, `Authorization::grant`만 만드는 `Cap<'a, S>`), `record`(`UNATTESTED`→`CAST_COMMITTED`, `CHALLENGED_SPOILED`·`QUARANTINED`, 수령 대조 다섯 결과, `SHARE_MISSING`·`TEST_BALLOT`, 집계 처분), `close`(VC-038 등식별 보류, 모듈 카운터 틈, 등록된 독립 서명자), `boxes`(`BallotBox<'a, S>` typestate: 개시·비상 투입·마감·수동 마감·늦은 마감·늦은 배치·개표·감사), `custody`(VC-040 인계 사슬과 봉인 변경), `issuance`(교부·참여 등식), `tally`(VC-057·VC-063 관문), `dispute`(두 기관 접수, 앞으로만 가는 상태와 법적 회부), `status`(상태 어휘, 공표 기한 반영, `LEGAL_CERTIFIED` 없는 `Status`와 `LegalReference`), `hold`(끈끈한 보류 사유). `no_std`, `alloc` 없음, 새 외부 의존성 없음. 스키마가 없는 이벤트(`BoxOpened`, `IssuanceCount`, `CustodyHandoff`, `DisputeEvent`, `LegalDecisionRef` 등)는 최소 입력 타입이며 M5 인코딩 과제다. 명세 공백 18건은 ADR-0025에 적었다.
- 검증(2026-11-01): `ityv-state` 테스트 80개 통과(단위 48, 통합 21: 실제 하이브리드 서명으로 만든 마감·늦은 마감·법적 승인·법적 참조 객체, 속성 5, doctest 6 중 `compile_fail` 5), 워크스페이스 테스트 443개 통과. Kani 하네스 9개 전부 통과(가장 무거운 것은 512개 범위 집합의 전제 규칙, 43초). cargo-mutants 386개 중 잡힘 297·unviable 89·놓침 0·타임아웃 0(첫 실행의 놓침 4건은 서명 반쪽 변조, 감사 상태의 보류, 합집합 연산, 시험용 생성자 시험으로 해소). fmt, clippy(워크스페이스, 모든 타깃), rustdoc `-D warnings`, `thumbv7em-none-eabihf` 빌드, cargo-deny, cargo-vet 통과.
- 리뷰 수정: 집계 관문 둘이 `CRYPTO_TALLY_AID` 권한의 선거를 확인한다(다른 선거의 권한으로 집계를 열 수 없음). 법적 승인의 두 키는 ML-DSA-87·Ed25519 반쪽이 모두 달라야 한다(VC-006).
- M5 인코딩 과제와 ADR-0025의 명세 공백 18건은 M5 1단계에서 닫았다(아래). 남은 것: 시뮬레이터 토큰 타입(ITYV-BEH-162, M6).

## M5 공개 검증기 `ityv-verify`
- 1단계(완료, 2026-11-01, ADR-0025 표): 사람이 서명하는 이벤트의 스키마 `CustodyHandoffBody`(0x0008), `DisputeEventBody`(0x000E), `LegalDecisionRefBody`(0x000F, 결과·집계 효과), 공통 봉투 `WitnessedEvent`(0x0028, 본문별 서명 역할 규칙), `BoxOpenedBody`(0x0029), `FallbackBody`(0x002A), `IssuanceCountBody`(0x002B, 용지 재고), `ImprintAuditBody`(0x002C), `SealChangeBody`(0x002D, 사유 코드), `LateBatchCloseBody`(0x002E), `BoxCloseBody.spoil_envelope_count`, genesis 항목형 `GenesisBox`·`CustodyRoute`·`RosterSigner`(`ENCODING.md` §8.33–§8.43, 시험 벡터 10개 파일). `ityv-state`의 불리언 서명 깃발을 모두 검증 토큰으로 바꾸고(`sig::check_event`, 마감의 `CloseTokens`, 서명자 키 반쪽 중복 금지, VC-098), 명세 공백 18건을 규범 문서에서 정했다(VC-099 법적 판정 전 집계 범위 금지, VC-100 늦은 마감 기한과 해소 조건, VC-101 이벤트 재수록). 범위 전제 강화: `VOTER_CODE`는 2단계 범위 전부, `RLA`는 `CRYPTO_TALLY_AID`(VC-008).
- 공개원장 전체 검증(체크포인트, 정형성 증명, 집계), 표본 검증 모드, 독립 2차 구현(V5)과 차분 테스트.
- 소프트웨어 신원(ADR-0023): 릴리스 목록 서명·구성 해시 재계산, `DeviceAttestation`·`AttestationSummary` 검증, 투표함별 개시·마감 증명 확인, 참관인 앱의 오프라인 QR 확인과 결과 화면(`docs/ui/SCREENS.md` §6)(VC-085..091).
- 연결 감사(ADR-0022): 연결 목록 형식과 TCB 장치 한 방향성 검사, `UplinkSession` 사슬 재계산과 장치 출처 객체 포함 검사, 참관인 캡처 대조 도구, 통신사 기록 대조 형식(VC-077..083).
- 미러 모드(전체·증분 동기화, 검증 후 재공표), 체크포인트 교환과 분기 증거 생성, 유권자 앱의 2곳 대조와 지문 표시(PROTOCOL §5.7, ADR-0018).
- 새 검증 조건: 관외 봉투·스티커·방문 수(VC-038), 방문당 슬립의 코드 목록(VC-070), 카운터 유닛 교체의 순번 연속(VC-073), 감사 사유 코드 1·2의 전수 대조 존재(VC-074), 보고 단위별 합계와 `PaperCountReport` 대조(VC-075), `DuplicateIdentification` 형식(VC-076).
- 투표 진행 기록(ADR-0027) 코드(완료, 2026-11-01): `ityv-encoding`의 `BoxProgressBody`·`CheckinProgressBody`·`ProgressTick`·`ProgressCheckBody`(0x002F–0x0032), genesis `StationProgressPolicy`, `UnitId`, 시험 벡터 4개. `ityv-state`의 `progress`(장치 흐름 `BoxStream`·`CheckinStream`: 토큰 확인, 슬롯 하나, 누계 단조, 마감 대조, 교체 이어받기; 평가기 `StationProgress`: 음수·과다·바닥 경보, 현장 확인 판정, `PROGRESS_UNRESOLVED`·`CARRY_OUT`과 교부 번호 대조 깃발, 정지). `ityv-cunit`의 `OpenBox::progress_tick`·`ClosedBox::closing_tick`. 검증: 워크스페이스 테스트 485개, Kani 새 하네스 7개(인코딩 4, 상태 3: `out` 정확성, 흐름 규칙, 경보는 조건의 한 구간에 한 번), 독립 참조 평가기와의 속성 테스트, cargo-mutants 놓침 0(`ityv-state` 전체 589개, 인코딩 바뀐 파일 213개, `ityv-cunit` 바뀐 파일 128개). 남은 것: 검증기와 참관인 앱의 진행·경보 화면(`docs/ui/SCREENS.md` §6.2), genesis `stations[]`와 `ObserverCountAttest`의 정규 형.

## M6 시뮬레이터 `tools/ityv-sim`
- 합성 선거 생성, 공격 주입(표갈이, 중복, 롤백, 분기, 은닉 채널), 모든 HOLD 경로 재현.
- 연결 공격 주입: 숨은 프레임, 일정·크기 이탈, 낱개 즉시 전송, 게이트웨이 누락·주입, 탭 캡처 불일치, 명부 회선의 기간 밖 연결(ADR-0022).
- 시범 선정 도구: 직전 선거 결과로 후보군·비교군 계산, 층화 추첨 재현, `PilotReport` 지표를 공개원장 이벤트에서 다시 세기(ADR-0026, VC-097).
- 진행 기록 공격 주입: 릴레이 투표(1장 사슬, 여러 장), 끼워 넣기, 재교부·반납 입력 누락, 단말의 거짓 교부 입력, 슬롯 누락·누계 감소, 비상 투입·장치 교체 뒤 정지. 붐비는 투표소에서 바닥 경보가 나지 않는 한계와 오래 기표하는 유권자의 거짓 경보 빈도를 잰다(ADR-0027).

## M7 프로토콜 모델
- TLA+: 장부·증인·신뢰기관. Tamarin: 비밀성, 영수증 무증명성, 은닉 채널 저항.
- TLA+ 확장: 증인 공모 시 분기가 체크포인트 교환에서 탐지됨(ADR-0018).

## M8 장치
- 모듈 키 보관(ADR-0024): MCU 계열 둘 이상에 기기 고유 키(PUF/HUK/KMU)로 키 영역·패드 카드 암호화, 디버그 영구 잠금, 변조 스위치와 코인 전지, 카운터·가명 유닛 정당 모듈의 보안 칩(SE050 계열, 정당마다 다른 공급원 권장)과 SCP03 주입, 정당 열쇠 생성 장비와 USB HSM 몫 절차. 확인할 것: SE050 변형별 HMAC 지원, TROPIC01 HMAC와 단가, QS7001 공급·인증, 결함 주입 내성, 변조 스위치 오작동률.
- 가명 PRF는 HMAC-SHA-256(`ityv:prf:v2`)으로 바뀌었다(PROTOCOL §6.4). 카운터·가명 유닛 크레이트를 만들 때 `ityv-crypto`에 HMAC-SHA-256 PRF와 `prf_key_check`를 둔다.
- 카운터·가명 유닛, 봉인 모듈 인터페이스, 하드웨어 선정과 인증 계획(P0-02).
- 소프트웨어 신원 장비(ADR-0023): 부트 ROM과 OTP(릴리스 키 해시, 단조 빌드 하한, 부팅 횟수, 고유 비밀) 설계와 인증, 이미지 결속 증명 키 유도, 확인 카드 판독과 반환, 신원 줄·상세 화면·문구 표 해시, 분해 표본의 플래시 직접 판독 절차.
- 연결 감사 장비(ADR-0022): 수신 소자 없는 광 송신 포트와 역방향 시험, 게이트웨이 참조 설계(프레임 사슬, `UplinkSession` 서명), 관찰 탭의 수동성 인증, 고정 일정 송신기(프레임 생성·채움·이어 보내기·따라잡기), 분해 검사 절차서, 무선 점검 절차와 기준.
- 증명 사전 계산(P6, ADR-0020 결정 11): 모듈이 다음 표의 기여를 한가한 시간에 미리 발급하고(묶음 항목처럼 저널에 남김) 사전 계산이 모듈이 낸 난수를 그대로 쓰게 하는 방식을 평가한다. 하드웨어 실측 뒤에 결정한다. 그때까지 커밋먼트 유닛은 사전 계산을 쓰지 않는다.
- 도면 D-00..D-08을 시제품 설계의 출발점으로 쓴다(`docs/hardware/drawings/DRAWINGS.md`). 도면의 가정(스캐너 외형과 기울인 대기 구역, 장 수 센서, 기구 제어기 구성, 모듈 커넥터 모양, 각인 판독기 차폐, 카세트 구조)을 실측과 설계 검토로 정하고, 정한 것은 규범 문서에 먼저 반영한다.
- 카운터·가명 유닛의 교부·훼손 회수·반납 입력과 슬롯별 `CheckinProgress`, 교체 때 누계 이어받기(ADR-0027).
- `docs/hardware/DEVICES.md` §8의 실측(사이클·스택, 급지·겹침·걸림률, 1,000만 위치 판독 시험, 각인 노화, 전원·재개 1,000회, 패드 카드 잔류, 부하 보정, 견적), 해석 유닛 인증 항목(VC-071), 패드 카드와 본체 재발급 절차(VC-072), 방문 하나를 끝낼 배터리.

## 이전 계획
- 증명 체계 교체(격자·해시 기반)는 `proof_system_id` 증가로 수행하며 공개원장 형식은 유지한다.
