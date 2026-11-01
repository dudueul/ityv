# 로드맵 / Roadmap

> English summary: Milestones after the first deliverable. Each crate must climb the verification ladder before the next depends on it. Nothing here changes the NO_GO status until every P0 gate is closed by independent evidence.

## M0 (이번 산출물)
- 헌법, CI 게이트, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, `ityv-encoding`(V1·V2).

## M1 암호 래퍼 `ityv-crypto` (산출 완료, ADR-0015)
- 산출: `crates/ityv-crypto`. SHA3-512 도메인 해시(객체·서명 다이제스트·Fiat-Shamir·해시-투-그룹), 하이브리드 서명(ML-DSA-87 **그리고** Ed25519, `Verified` 토큰), 기록 서명(Ed25519, 용도를 타입으로 제한), SLH-DSA-SHAKE-256s 보존 서명, 하이브리드 KEM(ML-KEM-1024 + X25519)과 `ChaCha20-Poly1305` 봉인, Ristretto255 일반화 Pedersen과 26비트 자릿수 묶음·해제·합계 열기, 1-of-(m+2) OR 표현 증명, 챔버 접근구조 Γ의 선형 비밀분산(정족수 판정·일관성 검사·준동형 합산), Poly1305 일회성 MAC, 패드 XOR. 모든 공개 객체는 `ityv-encoding` 고정폭 인코딩을 구현한다. 백엔드는 `backend` 모듈의 trait 뒤에 있으며 초기 구현은 순수 Rust(RustCrypto·dalek)다.
- 검증: V1(단위·속성·독립 KAT·회귀 벡터·변이 테스트), V2(Kani 하네스 21개: 자릿수 지수·비트 묶음·해제, 청크 수와 `OptionCount`, 접근구조 판정, share 인덱스 산술, 패드 XOR, purpose 검증, 길이 접두, 서명 접두 바이트 배치; `kani/proofs.rs`). 2026-10-31 기준 결과: 워크스페이스 테스트 114개 통과(crypto 66, encoding 48, 9초), Kani 33개 하네스 전부 통과(crypto 21, encoding 12, 6분), cargo-mutants(CI) `ityv-crypto` 509개 중 잡힘 269·놓침 0·unviable 236·타임아웃 0(동치 변이 2건은 `.cargo/mutants.toml`에서 이름으로 제외, 사유는 crate README), `ityv-encoding` 203개 중 놓침 0. 독립 리뷰(명세 대조)에서 나온 수정: `Verified<T>`가 검증 입력 전부를 참조, KEM `SealKey`/`OpenKey` 분리와 수신자 공개키 결속, `verify_opening`의 선택지 범위 검사, `Proof::decode`의 청크 수 검사, 오류 경로 소거, 하네스의 `src/` 밖 이동. CI: 빌드·clippy·docs·`no_std` 타깃·deny·vet·Kani(하네스당 10분 상한)·mutants(자문).
- 남은 것: 증명 생성 재배열과 KEM 사전 계산(ADR-0020 결정 8·11; 출력 분포·인코딩은 명세와 같음, 독립 암호 검토·상수 시간 검사·분포 비교 차분 테스트 조건); 백엔드 형식 검증 교체(libcrux ML-KEM·ML-DSA, HACL*, fiat-crypto 백엔드 cfg)와 교차 백엔드 벡터; 곡선 산술·Σ-프로토콜 V3(M2 이후); `slh-dsa` 정식판으로 교체(현재 0.2.0-rc.5); 증인 정족수 정책(ITYV-BEH-110·111·112·283·284)은 암호 연산이 아니므로 M2 `ityv-ledger`로 이관.

## M2 장부 `ityv-ledger` (산출 완료, ADR-0016)
- 산출: `crates/ityv-ledger`. `merkle`(RFC 9162 모양의 SHA3-512 트리, 봉우리 40개의 누산기, 포함 증명 ≤ 40·일관성 증명 ≤ 41의 생성·검증, 정렬 집합 root), `frame`(사슬 규칙, `u32_be 길이 ‖ 프레임` 디스크 스트림과 찢어진 꼬리 격리, 동일 바이트 재전송 멱등·다른 바이트 충돌), `checkpoint`(`SignedCheckpoint` 0x0010, 후속 검증, 기억을 소비하고 전진한 기억을 돌려주는 증인 `may_sign`, `WitnessMemory` 0x0011), `policy`(정족수 프로필 `2q − n > f`, 명부, 서명 전수 검증과 다양성 7·4·3), `publication`(앵커 +4·게시판 +96 구간, 수신 3곳). `no_std`, `alloc` 없음, 저장소·네트워크·시계 없음. 독립 벡터 생성기 `vectors/generate.py`(표준 라이브러리만).
- 검증(2026-10-31): 워크스페이스 테스트 168개 통과(ledger 50, 약 2초), Kani 하네스 10개 전부 통과(가장 무거운 세 개 161–210초; 기호적 트리 크기는 메모리 초과라 크기·인덱스는 열거, 리프는 기호), cargo-mutants 479개 중 잡힘 312·unviable 163·놓침 0(초기 놓침 19건은 경계 테스트와 시프트 재작성으로 해소, 동치 변이 없음). 독립 리뷰(명세·RFC 9162 대조, Python 참조 모델)에서 나온 수정: 증인 확인과 기억 전진의 원자화(`may_sign`이 기억을 소비), `Signable` 복제 불가, 식별자 연속성 `ids_hash`, `WitnessMemory` 객체화, 앵커 수 상수화, 재생 상태 타입의 `Default` 제거. V3(Merkle 연역 증명)는 미해결.

## M3 커밋먼트 유닛 `ityv-cunit` (진행 중, ADR-0017)
- `no_std`, 힙 없음. 투함 기록 생성, 투입 전 검증 공개, share 패키지, 일회용 패드 소비, 슬립 서명. 소거 성질 V3.
- 1단계(완료, 2026-10-31): `ityv-encoding`에 공유 스키마 14개(0x0005·0x0006·0x0007·0x000A·0x000B·0x0012·0x0013·0x0015·0x0016·0x0017·0x0018·0x0019·0x001A·0x001B). 워크스페이스 테스트 203개, Kani 20개 하네스 통과(배열 필드 본문의 객체 수준 왕복은 도구 한계로 V1이 담당, crate README 참조), cargo-mutants 557개 중 놓침 0. 독립 리뷰 수정: 첫 위반 순서, 하한 개수의 오류 종류, 미공표 규칙의 명세 반영, 결측 거부 벡터, `MemberShare`의 `Copy` 제거. 2단계: `ityv-cunit`(링크 디코더 0x0101·0x0103, 표별 typestate, share 패키지와 패드·KEM 전송, 봉인 저널 0x0014, 배치·투표함 회계, 검증 공개, 슬립).
- 방문 단위 투입 반영(ADR-0021): `ityv-cunit` 방문 흐름(작업 영역 최대 8, `VisitEnd` 링크 객체 0x0104 디코더, 모든 위치의 장치·모듈 기록 서명 뒤에만 결정을 받는 typestate, 위치별 넣기·확인 결정, 저널 종류 7 방문 결정·8 라벨 출력과 그 순서, §7.3의 재개 판정 네 경우, 방문당 라벨 스티커와 슬립), `ityv-encoding`(`SlipBody.tracking_codes: Array<Hash512, 8>`와 `Slip.body` 상한 1024, `BoxCloseBody`의 `visit_count`·`envelope_count`·`sticker_count`), 마감 검사(관외 `sticker_count == visit_count`, 봉투 수와 교부 회계, `visit_count ≤ record_count ≤ 8·visit_count`), 모듈 측 "카운터당 본문 하나" 규칙의 참조 구현과 시험. Kani: 결정 입력이 모든 위치의 서명 뒤에만 가능함. 문서는 반영됨, 코드는 같은 PR에서 맞춘다.
- 정당 챔버 n개 반영(ADR-0019): `ityv-crypto` shares(챔버 P1–P4·J·A·C·N, 정당 챔버 전부 필수 접근구조), `ityv-encoding` ChamberCode·배열 상한(모듈 7, `MemberShare.shares` 58), `ityv-cunit` 모듈 상한 7과 필수 정당 모듈 검사. 문서는 반영됨, 코드는 같은 PR에서 맞춘다.
- 소프트웨어 신원(ADR-0023): `ityv-encoding`에 `ReleaseManifestBody`·`ReleaseManifest`(0x0021·0x0022), `DeviceAttestationBody`·`DeviceAttestation`(0x0023·0x0024), `AttestationSummary`(0x0025), 링크 객체 `AttestChallenge`(0x0105). `ityv-cunit`에 `attest(challenge)` API: 주어진 증명 키로 서명만 하고 투표 상태(작업 영역, 저널, 배치, 카운터)를 읽거나 바꾸지 않으며, 열린 방문 중과 30초 안 재요청을 거부하는 typestate(VC-088). 재현 빌드 절차 문서와 CI의 이미지 해시 공개(VC-091).

## M4 상태기계 `ityv-state`
- typestate: 투표지, 투표함, 보관, 체크포인트, 분쟁. capability 게이트. trybuild 컴파일 실패 테스트.

## M5 공개 검증기 `ityv-verify`
- 게시판 전체 검증(체크포인트, 정형성 증명, 집계), 표본 검증 모드, 독립 2차 구현(V5)과 차분 테스트.
- 소프트웨어 신원(ADR-0023): 릴리스 목록 서명·구성 해시 재계산, `DeviceAttestation`·`AttestationSummary` 검증, 투표함별 개시·마감 증명 확인, 참관인 앱의 오프라인 QR 확인과 결과 화면(`docs/ui/SCREENS.md` §6)(VC-085..091).
- 연결 감사(ADR-0022): 연결 목록 형식과 TCB 장치 한 방향성 검사, `UplinkSession` 사슬 재계산과 장치 출처 객체 포함 검사, 참관인 캡처 대조 도구, 통신사 기록 대조 형식(VC-077..083).
- 미러 모드(전체·증분 동기화, 검증 후 재공표), 체크포인트 교환과 분기 증거 생성, 유권자 앱의 2곳 대조와 지문 표시(PROTOCOL §5.7, ADR-0018).
- 새 검증 조건: 관외 봉투·스티커·방문 수(VC-038), 방문당 슬립의 코드 목록(VC-070), 카운터 유닛 교체의 순번 연속(VC-073), 감사 사유 코드 1·2의 전수 대조 존재(VC-074), 보고 단위별 합계와 `PaperCountReport` 대조(VC-075), `DuplicateIdentification` 형식(VC-076).

## M6 시뮬레이터 `tools/ityv-sim`
- 합성 선거 생성, 공격 주입(표갈이, 중복, 롤백, 분기, 은닉 채널), 모든 HOLD 경로 재현.
- 연결 공격 주입: 숨은 프레임, 일정·크기 이탈, 낱개 즉시 전송, 게이트웨이 누락·주입, 탭 캡처 불일치, 명부 회선의 기간 밖 연결(ADR-0022).

## M7 프로토콜 모델
- TLA+: 장부·증인·신뢰기관. Tamarin: 비밀성, 영수증 무증명성, 은닉 채널 저항.
- TLA+ 확장: 증인 공모 시 분기가 체크포인트 교환에서 탐지됨(ADR-0018).

## M8 장치
- 모듈 키 보관(ADR-0024): MCU 계열 둘 이상에 기기 고유 키(PUF/HUK/KMU)로 키 영역·패드 카드 암호화, 디버그 영구 잠금, 변조 스위치와 코인 전지, 카운터·가명 유닛 정당 모듈의 보안 칩(SE050 계열, 정당마다 다른 공급원 권장)과 SCP03 주입, 정당 열쇠 생성 장비와 USB HSM 몫 절차. 확인할 것: SE050 변형별 HMAC 지원, TROPIC01 HMAC와 단가, QS7001 공급·인증, 결함 주입 내성, 변조 스위치 오작동률.
- 가명 PRF는 HMAC-SHA-256(`ityv:prf:v2`)으로 바뀌었다(PROTOCOL §6.4). 카운터·가명 유닛 크레이트를 만들 때 `ityv-crypto`에 HMAC-SHA-256 PRF와 `prf_key_check`를 둔다.
- 카운터·가명 유닛, 봉인 모듈 인터페이스, 하드웨어 선정과 인증 계획(P0-02).
- 소프트웨어 신원 장비(ADR-0023): 부트 ROM과 OTP(릴리스 키 해시, 단조 빌드 하한, 부팅 횟수, 고유 비밀) 설계와 인증, 이미지 결속 증명 키 유도, 확인 카드 판독과 반환, 신원 줄·상세 화면·문구 표 해시, 분해 표본의 플래시 직접 판독 절차.
- 연결 감사 장비(ADR-0022): 수신 소자 없는 광 송신 포트와 역방향 시험, 게이트웨이 참조 설계(프레임 사슬, `UplinkSession` 서명), 관찰 탭의 수동성 인증, 고정 일정 송신기(프레임 생성·채움·이어 보내기·따라잡기), 분해 검사 절차서, 무선 점검 절차와 기준.
- `docs/hardware/DEVICES.md` §8의 실측(사이클·스택, 급지·겹침·걸림률, 1,000만 위치 판독 시험, 각인 노화, 전원·재개 1,000회, 패드 카드 잔류, 부하 보정, 견적), 해석 유닛 인증 항목(VC-071), 패드 카드와 본체 재발급 절차(VC-072), 방문 하나를 끝낼 배터리.

## 이전 계획
- 증명 체계 교체(격자·해시 기반)는 `proof_system_id` 증가로 수행하며 게시판 형식은 유지한다.
