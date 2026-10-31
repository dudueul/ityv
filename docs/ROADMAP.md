# 로드맵 / Roadmap

> English summary: Milestones after the first deliverable. Each crate must climb the verification ladder before the next depends on it. Nothing here changes the NO_GO status until every P0 gate is closed by independent evidence.

## M0 (이번 산출물)
- 헌법, CI 게이트, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, `ityv-encoding`(V1·V2).

## M1 암호 래퍼 `ityv-crypto` (산출 완료, ADR-0015)
- 산출: `crates/ityv-crypto`. SHA3-512 도메인 해시(객체·서명 다이제스트·Fiat-Shamir·해시-투-그룹), 하이브리드 서명(ML-DSA-87 **그리고** Ed25519, `Verified` 토큰), 기록 서명(Ed25519, 용도를 타입으로 제한), SLH-DSA-SHAKE-256s 보존 서명, 하이브리드 KEM(ML-KEM-1024 + X25519)과 `ChaCha20-Poly1305` 봉인, Ristretto255 일반화 Pedersen과 26비트 자릿수 묶음·해제·합계 열기, 1-of-(m+2) OR 표현 증명, 챔버 접근구조 Γ의 선형 비밀분산(정족수 판정·일관성 검사·준동형 합산), Poly1305 일회성 MAC, 패드 XOR. 모든 공개 객체는 `ityv-encoding` 고정폭 인코딩을 구현한다. 백엔드는 `backend` 모듈의 trait 뒤에 있으며 초기 구현은 순수 Rust(RustCrypto·dalek)다.
- 검증: V1(단위·속성·독립 KAT·회귀 벡터·변이 테스트), V2(Kani 하네스 21개: 자릿수 지수·비트 묶음·해제, 청크 수와 `OptionCount`, 접근구조 판정, share 인덱스 산술, 패드 XOR, purpose 검증, 길이 접두, 서명 접두 바이트 배치; `kani/proofs.rs`). 2026-10-31 기준 결과: 워크스페이스 테스트 114개 통과(crypto 66, encoding 48, 9초), Kani 33개 하네스 전부 통과(crypto 21, encoding 12, 6분), cargo-mutants(CI) `ityv-crypto` 509개 중 잡힘 269·놓침 0·unviable 236·타임아웃 0(동치 변이 2건은 `.cargo/mutants.toml`에서 이름으로 제외, 사유는 crate README), `ityv-encoding` 203개 중 놓침 0. 독립 리뷰(명세 대조)에서 나온 수정: `Verified<T>`가 검증 입력 전부를 참조, KEM `SealKey`/`OpenKey` 분리와 수신자 공개키 결속, `verify_opening`의 선택지 범위 검사, `Proof::decode`의 청크 수 검사, 오류 경로 소거, 하네스의 `src/` 밖 이동. CI: 빌드·clippy·docs·`no_std` 타깃·deny·vet·Kani(하네스당 10분 상한)·mutants(자문).
- 남은 것: 백엔드 형식 검증 교체(libcrux ML-KEM·ML-DSA, HACL*, fiat-crypto 백엔드 cfg)와 교차 백엔드 벡터; 곡선 산술·Σ-프로토콜 V3(M2 이후); `slh-dsa` 정식판으로 교체(현재 0.2.0-rc.5); 증인 정족수 정책(ITYV-BEH-110·111·112·283·284)은 암호 연산이 아니므로 M2 `ityv-ledger`로 이관.

## M2 장부 `ityv-ledger` (산출 완료, ADR-0016)
- 산출: `crates/ityv-ledger`. `merkle`(RFC 9162 모양의 SHA3-512 트리, 봉우리 40개의 누산기, 포함 증명 ≤ 40·일관성 증명 ≤ 41의 생성·검증, 정렬 집합 root), `frame`(사슬 규칙, `u32_be 길이 ‖ 프레임` 디스크 스트림과 찢어진 꼬리 격리, 동일 바이트 재전송 멱등·다른 바이트 충돌), `checkpoint`(`SignedCheckpoint` 0x0010, 후속 검증, 기억을 소비하고 전진한 기억을 돌려주는 증인 `may_sign`, `WitnessMemory` 0x0011), `policy`(정족수 프로필 `2q − n > f`, 명부, 서명 전수 검증과 다양성 7·4·3), `publication`(앵커 +4·게시판 +96 구간, 수신 3곳). `no_std`, `alloc` 없음, 저장소·네트워크·시계 없음. 독립 벡터 생성기 `vectors/generate.py`(표준 라이브러리만).
- 검증(2026-10-31): 워크스페이스 테스트 168개 통과(ledger 50, 약 2초), Kani 하네스 10개 전부 통과(가장 무거운 세 개 161–210초; 기호적 트리 크기는 메모리 초과라 크기·인덱스는 열거, 리프는 기호), cargo-mutants 479개 중 잡힘 312·unviable 163·놓침 0(초기 놓침 19건은 경계 테스트와 시프트 재작성으로 해소, 동치 변이 없음). 독립 리뷰(명세·RFC 9162 대조, Python 참조 모델)에서 나온 수정: 증인 확인과 기억 전진의 원자화(`may_sign`이 기억을 소비), `Signable` 복제 불가, 식별자 연속성 `ids_hash`, `WitnessMemory` 객체화, 앵커 수 상수화, 재생 상태 타입의 `Default` 제거. V3(Merkle 연역 증명)는 미해결.

## M3 커밋먼트 유닛 `ityv-cunit` (진행 중, ADR-0017)
- `no_std`, 힙 없음. 투함 기록 생성, 투입 전 검증 공개, share 패키지, 일회용 패드 소비, 슬립 서명. 소거 성질 V3.
- 1단계: `ityv-encoding`에 공유 스키마 14개(0x0005·0x0006·0x0007·0x000A·0x000B·0x0012·0x0013·0x0015·0x0016·0x0017·0x0018·0x0019·0x001A·0x001B)와 벡터·Kani 왕복. 2단계: `ityv-cunit`(링크 디코더 0x0101·0x0103, 표별 typestate, share 패키지와 패드·KEM 전송, 봉인 저널 0x0014, 배치·투표함 회계, 검증 공개, 슬립).

## M4 상태기계 `ityv-state`
- typestate: 투표지, 투표함, 보관, 체크포인트, 분쟁. capability 게이트. trybuild 컴파일 실패 테스트.

## M5 공개 검증기 `ityv-verify`
- 게시판 전체 검증(체크포인트, 정형성 증명, 집계), 표본 검증 모드, 독립 2차 구현(V5)과 차분 테스트.

## M6 시뮬레이터 `tools/ityv-sim`
- 합성 선거 생성, 공격 주입(표갈이, 중복, 롤백, 분기, 은닉 채널), 모든 HOLD 경로 재현.

## M7 프로토콜 모델
- TLA+: 장부·증인·신뢰기관. Tamarin: 비밀성, 영수증 무증명성, 은닉 채널 저항.

## M8 장치
- 카운터·가명 유닛, 봉인 모듈 인터페이스, 하드웨어 선정과 인증 계획(P0-02).

## 이전 계획
- 증명 체계 교체(격자·해시 기반)는 `proof_system_id` 증가로 수행하며 게시판 형식은 유지한다.
