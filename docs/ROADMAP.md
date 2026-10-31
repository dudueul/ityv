# 로드맵 / Roadmap

> English summary: Milestones after the first deliverable. Each crate must climb the verification ladder before the next depends on it. Nothing here changes the NO_GO status until every P0 gate is closed by independent evidence.

## M0 (이번 산출물)
- 헌법, CI 게이트, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, `ityv-encoding`(V1·V2).

## M1 암호 래퍼 `ityv-crypto` (산출 완료, ADR-0015)
- 산출: `crates/ityv-crypto`. SHA3-512 도메인 해시(객체·서명 다이제스트·Fiat-Shamir·해시-투-그룹), 하이브리드 서명(ML-DSA-87 **그리고** Ed25519, `Verified` 토큰), 기록 서명(Ed25519, 용도를 타입으로 제한), SLH-DSA-SHAKE-256s 보존 서명, 하이브리드 KEM(ML-KEM-1024 + X25519)과 `ChaCha20-Poly1305` 봉인, Ristretto255 일반화 Pedersen과 26비트 자릿수 묶음·해제·합계 열기, 1-of-(m+2) OR 표현 증명, 챔버 접근구조 Γ의 선형 비밀분산(정족수 판정·일관성 검사·준동형 합산), Poly1305 일회성 MAC, 패드 XOR. 모든 공개 객체는 `ityv-encoding` 고정폭 인코딩을 구현한다. 백엔드는 `backend` 모듈의 trait 뒤에 있으며 초기 구현은 순수 Rust(RustCrypto·dalek)다.
- 검증: V1(단위·속성·독립 KAT·회귀 벡터·변이 테스트), V2(Kani 하네스 19개: 자릿수 지수·비트 묶음·해제, 청크 수, 접근구조 판정, share 인덱스 산술, 패드 XOR, purpose 검증, 길이 접두). CI: 빌드·clippy·docs·`no_std` 타깃·deny·vet·Kani·mutants.
- 남은 것: 백엔드 형식 검증 교체(libcrux ML-KEM·ML-DSA, HACL*, fiat-crypto 백엔드 cfg)와 교차 백엔드 벡터; 곡선 산술·Σ-프로토콜 V3(M2 이후); `slh-dsa` 정식판으로 교체(현재 0.2.0-rc.5); 증인 정족수 정책(ITYV-BEH-110·111·112·283·284)은 암호 연산이 아니므로 M2 `ityv-ledger`로 이관.

## M2 장부 `ityv-ledger`
- 프레임 로그, SHA3-512 Merkle(RFC 9162 트리 모양), 포함·일관성 증명, 체크포인트, 외부 앵커. V1·V2·V3(Merkle), TLA+ 안전성(V4).

## M3 커밋먼트 유닛 `ityv-cunit`
- `no_std`, 힙 없음. 투함 기록 생성, 투입 전 검증 공개, share 패키지, 일회용 패드 소비, 슬립 서명. 소거 성질 V3.

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
