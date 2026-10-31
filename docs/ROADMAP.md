# 로드맵 / Roadmap

> English summary: Milestones after the first deliverable. Each crate must climb the verification ladder before the next depends on it. Nothing here changes the NO_GO status until every P0 gate is closed by independent evidence.

## M0 (이번 산출물)
- 헌법, CI 게이트, ADR 13건, 프로토콜 명세 v0.1(일회용 패드 장 포함), 법령 부속서, 거버넌스, 사용례·투표지·처리 흐름, 보증 수확 계획, `ityv-encoding`(V1·V2).

## M1 암호 래퍼 `ityv-crypto` (진행 중, ADR-0015)
- SHA3-512 도메인 해시, 하이브리드 서명(ML-DSA-87 + Ed25519) 검증 인터페이스, 기록 서명(Ed25519), SLH-DSA 보조 서명, 하이브리드 KEM과 AEAD, Ristretto255 일반화 Pedersen과 자릿수 묶음, 1-of-m OR 증명, 챔버 접근구조 선형 비밀분산, 일회성 MAC과 패드 XOR. 초기 백엔드는 순수 Rust, 형식 검증 백엔드로 교체 가능한 trait 경계. V1·V2; 곡선 산술·Σ-프로토콜 V3는 M2 이후.

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
