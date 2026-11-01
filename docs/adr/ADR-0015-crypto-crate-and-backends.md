# ADR-0015: 암호 래퍼 크레이트 `ityv-crypto`의 경계와 백엔드 정책

> English summary: `ityv-crypto` is the single TCB crate through which every other ityv component uses cryptography. It exposes typed, misuse-resistant operations (domain hashing, hybrid signatures, record signatures, archive co-signatures, hybrid KEM with AEAD, generalized Pedersen commitments with digit packing, the 1-of-m OR representation proof, chamber-structured linear secret sharing, one-time MAC and pad XOR) and hides the algorithm backends behind traits so that formally verified implementations can replace the initial pure-Rust ones without changing callers. Signatures are made over the SHA3-512 digest of the purpose-prefixed message (hash-then-sign), which keeps the crate allocation-free. The crate is `no_std`, has no `unsafe`, no panics, and takes randomness only from a caller-supplied `CryptoRngCore`.

- 상태: 채택
- 날짜: 2026-10-31
- 관련: ADR-0006, ADR-0007, ADR-0014; `docs/spec/PROTOCOL.md` §3, §7.4, §7.5, §9; `docs/spec/ENCODING.md` §4; `docs/ROADMAP.md` M1

## 맥락

프로토콜은 SHA3-512, Ristretto255 위의 일반화 Pedersen 커밋먼트, Σ-프로토콜 OR 증명, ML-DSA-87과 Ed25519의 하이브리드 서명, SLH-DSA 보조 서명, ML-KEM-1024과 X25519 하이브리드 KEM, Poly1305 일회성 MAC, 챔버 접근구조의 선형 비밀분산을 요구한다(ADR-0006). 이들을 각 크레이트가 직접 쓰면 도메인 분리와 canonical 검사가 흩어져 오류 지점이 늘어난다. 한편 형식 검증된 구현(libcrux, HACL*, fiat-crypto 백엔드)은 알고리즘마다 성숙도가 달라 처음부터 모두 쓸 수는 없다.

## 결정

1. **단일 진입점.** 다른 TCB 크레이트는 암호 라이브러리를 직접 의존하지 않고 `ityv-crypto`만 의존한다. CI는 이를 `cargo deny`의 bans 규칙으로 검사한다.
2. **타입 경계.** 모든 연산은 newtype 입력·출력만 받는다. 검증 결과는 `bool`이 아니라 검증된 값을 담는 타입(`Verified<T>`)으로 돌려주어 "검증을 건너뛴 값"이 타입상 존재하지 않게 한다. 토큰 `T`는 검증에 들어간 입력 전부(키, purpose, 객체, 서명; 진술과 증명; 커밋먼트와 열기; 인증된 메시지)를 참조하므로 한 객체의 토큰을 다른 객체에 넘겨 쓸 수 없고, 토큰은 이 크레이트만 만든다. 하이브리드 서명 검증은 두 서명을 모두 검사해야만 `Verified`를 만든다.
3. **해시 후 서명.** 서명 입력은 `ENCODING.md` §4의 서명 메시지 `"ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len) ‖ obj`의 **SHA3-512 다이제스트 64바이트**다. ML-DSA-87에는 같은 `purpose`를 FIPS 204 컨텍스트 문자열로, SLH-DSA-SHAKE-256s에는 FIPS 205 컨텍스트 문자열로도 넘긴다(Ed25519는 다이제스트만). 이 규칙으로 서명 경로가 힙 없이 동작하고, 메시지 정의는 변하지 않는다.
4. **백엔드 정책.** 알고리즘은 trait 뒤에 둔다. 초기 백엔드는 순수 Rust 구현(RustCrypto 계열 `sha3`, `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `ml-dsa`, `ml-kem`, `slh-dsa`, `poly1305`, `chacha20poly1305`)이며, 형식 검증된 구현(libcrux ML-KEM·ML-DSA, HACL*, fiat-crypto 필드 산술)이 `no_std`와 API 요건을 충족하는 대로 교체한다. 교체는 호출자 변경 없이 이 크레이트 안에서만 일어나야 하며, 교차 백엔드 시험 벡터로 동일성을 검사한다. 군 산술(Ristretto255)은 v0.1에서 trait 없이 `backend/ristretto`가 단일 진입점이며, 검증된 필드 산술 백엔드 교체 시 trait 경계를 세운다(미해결 항목).
5. **난수.** 크레이트는 OS 난수원을 열지 않는다. 난수가 필요한 연산은 `rand_core::CryptoRngCore`를 인자로 받는다. 현장 장치에서는 챔버 모듈의 기여가 그 입력이다(PROTOCOL §7.2).
6. **고정 용량.** OR 증명과 비밀분산은 상한(선택지 64, 청크 8, 챔버 8(정당 챔버 P1–P4와 J·A·C·N, ADR-0019), 챔버당 구성원 8)의 고정 배열로 동작하며 `alloc`을 쓰지 않는다. 정당 챔버 수 n(2–4)은 접근구조가 갖고, n을 넘는 정당 챔버는 share를 받지 않는다. 상한은 genesis의 투표양식 검증에서 함께 강제한다.
7. **검증 사다리.** V1(속성 테스트, 퍼징, 변이)과 V2(Kani: 자릿수 묶음·해제, 패드 XOR, 접근구조 판정, share 인덱스 산술, 서명 입력 구성)를 M1에서 갖춘다. 곡선 산술과 Σ-프로토콜의 V3는 백엔드 교체와 함께 M2 이후에 둔다.

## 결과

- `ENCODING.md` §4와 `PROTOCOL.md` §3.1에 해시 후 서명 규칙을 명시한다.
- 바이트 배치를 명세에 고정한다: 해시-투-그룹 `SHA3-512(label ‖ 0x00)`, OR 증명 대본의 `option_count`·`chunk_count`·배열 개수 접두사, KEM 키 유도에 두 암호문 포함, 서명·키·암호문의 길이 접두사 없는 고정폭 인코딩(`[u8; N]`), 증명의 3바이트 머리부. 제2 구현(V5)은 `ityv-crypto`의 상호운용 벡터(베이스 점, KEM 키, Fiat-Shamir 챌린지)로 동일성을 확인한다.
- 의존성이 늘어나므로 `supply-chain/`의 cargo-vet 기록과 `deny.toml`의 라이선스 허용 목록을 갱신하고, 각 의존성의 선택 이유를 크레이트 README에 적는다.
- 순수 Rust 백엔드는 상수 시간과 부채널에 대해 라이브러리의 주장에 의존한다. P0-02·P0-05(장치·HSM)와 별개로 "백엔드 형식 검증 완료"를 M1의 미해결 항목으로 둔다.

## 기각한 대안

- 각 크레이트가 라이브러리를 직접 사용: 도메인 분리·canonical 검사의 분산.
- 메시지 전체를 서명 라이브러리에 넘김: 힙 또는 스트리밍 API가 필요하고 백엔드마다 다름.
- 처음부터 libcrux만 사용: 일부 알고리즘·`no_std` 조합이 미성숙.
