# ityv-crypto

> English summary: The single cryptographic entry point of ityv (ADR-0015). A `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate that wraps domain-separated SHA3-512, hybrid ML-DSA-87 + Ed25519 signatures (both must verify), Ed25519 record signatures, SLH-DSA-SHAKE-256s archive co-signatures, a hybrid ML-KEM-1024 + X25519 KEM with ChaCha20-Poly1305 sealing, generalized Pedersen commitments with 26-bit digit packing over Ristretto255, the 1-of-(m+2) OR proof of representation, linear secret sharing over the chamber access structure, Poly1305 one-time MACs and one-time pad XOR. Algorithm libraries are reached only through the `backend` module so that formally verified implementations can replace them without changing callers. Verification ladder: V1 (known-answer, property, regression and mutation tests) and V2 (Kani harnesses) are in the tree.

## 무엇인가

ityv의 다른 모든 크레이트는 암호를 이 크레이트를 통해서만 쓴다(ADR-0015 §1). 명세는 `docs/spec/PROTOCOL.md` §3.1, §7.2.1, §7.4, §7.5, §9와 `docs/spec/ENCODING.md` §4이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `hash` | 도메인 분리 SHA3-512: 객체 해시, 서명 다이제스트, Fiat-Shamir, 해시-투-그룹 | ENCODING.md §4 |
| `sig` | 하이브리드 서명(ML-DSA-87 **그리고** Ed25519), 기록 서명(Ed25519, `cast-record`/`module-record` 전용), 보존 서명(SLH-DSA-SHAKE-256s, `checkpoint-archive` 전용) | PROTOCOL.md §3.1, §7.2.1 |
| `kem` | ML-KEM-1024 **그리고** X25519 결합 KEM, `ChaCha20-Poly1305` 봉인 | PROTOCOL.md §9.6 |
| `commit` | 일반화 Pedersen 커밋먼트, 자릿수 묶음·해제, 합계 열기 | PROTOCOL.md §7.4, §11.2 |
| `orproof` | 1-of-(m+2) OR 표현 증명(Σ-프로토콜, Fiat-Shamir) | PROTOCOL.md §7.5 |
| `shares` | 챔버 접근구조 Γ의 선형 비밀분산, 정족수 판정, 복원 | PROTOCOL.md §9.2, ADR-0012 |
| `otmac`, `pad` | Poly1305 일회성 MAC, 일회용 패드 XOR | PROTOCOL.md §9.3, §9.4 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음(워크스페이스 lint 집합, Kani 하네스).
- 모든 검증은 `bool`이 아니라 이 크레이트만 만들 수 있는 `Verified<T>` 토큰을 돌려준다. 하이브리드 서명은 두 서명을 모두 검사해야 토큰이 생긴다(VC-002).
- 모든 비밀키 타입은 drop 시 소거되고 `Debug`로 내용을 찍지 않는다. `SharedKey`와 `OneTimeKey`는 복제할 수 없고 한 번 쓰면 소비된다.
- 난수는 호출자가 넘기는 `rand_core::CryptoRng`에서만 온다. 크레이트는 OS 난수원을 열지 않는다.
- 고정 용량: 선택지 64, 청크 8, 챔버 6, 챔버당 구성원 8. 입력 크기에 따라 커지는 것이 없다.
- 모든 공개 객체는 `ityv-encoding`의 `Encode`/`Decode`를 구현하며, 디코더는 비정규 스칼라와 무효한 점을 거부한다(VC-026).

보장하지 않는 것(미증명 항목):
- 상수 시간 실행과 부채널 저항은 백엔드 라이브러리의 주장에 의존한다. 이 크레이트는 자기 비교만 상수 시간으로 한다.
- 키 보관(HSM)은 범위 밖이다. 시드는 호출자에게 돌려주며 소거는 이 크레이트의 사본에만 미친다.
- 백엔드는 아직 형식 검증되지 않았다(ADR-0015 미해결 항목). `backend` 모듈의 trait 경계가 검증된 구현이 들어갈 자리다.
- OR 증명의 건전성과 커밋먼트의 결속은 Ristretto255 이산대수 가정 아래 계산적으로만 성립한다. 숨김은 무조건적이다.
- 곡선 산술과 Σ-프로토콜은 V1 수준이다(속성·변이·KAT). V3는 백엔드 교체와 함께 M2 이후다.

## 해시 입력 규칙

| 용도 | 입력 |
|---|---|
| 객체 해시 | `SHA3-512("ityv:hash:v1" ‖ 0x00 ‖ u64_be(len) ‖ obj)` |
| 서명 다이제스트 | `SHA3-512("ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len) ‖ obj)`; 모든 서명 알고리즘은 이 64바이트를 서명한다. ML-DSA-87과 SLH-DSA에는 `purpose`를 FIPS 204/205 컨텍스트로도 넘긴다 |
| Fiat-Shamir | `SHA3-512("ityv:fs:v1:" ‖ proof_system ‖ 0x00 ‖ u64_be(len) ‖ transcript)`를 스칼라로 균등 축소 |
| 해시-투-그룹 | `from_uniform_bytes(SHA3-512(label ‖ 0x00))`, 라벨은 `ityv:base:val:v1`, `ityv:base:id:v1`, `ityv:base:rand:v1` |
| KEM 키 유도 | `SHA3-512("ityv:kem:v1" ‖ 0x00 ‖ ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ ct_x25519)[0..32]` |

OR 증명의 대본 바이트 배치는 `src/orproof.rs`의 모듈 문서에 있다: `election_id`, `box_id`, `ballot_style_id`(각 u32 길이 접두), `proof_system_id: u16`, `option_count: u16`, `chunk_count: u8`, 커밋먼트 배열(u32 개수 접두), 공표값 `a_{t,j}` 배열(u32 개수 접두, t 외측·j 내측).

## API

```rust
use ityv_crypto::{HybridSigningKey, Purpose, sign_hybrid, verify_hybrid};
use rand_core::SeedableRng;

let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7); // 실제 장치: 챔버 모듈 기여
let key = HybridSigningKey::generate(&mut rng);
let purpose = Purpose::new(b"checkpoint").ok_or("bad purpose")?;
let obj = b"ITYV...object bytes";
let sig = sign_hybrid(&key, &purpose, obj, &mut rng)?;
let verified = verify_hybrid(&key.verifying_key(), &purpose, obj, &sig)?;
let () = verified.into_inner();
# Ok::<(), Box<dyn core::error::Error>>(())
```

- `Scalar`: 정규형만 존재하는 스칼라. 산술은 연산자가 아니라 `add`/`sub`/`mul`/`neg`/`invert` 메서드다(헌법의 산술 lint를 호출자도 그대로 지키게 한다).
- `Bases::derive()`: 세 베이스를 한 번 유도해 재사용한다. `commit`, `verify_opening`, `sum_commitments`, `verify_aggregate`, `decode_digits`.
- `Statement::new`가 선택지 수와 청크 수의 관계(`k = ⌈(m+2)/9⌉`)를 강제한다. `prove`는 증인이 커밋먼트를 실제로 여는지 먼저 확인한다. `verify`는 모든 `a_{t,j}`를 재계산해 `Σ c_t`를 대조한다.
- `split`/`reconstruct`: `reconstruct`는 share 값을 쓰기 전에 정족수를 판정하고, 임계치를 넘는 share는 다항식과의 일치를 검사해 `InconsistentShares`로 보고한다.

## 의존성과 선택 이유

모든 버전은 정확히 고정한다(`=x.y.z`). `backend/`만 알고리즘 크레이트를 import한다.

| 크레이트 | 버전 | 라이선스 | 이유 |
|---|---|---|---|
| `sha3` | 0.12.0 | MIT/Apache-2.0 | RustCrypto SHA3-512; `no_std`, 순수 Rust |
| `curve25519-dalek` | 5.0.0 | BSD-3-Clause | Ristretto255; `curve25519_dalek_backend="fiat"`로 fiat-crypto 검증 필드 산술 선택 가능 |
| `ed25519-dalek` | 3.0.0 | BSD-3-Clause | Ed25519 엄격 검증(`verify_strict`), 약한 키 거부 |
| `x25519-dalek` | 3.0.0 | BSD-3-Clause | X25519, 비기여 키 검출(`was_contributory`) |
| `ml-dsa` | 0.1.1 | MIT/Apache-2.0 | FIPS 204 ML-DSA-87, hedged 서명, 컨텍스트 문자열 |
| `ml-kem` | 0.3.3 | MIT/Apache-2.0 | FIPS 203 ML-KEM-1024, 시드 키 생성, 캡슐화 키 모듈러스 검사 |
| `slh-dsa` | 0.2.0-rc.5 | MIT/Apache-2.0 | FIPS 205 SLH-DSA-SHAKE-256s. **사전 릴리스**: 정식판이 나오면 교체 대상 |
| `poly1305` | 0.9.1 | MIT/Apache-2.0 | 일회성 MAC |
| `chacha20poly1305` | 0.11.0 | MIT/Apache-2.0 | KEM 대체 경로의 AEAD |
| `zeroize` | 1.9.1 | MIT/Apache-2.0 | 비밀 소거 |
| `rand_core` | 0.10.1 | MIT/Apache-2.0 | `CryptoRng` 경계 |
| `subtle` | 2.6.1 | BSD-3-Clause | 상수 시간 비교 |

알려진 중복: `slh-dsa 0.2.0-rc.5`가 `sha3 0.11`을, 나머지가 `sha3 0.12`를 쓴다(`cargo deny`의 `multiple-versions = warn`). `slh-dsa` 정식판에서 해소된다.

## 검증

```bash
cargo test --locked -p ityv-crypto                 # V1: 단위·속성·KAT·회귀 벡터
ITYV_UPDATE_VECTORS=1 cargo test --locked -p ityv-crypto --test vectors   # 회귀 벡터 재생성
cargo kani -p ityv-crypto                          # V2: Kani 하네스
cargo mutants -p ityv-crypto --timeout 300         # V1: 변이 테스트
cargo build --locked -p ityv-crypto --target thumbv7em-none-eabihf   # no_std 빌드
```

알려진 답 벡터(독립 출처): SHA3-512는 NIST FIPS 202 벡터와 Python `hashlib`로 계산한 도메인 해시, Ed25519·X25519·Poly1305·`ChaCha20-Poly1305`는 Python `cryptography`로 계산했다. ML-DSA·ML-KEM·SLH-DSA는 백엔드 크레이트의 자체 FIPS 벡터 테스트에 의존하며, 이 크레이트의 `vectors/crypto.txt`는 이 구현이 만든 **회귀** 벡터다(독립 출처가 아님을 파일 머리에 적었다).

Kani 하네스: 선택지·청크 인덱스 경계, 자릿수 지수(`26·(t−9j)`), 비트 설정·추출, 묶음 범위 검사, 청크 수 올림 나눗셈, 증명 인코딩 길이, 임계치·구성원 경계, 구성원 평가점, 챔버 인덱스·`s_rest` 평가점, 접근구조 Γ 판정, 패드 XOR, purpose 알파벳, 길이 접두.

## 테스트 코드의 lint 완화

`tests/` 아래 통합 테스트 크레이트는 TCB 밖이다. 각 파일 머리에 사유를 적고 `unwrap`, `expect`, `panic`, 인덱싱, 산술 부작용 lint만 완화한다. TCB 크레이트(`src/`)에는 어떤 완화도 없다.
