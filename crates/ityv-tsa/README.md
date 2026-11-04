# ityv-tsa

> English summary: The RFC 3161 timestamp token verifier of ityv (ADR-0034 §6, ADR-0037), kept out of the core verifier. A `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate with its own strict DER reader (single-octet tags, definite minimal lengths of at most two octets, at most 32 levels and 16 KiB per token, minimal `INTEGER`s, `BOOLEAN` `0x00`/`0xFF`, valid object identifiers, sorted `SET`s, no `DEFAULT` written out, every `SEQUENCE` consumed, and the same rules inside every part it does not interpret). `verify_token(token, pin, expected)` checks `ContentInfo` → `SignedData` (version 3, one digest algorithm, `id-ct-TSTInfo` content, X.509 certificates only, no CRLs, exactly one `SignerInfo`), the signed attributes (content type, message digest over the `TSTInfo`, ESS signing-certificate v2, or v1 with SHA-1 only when the pin allows it), the signer's certificate (the embedded one whose SHA-256 the genesis pins, or the pin's own copy; X.509 v3, critical extended key usage of exactly `id-kp-timeStamping`, digital-signature/non-repudiation key usage, not a CA, no unknown critical extension, `genTime` within its validity; no path validation), the signature over the DER `SET OF` signed attributes (RSASSA-PKCS1-v1_5 with SHA-256/384/512 for 2048–4096-bit moduli, computed with `crypto-bigint` and checked by encoding and comparing the whole block; ECDSA P-256/SHA-256, P-384/SHA-384 and P-384/SHA-512 through `p256`/`p384`), and the `TSTInfo` (version 1, a pinned policy, the expected imprint, a serial of at most 160 bits, a strict `GeneralizedTime`, accuracy, ordering, nonce, a `tsa` name equal to the certificate subject, no critical extension). It returns `VerifiedTimestamp`: the time as Unix seconds and nanoseconds, policy, serial, nonce, accuracy, ordering, imprint, the pinned certificate's hash and where the certificate came from. The pin is a byte string the genesis can hold. Verification: V1 (real OpenSSL tokens for every algorithm, a real freetsa.org token, one crafted token per rule, every truncation, proptests of arbitrary and mutated tokens, cargo-mutants), V2 (Kani harnesses for the reader and the time parsers); a cargo-fuzz target is in `fuzz/`.

## 무엇인가

ADR-0034의 시점확인 토큰을 검증하는 TCB 크레이트다. DER·CMS 파서와 RSA·ECDSA 검증이 핵심 검증기(`ityv-verify`)의 TCB를 키우지 않도록 따로 두었고(ADR-0034 §6), 다른 워크스페이스 크레이트에 의존하지 않는다. 결정과 이유는 `docs/adr/ADR-0037-tsa-crate.md`에 있다. 장부와의 연결(`TimestampRecord`, genesis의 기관 목록, 체크포인트 단계)은 다음 단계다.

| 모듈 | 내용 | 근거 |
|---|---|---|
| `der` | 엄격한 DER 읽기: 한 옥텟 태그, 최소·확정 길이(길이 옥텟 둘까지), 깊이 32, 원시 타입 규칙, `SET` 정렬, 해석하지 않는 부분의 재귀 검사 | X.690 §8, §10, §11 |
| `time` | `GeneralizedTime`(`YYYYMMDDhhmmss[.f]Z`, 소수 1–9자리, 끝 0 없음), `UTCTime`, 1970년 이후 Unix 초 | X.690 §11.7–11.8, RFC 5280 §4.1.2.5 |
| `cms` | `ContentInfo`, `SignedData`, `SignerInfo`, 서명 속성, ESS 인증서 식별자 | RFC 5652, RFC 2634, RFC 5035, RFC 3161 §2.4.2 |
| `tst` | `TSTInfo`, `Accuracy` | RFC 3161 §2.4.2 |
| `cert` | 서명자 인증서: 일련번호, 발급자, 주체, 유효기간, 공개키, 확장 | RFC 5280, RFC 3161 §2.3 |
| `alg` | 다이제스트·서명 알고리즘, 핀의 허용 집합, `Imprint` | RFC 5754, RFC 5758, RFC 8017 |
| `rsa` | RSASSA-PKCS1-v1_5 검증: `s^e mod n` 뒤 EMSA 전체를 만들어 비교 | RFC 8017 §8.2.2, §9.2 |
| `ecdsa` | P-256·P-384 ECDSA 검증, 엄격한 `Ecdsa-Sig-Value` | FIPS 186-5, RFC 5758 §3.2 |
| `pin` | `PinnedTsa`: genesis가 담는 바이트 형식 | ADR-0034 §1, ADR-0037 |
| `verify` | `verify_token`, `VerifiedTimestamp` | ADR-0034 §4 |

## 쓰는 법

```text
genesis의 기관 항목 ──▶ PinnedTsa::from_bytes(pin) ─┐
체크포인트 객체 해시 ─▶ Imprint::of(Sha512, &hash) ─┤
장부의 DER 토큰 ────────────────────────────────────┴─▶ verify_token
                                                         │ Err(TsaError::…) → TimestampInvalid (연결 단계)
                                                         ▼
                                  VerifiedTimestamp: gen_time(), policy(), serial(), nonce(),
                                  accuracy(), imprint(), certificate_sha256(), certificate_source()
```

핀의 바이트 형식(`src/pin.rs`): 형식 버전 1, 서명 인증서 DER의 SHA-256(32), 다이제스트 마스크, 서명 알고리즘 마스크, 플래그(ESS v1 허용), 정책 목록(DER OID 1–8개, 오름차순, `u16` 길이 접두), 인증서(선택, `u16` 길이 접두). 모르는 비트, 정렬되지 않거나 겹친 정책, 길이가 맞지 않는 핀은 거부하므로 핀마다 인코딩이 하나다. `PinnedTsa::new`와 `encode`가 같은 형식을 만든다.

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음(워크스페이스 lint 집합, Kani 하네스, 모든 절단과 변형에 대한 속성 테스트).
- 받아들인 토큰은 전부 엄격한 DER 부분집합 안에 있다. 해석하지 않는 이름, 서명되지 않은 속성, 체인 인증서도 같은 규칙으로 검사한다.
- 반환값은 모두 서명됐거나(`TSTInfo` 필드) 핀이나 호출자가 준 것(인증서 해시, 각인)이다. 서명된 바이트를 바꾸는 변형은 받아들여지지 않고, 받아들여진 변형은 결과를 바꾸지 않는다(`tests/proptests.rs`).
- 핀이 허용한 다이제스트(각인, `SignerInfo`, ESS v2)와 서명 알고리즘만 쓴다. 지원하지 않는 조합(P-256과 SHA-384, 1024비트 RSA, SHA-1 각인)은 핀과 상관없이 거부한다.
- 거부마다 `TsaError`의 고유 변형이 있다. 검사 순서(구조 → 인증서 → 허용 알고리즘 → 서명 속성 → 서명 → 내용)가 고정이므로 같은 토큰은 언제나 같은 오류를 낸다.

보장하지 않는 것:
- 기관이 적은 시각이 참이라는 것. 기관 하나는 아무 시각에나 서명할 수 있다. ADR-0034는 서로 다른 운영 주체의 기관 둘 이상을 요구하고, 그 판정은 연결 단계의 체크포인트 단계가 한다.
- 인증서의 폐지 여부, 루트까지의 경로. 인증서는 해시로 고정되며 그 고정의 출처는 genesis다.
- 양자 내성. 토큰의 RSA·ECDSA 서명은 보강 증거이고 신뢰의 뿌리는 증인 정족수의 하이브리드 서명이다(ADR-0034 §5).
- 실제 지정 기관의 토큰이 이 엄격성을 통과한다는 것. freetsa.org 토큰은 통과했고(ESS v1 허용 핀), 지정 기관의 실제 토큰은 채택 전에 확인한다(ADR-0034, ADR-0037).

## 의존성

정확한 버전으로 고정하고 `default-features = false`로 쓴다. 모두 RustCrypto 프로젝트의 크레이트이고 `ityv-crypto`와 같은 세대(`digest` 0.11, `crypto-bigint` 0.7)다. 검증 경로만 호출한다.

| 크레이트 | 버전 | 쓰는 곳 | 이유 |
|---|---|---|---|
| `sha2` | =0.11.1 | 각인, 메시지 다이제스트, 서명 속성, 인증서 핀 | 이미 워크스페이스에 있음(`ed25519-dalek`, `slh-dsa`) |
| `sha1` | =0.11.0 | ESS 서명 인증서 v1의 인증서 해시만, 핀이 허용할 때만 | 실제 기관(freetsa.org)이 v1을 쓴다. 인증서는 SHA-256 핀으로 이미 정해지므로 SHA-1 충돌로 바꿔치기할 것이 없다(ADR-0037 3) |
| `crypto-bigint` | =0.7.10 | RSA `s^e mod n`(4096비트 고정폭 몽고메리) | `elliptic-curve`가 쓰는 판과 같아 중복이 없다. `rsa` 크레이트는 RUSTSEC-2023-0071(개인키 연산의 시간 누출)로 `deny.toml`의 `ignore = []`에 걸리고, 검증에는 공개키 연산 하나면 된다 |
| `p256`, `p384` | =0.14.0 | ECDSA 검증(`ecdsa` 0.17.0의 `VerifyingKey`) | `ecdsa` 기능이 서명용 `rfc6979`도 끌어오지만 호출하지 않는다 |

새로 잠금 파일에 들어온 크레이트 15개(`base16ct`, `cpubits`, `crypto-bigint`, `ecdsa`, `elliptic-curve`, `ff`, `group`, `p256`, `p384`, `primefield`, `primeorder`, `rfc6979`, `sec1`, `sha1`, `wnaf`)는 `supply-chain/config.toml`에 다른 의존성과 같은 방식으로 면제를 두었다. 라이선스는 모두 Apache-2.0 또는 MIT다.

## 시험 벡터

`tests/vectors/make.sh`가 OpenSSL 3.0(`openssl ts`)으로 일회용 기관(RSA-2048·3072·4096, P-256, P-384, 크기 거부용 RSA-1024)과 자체 서명 인증서(CA 아님, 키 용도 디지털 서명·부인 방지, 필수 EKU timeStamping), 토큰을 만들고, `openssl ts -verify`로 확인하고, OpenSSL이 읽은 값을 `manifest.txt`에 적는다. 같은 RSA-3072 키로 프로필 규칙 하나씩을 어긴 인증서 6개(비필수 EKU, EKU 둘, EKU 없음, CA, 인증서 서명 키 용도, 모르는 필수 확장)도 만든다. `forge.py`(표준 라이브러리만)는 `rsa3072-sha384.tst`를 한 곳씩 바꾼 조작 토큰 50개를 만들고, 서명 바이트가 바뀌면 같은 키로 다시 서명해 시험하는 규칙 하나만 어기게 한다(경계값: 160비트 일련번호, 256비트 nonce, 인증서 8개, 유효기간의 양 끝은 받는 쪽). 개인키는 임시 디렉터리에만 있고 커밋하지 않는다. 다시 만들면 모든 파일이 바뀌고 테스트는 `manifest.txt`를 읽는다. `tests/vectors/freetsa/`는 freetsa.org의 실제 토큰과 인증서이고 `fetch.sh`가 받은 방법이다(빈 임시 디렉터리에 받고 openssl로 읽기만 한다).

## 검증

- V1: `tests/tokens.rs`(유효 토큰 9개의 시각·각인·정책·일련번호·nonce·정확도·알고리즘·인증서, 핀의 다이제스트·서명·ESS v1 허용, 다른 기관, 각인·정책 불일치, 지원하지 않는 조합, 서명 바이트 뒤집기, `TSTInfo` 바이트 변경, freetsa.org 토큰), `tests/strict.rs`(조작 토큰 규칙마다와 받는 경계값, 인증서 프로필 규칙마다, 키 식별자로 지목한 서명자, 비정규 DER: 비최소 길이·부정 길이·긴 길이·뒤따르는 바이트, 모든 오프셋의 절단, 크기 상한), `tests/proptests.rs`(임의 바이트, 유효 토큰의 무작위 변형, 임의 핀), 모듈 단위 테스트(DER 규칙, 시각과 독립 참조 구현, RSA 경계 `s ≥ n`·짧은 `s`·크기·지수, ECDSA 범위, 핀 왕복), cargo-mutants.
- V2: `kani/proofs.rs`(길이 헤더의 정규성과 경계(260바이트 입력까지, 짧은·`0x81`·`0x82` 형식 전부), 정규 헤더 수락, 트리 검사의 전역성(4바이트: CBMC 메모리 한계, 더 깊은 트리는 단위·속성 테스트), `SEQUENCE` 정확 소비, `BOOLEAN`·`INTEGER`·OID 규칙, `SET` 순서, `GeneralizedTime`·`UTCTime` 전역성, 참조 구현과의 시각 일치(윤년 규칙마다 하네스 하나, 연도는 구체값이고 월·일·시각은 기호값; 임의 연도는 속성 테스트)). 하네스 15개, 가장 긴 것이 4분 안쪽. `cargo kani -p ityv-tsa`.
- 퍼징: `fuzz/`(워크스페이스 밖, nightly와 cargo-fuzz). CI에서는 돌리지 않고 속성 테스트가 대신한다.
