# ADR-0037: 시점확인 토큰 크레이트 `ityv-tsa` — 핀 형식, 엄격한 부분집합, 알고리즘, 의존성

> English summary: ADR-0034 §6 put RFC 3161 token parsing and verification in a small separate `no_std` crate. This ADR records the decisions ADR-0034 leaves open, as implemented by `crates/ityv-tsa`. The pin a genesis holds per authority is a canonical byte string: the SHA-256 of the authority's signing certificate, a digest mask, a signature-algorithm mask, a flag that accepts an ESS signing-certificate v1 (SHA-1) binding, one to eight policy OIDs and optionally the certificate itself (used only when a token embeds none). The DER subset is strict and applies to the whole token, including the parts not interpreted; the profile refuses CRLs, more than one signer, non-certificate choices, unknown critical extensions in the `TSTInfo` or the certificate, a `DEFAULT` value written out (including an explicit SHA-256 in ESS v2), a `tsa` name other than the certificate subject, and a `genTime` outside the certificate's validity. Supported signatures are RSASSA-PKCS1-v1_5 with SHA-256/384/512 (2048–4096-bit modulus, `2^16 < e < 2^256`) and ECDSA P-256/SHA-256, P-384/SHA-384 and P-384/SHA-512; RSA-PSS is not supported. RSA is verified by this crate over `crypto-bigint` (`s^e mod n`, then the whole EMSA-PKCS1-v1_5 block is built and compared), not by the `rsa` crate, whose RUSTSEC-2023-0071 the workspace's `deny.toml` does not ignore. ESS v1 is accepted only when the pin allows it, because a real public authority (freetsa.org) uses it; the certificate is already fixed by the SHA-256 pin, so a SHA-1 collision cannot substitute one. A real freetsa.org token passes every strict rule under such a pin. The crate returns only what is signed or pinned; the ledger wiring (the `TimestampRecord` schema, the genesis authority list and the checkpoint stage) is the next step.

- 상태: 제안
- 날짜: 2026-11-04
- 관련: ADR-0034(시점확인), ADR-0006(암호 방향), ADR-0015(암호 크레이트와 백엔드), ADR-0028(genesis 인코딩); CONSTITUTION §1, §3; RFC 3161, RFC 5652, RFC 5035, RFC 5816, RFC 5280, RFC 8017, FIPS 186-5

## 맥락

ADR-0034는 RFC 3161 토큰을 엄격한 DER 부분집합으로 읽고 genesis가 고정한 기관의 인증서·정책·해시 알고리즘으로 검증하라고 정했다. 그러나 다음은 정하지 않았다.
- genesis가 담을 기관 핀의 정확한 형식과, 인증서를 토큰에서 찾을지 핀에 둘지.
- "엄격한 부분집합"의 경계: 어떤 DER 위반과 어떤 CMS·X.509 구성을 거부하는가.
- ESS 서명 인증서 속성 v1(SHA-1)을 받을지.
- 지원할 서명 알고리즘과 키 크기, RSA 구현.
- 실제 기관의 토큰이 그 엄격성을 통과하는지.

실제 토큰으로 확인했다. OpenSSL 3.0 `openssl ts`가 만든 토큰과 freetsa.org(무료 공개 기관)의 토큰을 받아 구조를 읽었다. freetsa.org는 ECDSA P-384와 SHA-512로 서명하고, ESS 서명 인증서를 v1(SHA-1)로 두며, 기관 인증서와 루트 인증서를 함께 넣는다.

## 결정

1. **핀 형식.** genesis의 기관 항목은 이 바이트열을 담는다(`PinnedTsa::from_bytes`, `src/pin.rs`).
   - 형식 버전 `1`, 서명 인증서 DER의 SHA-256(32바이트), 다이제스트 마스크(SHA-256·384·512), 서명 알고리즘 마스크(아래 6개), 플래그(`0x01`: ESS v1 허용), 정책 목록(`u16` 길이, DER OID 1–8개, 인코딩 엄격 오름차순), 인증서(`u16` 길이, 0이면 없음).
   - 모르는 비트, 빈 마스크, 정렬되지 않거나 겹친 정책, 해시가 맞지 않는 인증서, 길이가 맞지 않는 바이트열은 거부한다. 그래서 핀마다 인코딩이 하나다.
   - 핀의 해시는 SHA-256이다. 인증서 지문을 공표하는 관례(`openssl x509 -fingerprint -sha256`)이고 RFC 5035 ESS v2의 기본 해시다.
   - 인증서 자체는 선택이다. ADR-0034 §3의 요청은 `certReq`를 넣으므로 토큰이 인증서를 담는다. 토큰 안에서 핀의 해시를 가진 인증서를 쓰고, 없을 때만 핀의 사본을 쓴다(`CertificateSource`).
   - 핀에 기관 ID, 운영 주체, 정부 운영 여부는 두지 않는다. 그것은 genesis 항목의 다른 필드이고 연결 단계가 정한다.

2. **엄격한 부분집합.** 토큰 전체(최대 16 KiB, 깊이 32)에 같은 DER 규칙을 적용한다. 해석하지 않는 부분(이름, 알 수 없는 서명 속성, 서명되지 않은 속성, 체인 인증서, 비필수 확장 값의 바깥)도 재귀적으로 검사한다.
   - 태그는 한 옥텟(번호 0–30), 길이는 확정·최소 형식이고 길이 옥텟은 둘까지다. 부정 길이, 비최소 길이, `0x83` 이상은 거부한다.
   - `BOOLEAN`은 `0x00`/`0xFF`, `INTEGER`는 최소 2의 보수, `NULL`은 빈 값, OID는 최소 arc와 완결, `BIT STRING`의 패딩은 0, `SET`과 `SET OF`는 인코딩 오름차순(인증서 집합 포함), 문자열·시각은 원시 형식만. 모든 `SEQUENCE`는 끝까지 읽는다.
   - `DEFAULT` 값을 적은 인코딩은 거부한다: `ordering FALSE`, 확장의 `critical FALSE`, ESS v2의 명시적 SHA-256.
3. **CMS·ESS 프로필.**
   - `SignedData` 버전 3, `digestAlgorithms`는 서명자의 알고리즘 하나, 내용은 `id-ct-TSTInfo`이고 분리되지 않음, 인증서는 X.509 `Certificate`만 8개까지, CRL은 거부, `SignerInfo`는 정확히 하나이고 버전이 식별자 형식과 맞아야 한다(발급자·일련번호 1, 주체 키 식별자 3).
   - 서명 속성은 필수다. 내용 형식(`id-ct-TSTInfo`), 메시지 다이제스트(`TSTInfo`의 해시), ESS 서명 인증서가 각각 한 번, 값 하나씩이다. 서명은 `[0]` 태그를 `SET`으로 바꾼 DER 바이트 위에서 검증한다(RFC 5652 §5.4). 그 밖의 서명 속성(서명 시각 등)과 서명되지 않은 속성은 쓰지 않지만 부분집합 안이어야 한다.
   - ESS는 v2(RFC 5035, RFC 5816)를 받는다. 해시 알고리즘은 핀의 다이제스트 집합 안이어야 한다. 첫 식별자가 서명자 인증서의 해시여야 하고 `issuerSerial`이 있으면 그 인증서의 발급자와 일련번호여야 한다.
   - ESS v1(SHA-1)은 핀의 플래그가 허용할 때만 받는다. freetsa.org가 v1을 쓰고, 다른 공개 기관도 OpenSSL 기본값 때문에 v1을 쓰는 경우가 많다. 서명자 인증서는 SHA-256 핀으로 정해지고 서명은 그 인증서의 키로 검증하므로, ESS는 일치 확인일 뿐이다. SHA-1 충돌로 다른 인증서를 끼워 넣어도 핀을 바꾸지 못한다. SHA-1은 각인과 서명에는 쓰지 않는다.
4. **서명자 인증서 프로필(경로 검증 없음).** X.509 v3, 확장 키 용도는 정확히 한 번, 필수(critical), `id-kp-timeStamping` 하나만(RFC 3161 §2.3). 키 용도가 있으면 디지털 서명과 부인 방지만, 기본 제약이 있으면 CA 아님. 그 밖의 필수 확장은 거부하고, 처리하는 확장의 반복도 거부한다. 서명자 식별자는 그 인증서를 가리켜야 하고, `TSTInfo`의 `tsa`가 있으면 인증서 주체와 같은 `directoryName`이어야 하며(RFC 3161 §2.4.2), `genTime`은 인증서 유효기간 안이어야 한다. 발급자의 서명은 검증하지 않는다.
5. **`TSTInfo`.** 버전 1, 핀의 정책, 기대 각인과 같은 알고리즘과 값, 일련번호 160비트 이하, nonce 256비트 이하, 정확도의 밀리·마이크로초 1–999, 비필수 확장은 무시하고 필수 확장은 모두 거부한다(이해하는 확장이 없다). `genTime`은 `YYYYMMDDhhmmss[.f]Z`이고 소수는 1–9자리, 끝이 0이 아니다. 윤초(60)와 1970년 이전은 Unix 시각으로 나타낼 수 없어 거부한다. 결과는 Unix 초와 나노초다.
6. **서명 알고리즘.** 핀이 허용한 것만, 그리고 다음 여섯 가지만 지원한다.
   - RSASSA-PKCS1-v1_5와 SHA-256·384·512. 모듈러스 2048–4096비트, 공개 지수는 홀수이고 `2^16 < e < 2^256`(FIPS 186-5 §5.4). 서명 길이는 정확히 모듈러스 길이, 표현값은 `n`보다 작아야 한다. 복호한 블록은 파싱하지 않는다. `00 01 FF…FF 00 DigestInfo`(`NULL` 매개변수) 전체를 만들어 비교한다(Bleichenbacher 2006 류의 위조 방지). `rsaEncryption`과 `sha*WithRSAEncryption` 표기를 모두 받되 후자는 서명자 다이제스트와 같아야 한다.
   - ECDSA P-256/SHA-256, P-384/SHA-384, P-384/SHA-512(freetsa.org). 다이제스트가 곡선보다 짧은 조합(P-256과 SHA-384 등)은 받지 않는다. 공개키는 비압축 점만, 서명은 엄격한 DER `Ecdsa-Sig-Value`이고 `r`, `s`는 `[1, n−1]`.
   - RSA-PSS는 지원하지 않는다. 매개변수 구조와 MGF1, 복호 블록 해석이 필요해 이번 범위를 넘는다. 지정 기관이 PSS를 쓰면 새 ADR로 더한다.
7. **의존성.** `sha2` =0.11.1, `sha1` =0.11.0, `crypto-bigint` =0.7.10, `p256`·`p384` =0.14.0(`ecdsa` =0.17.0), 모두 `default-features = false`. RSA는 `rsa` 크레이트를 쓰지 않는다. 그 크레이트는 RUSTSEC-2023-0071(Marvin, 개인키 연산의 시간 누출)이 있고 `deny.toml`이 `ignore = []`이다. 검증에는 공개키 연산 `s^e mod n` 하나면 되므로, `elliptic-curve`가 이미 쓰는 `crypto-bigint`의 고정폭 몽고메리 연산으로 직접 계산한다. 비밀이 없으니 상수 시간은 필요 없고 정확성이 중요하다. 그래서 인코딩을 만들어 비교하고 경계(`s ≥ n`, 짧은 `s`)를 시험한다.
8. **검사 순서.** 구조(DER·CMS·`TSTInfo`) → 인증서 선택과 프로필 → 서명자 식별자 → 핀의 허용 알고리즘 → ESS → 메시지 다이제스트 → 서명 → 각인·정책·`tsa`·유효기간. 서명으로 진정성을 먼저 세우고 내용을 기대값과 비교한다. 순서가 고정이므로 같은 토큰은 같은 오류를 낸다. 연결 단계는 어떤 오류든 `TimestampInvalid`로 다룬다(ADR-0034 §7).

## 결과

- `ityv-verify`는 `VerifiedTimestamp`만 받는다: 시각, 정책, 일련번호, nonce, 정확도, 각인, 인증서 해시와 출처, 알고리즘. 모두 서명됐거나 핀·호출자가 준 값이다.
- OpenSSL이 만든 6개 알고리즘의 토큰과 freetsa.org의 실제 토큰이 모두 엄격한 규칙을 통과한다(freetsa.org는 ESS v1 허용 핀으로). 규칙마다 한 곳만 어긴 조작 토큰이 그 규칙의 오류로 거부된다.
- 토큰 TCB는 이 크레이트와 RustCrypto 의존성 15개다. `ityv-verify`와 `ityv-encoding`은 바뀌지 않았다.

## 비용과 위험

- 엄격성은 실제 기관과 어긋날 수 있다(정렬되지 않은 인증서 집합, ESS v2의 명시적 SHA-256, 이름 형식, 윤초). ADR-0034가 정한 대로 지정 기관의 실제 토큰으로 채택 전에 확인한다. 어긋나면 조용히 풀지 않고 이 ADR을 고친다.
- 새 의존성 15개는 cargo-vet 면제로 들어왔다. 감사 기록으로 바꾸는 것은 다른 의존성과 같이 남은 일이다.
- RSA 검증은 자체 구현이다. 범위가 작고(모듈러 거듭제곱 하나와 비교) 실제 토큰, 경계값, 변이 시험으로 확인하지만 형식 검증은 아니다.

## 대안

- **`rsa` 크레이트와 좁은 `ignore`.** 공개키 검증 경로는 RUSTSEC-2023-0071과 무관하지만, 감사 예외가 생기고 개인키 코드까지 TCB에 들어온다. 기각.
- **`der`·`cms`·`x509-cert` 크레이트.** 범용 파서는 BER 관용과 넓은 구조를 갖고, ADR-0034가 요구한 부분집합보다 크다. 크기와 깊이를 고정한 자체 읽기가 Kani로 검사하기 쉽다. 기각.
- **ESS v1 전면 거부.** 실제 공개 기관이 v1을 쓴다. 핀별 허용으로 둔다.
- **핀에 인증서 대신 공개키(SPKI)만.** EKU·유효기간·주체 확인에 인증서가 필요하다. 기각.

## 연결되는 검증

- `crates/ityv-tsa/tests/tokens.rs`, `tests/strict.rs`, `tests/proptests.rs`, 모듈 단위 테스트, `kani/proofs.rs`, `fuzz/`; 시험 벡터 `tests/vectors/make.sh`, `tests/vectors/freetsa/fetch.sh`.
- 남은 일(연결 단계): `TimestampRecord` 스키마와 genesis의 기관 목록(핀 바이트, 운영 주체, 정부 운영 여부), 체크포인트 단계의 역산 금지·앵커 창 판정(VC-114..118), `TimestampMismatch`·`TimestampInvalid` 보류.
