# ADR-0037: 시점확인 토큰 크레이트 `ityv-tsa` — 핀 형식, 엄격한 부분집합, 알고리즘, 의존성

> English summary: ADR-0034 §6 put RFC 3161 token parsing and verification in a small separate `no_std` crate. This ADR records the decisions ADR-0034 leaves open, as implemented by `crates/ityv-tsa`. The pin a genesis holds per authority is a canonical byte string: the SHA-256 of the authority's signing certificate, a digest mask, a signature-algorithm mask, a flag that accepts an ESS signing-certificate v1 (SHA-1) binding, one to eight policy OIDs and optionally the certificate itself (used only when a token embeds none). The DER subset is strict and applies to the whole token; the parts not interpreted get the DER checks only, and the two unsigned sets (the embedded certificates and the unsigned attributes) may be in any order, since anyone can reorder them and the certificate is found by its pinned hash. The profile refuses CRLs, more than one signer, non-certificate choices, unknown critical extensions in the `TSTInfo` or the certificate (a critical certificate policies extension is accepted and ignored: Korean accredited and government profiles mark it critical, and trust comes from the pin, not from policy processing), a `DEFAULT` value written out (including ESS v2's `{id-sha256}` with absent parameters; `{id-sha256, NULL}` is another value and is accepted), a `tsa` name other than the certificate subject, an accuracy above one hour, and a `genTime` outside the certificate's validity. Supported signatures are RSASSA-PKCS1-v1_5 with SHA-256/384/512 (2048–4096-bit modulus, `2^16 < e < 2^256`) and ECDSA P-256/SHA-256, P-384/SHA-384 and P-384/SHA-512; RSA-PSS is not supported. RSA is verified by this crate over `crypto-bigint` (`s^e mod n`, then the whole EMSA-PKCS1-v1_5 block is built and compared), not by the `rsa` crate, whose RUSTSEC-2023-0071 the workspace's `deny.toml` does not ignore. ESS v1 is accepted only when the pin allows it, because a real public authority (freetsa.org) uses it; the certificate is already fixed by the SHA-256 pin, so a SHA-1 collision cannot substitute one. A real freetsa.org token passes every strict rule under such a pin. The crate returns only what is signed or pinned (except the certificate's source, a diagnostic read from the unsigned certificate set), plus `earliest()`/`latest()`, genTime ± accuracy computed without overflow, the interval the checkpoint stage must judge with. Every `TsaError` variant a token can produce, other than `Der(_)` (covered by the DER unit tests and crafted tokens), has a test token that breaks only that rule (`tests/rules.rs`, checked against an exhaustive `match`). For the ledger wiring (the `TimestampRecord` schema, the genesis authority list and the checkpoint stage, the next step) this ADR records that token bytes are not unique (unsigned parts and an ECDSA signature's `s` can change without changing the result), so tokens are counted per authority; that the crate takes no expected nonce, so the requester checks it; and that a pin holds one certificate, so an authority that rotates its certificate during an election needs several pins.

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
   - 개정(ADR-0039 리뷰, 2026-11-05; 둘째 리뷰 반영): `PinnedTsa::signer_key()`는 사본이 있을 때 그 서명자(`SignerKey`)를 돌려준다: 서명 키(RSA 모듈러스나 EC 점, 한 서명자는 한 값)와 인증서의 `notBefore`·`notAfter`. 사본이 서명자 인증서로 읽히고, EC 점이 곡선 위에 있으며(`p256`·`p384`로 해독, 아니면 `InvalidEcPoint`), 핀이 허용한 서명 알고리즘 가운데 그 키가 만들고 다이제스트도 허용된 것이 있을 때만이다. `verify_token`의 검사와 오류 순서는 그대로다(곡선 밖의 점은 서명 검증에서 `InvalidEcPoint`). 이 크레이트의 형식에서 사본은 여전히 선택이고, 사본을 요구하는 것은 연결 단계의 genesis 규칙이다(ADR-0039 2항: 한 키를 두 인증서로 핀하면 한 기관이 둘로 셀 수 있다).
   - 핀에 기관 ID, 운영 주체, 정부 운영 여부는 두지 않는다. 그것은 genesis 항목의 다른 필드이고 연결 단계가 정한다.

2. **엄격한 부분집합.** 토큰 전체(최대 16 KiB, 깊이 32)에 같은 DER 규칙을 적용한다. 해석하지 않는 부분(이름, 알 수 없는 서명 속성, 서명되지 않은 속성, 체인 인증서, 비필수 확장 값의 바깥)도 같은 DER 규칙으로 끝까지 검사한다. 다만 그 안의 구조는 모르므로, 그 안에 `DEFAULT` 값을 적은 것(체인 인증서 확장의 `critical FALSE` 등)은 알아채지 못한다.
   - 태그는 한 옥텟(번호 0–30), 길이는 확정·최소 형식이고 길이 옥텟은 둘까지다. 부정 길이, 비최소 길이, `0x83` 이상은 거부한다.
   - `BOOLEAN`은 `0x00`/`0xFF`, `INTEGER`는 최소 2의 보수, `NULL`은 빈 값, OID는 최소 arc와 완결, `BIT STRING`의 패딩은 0, `SET OF`는 인코딩 오름차순(X.690 §11.6), 문자열·시각은 원시 형식만. 해석하는 구조의 `SEQUENCE`는 끝까지 읽는다.
   - 서명되지 않는 두 집합, `SignedData`의 인증서 집합과 `SignerInfo`의 서명되지 않은 속성은 원소 순서를 보지 않는다. 원소 하나하나는 엄격하게 검사한다. 누구나 서명을 깨지 않고 순서를 바꿀 수 있어 순서가 아무것도 보장하지 않고, 인증서는 핀의 해시로만 찾는다. 기관이 인증서를 체인 순서로 넣어도 거부할 이유가 없다.
   - 해석하는 구조에서 `DEFAULT` 값을 적은 인코딩은 거부한다: `ordering FALSE`, 확장의 `critical FALSE`, ESS v2의 `hashAlgorithm` `{id-sha256}`(매개변수 없음, RFC 5035의 기본값 그 자체). `{id-sha256, NULL}`은 기본값과 다른 값이어서 DER도 적으므로 받는다.
3. **CMS·ESS 프로필.**
   - `SignedData` 버전 3, `digestAlgorithms`는 서명자의 알고리즘 하나, 내용은 `id-ct-TSTInfo`이고 분리되지 않음, 인증서는 X.509 `Certificate`만 8개까지, CRL은 거부, `SignerInfo`는 정확히 하나이고 버전이 식별자 형식과 맞아야 한다(발급자·일련번호 1, 주체 키 식별자 3).
   - 서명 속성은 필수다. 내용 형식(`id-ct-TSTInfo`), 메시지 다이제스트(`TSTInfo`의 해시), ESS 서명 인증서가 각각 한 번, 값 하나씩이다. 서명은 `[0]` 태그를 `SET`으로 바꾼 DER 바이트 위에서 검증한다(RFC 5652 §5.4). 그 밖의 서명 속성(서명 시각 등)과 서명되지 않은 속성은 쓰지 않지만 부분집합 안이어야 한다.
   - ESS는 v2(RFC 5035, RFC 5816)를 받는다. 해시 알고리즘은 핀의 다이제스트 집합 안이어야 한다. 첫 식별자가 서명자 인증서의 해시여야 하고 `issuerSerial`이 있으면 그 인증서의 발급자와 일련번호여야 한다.
   - ESS v1(SHA-1)은 핀의 플래그가 허용할 때만 받는다. freetsa.org가 v1을 쓰고, 다른 공개 기관도 OpenSSL 기본값 때문에 v1을 쓰는 경우가 많다. 서명자 인증서는 SHA-256 핀으로 정해지고 서명은 그 인증서의 키로 검증하므로, ESS는 일치 확인일 뿐이다. SHA-1 충돌로 다른 인증서를 끼워 넣어도 핀을 바꾸지 못한다. SHA-1은 각인과 서명에는 쓰지 않는다.
4. **서명자 인증서 프로필(경로 검증 없음).** X.509 v3, 확장 키 용도는 정확히 한 번, 필수(critical), `id-kp-timeStamping` 하나만(RFC 3161 §2.3). 키 용도가 있으면 디지털 서명과 부인 방지만, 기본 제약이 있으면 CA 아님. 인증서 정책(`certificatePolicies`)은 필수로 표시돼 있어도 받는다. 구조(정책 정보 하나 이상, 각각 OID와 선택 한정자)와 DER 규칙만 검사하고 내용은 해석하지 않는다. RFC 5280 §4.2.1.4는 필수 정책 확장을 해석하지 못하는 경로 검증이 인증서를 거부하라고 하지만, 이 크레이트는 경로 검증을 하지 않는다. 인증서는 genesis가 해시로 고정한 것이고, 어떤 정책의 인증서를 고정할지는 genesis를 만드는 사람이 그 인증서를 보고 정한다. 신뢰는 정책 처리가 아니라 핀에서 온다. 한국의 공인인증·행정전자서명(GPKI) 인증서 프로필은 이 확장을 필수로 표시하므로, 거부하면 ADR-0034가 요구하는 정부 운영 기관의 토큰이 모두 거부될 수 있다. 그 밖의 필수 확장은 거부하고, 처리하는 확장(인증서 정책 포함)의 반복도 거부한다. 서명자 식별자는 그 인증서를 가리켜야 하고, `TSTInfo`의 `tsa`가 있으면 인증서 주체와 같은 `directoryName`이어야 하며(RFC 3161 §2.4.2), `genTime`은 인증서 유효기간 안이어야 한다. 발급자의 서명은 검증하지 않는다.
5. **`TSTInfo`.** 버전 1, 핀의 정책, 기대 각인과 같은 알고리즘과 값, 일련번호 160비트 이하, nonce 256비트 이하, 정확도의 밀리·마이크로초 1–999, 정확도의 초 3600 이하(`MAX_ACCURACY_SECONDS`, 넘으면 `AccuracyTooLarge`), 비필수 확장은 무시하고 필수 확장은 모두 거부한다(이해하는 확장이 없다). `genTime`은 `YYYYMMDDhhmmss[.f]Z`이고 소수는 1–9자리, 끝이 0이 아니다. 윤초(60)와 1970년 이전은 Unix 시각으로 나타낼 수 없어 거부한다. 결과는 Unix 초와 나노초다. 정확도의 상한은 RFC 3161에 없다. 실제 기관은 1초 이하를 적고, 정확도가 한 시간인 토큰은 ADR-0034의 앵커 창(15분 구간 넷, 한 시간)에 체크포인트를 놓지 못하며, 상한이 있어 아래 9의 구간 계산이 넘치지 않는다.
6. **서명 알고리즘.** 핀이 허용한 것만, 그리고 다음 여섯 가지만 지원한다.
   - RSASSA-PKCS1-v1_5와 SHA-256·384·512. 모듈러스 2048–4096비트, 공개 지수는 홀수이고 `2^16 < e < 2^256`(FIPS 186-5 §5.4). 서명 길이는 정확히 모듈러스 길이, 표현값은 `n`보다 작아야 한다. 복호한 블록은 파싱하지 않는다. `00 01 FF…FF 00 DigestInfo`(`NULL` 매개변수) 전체를 만들어 비교한다(Bleichenbacher 2006 류의 위조 방지). `rsaEncryption`과 `sha*WithRSAEncryption` 표기를 모두 받되 후자는 서명자 다이제스트와 같아야 한다.
   - ECDSA P-256/SHA-256, P-384/SHA-384, P-384/SHA-512(freetsa.org, 다이제스트를 384비트로 자른다). 곡선에 맞지 않는 다이제스트는 받지 않는다: P-256과 SHA-384·SHA-512(다이제스트가 곡선보다 길다), P-384와 SHA-256(짧다). 공개키는 비압축 점만, 서명은 엄격한 DER `Ecdsa-Sig-Value`이고 `r`, `s`는 `[1, n−1]`.
   - RSA-PSS는 지원하지 않는다. 매개변수 구조와 MGF1, 복호 블록 해석이 필요해 이번 범위를 넘는다. 지정 기관이 PSS를 쓰면 새 ADR로 더한다.
7. **의존성.** `sha2` =0.11.1, `sha1` =0.11.0, `crypto-bigint` =0.7.10, `p256`·`p384` =0.14.0(`ecdsa` =0.17.0), 모두 `default-features = false`. RSA는 `rsa` 크레이트를 쓰지 않는다. 그 크레이트는 RUSTSEC-2023-0071(Marvin, 개인키 연산의 시간 누출)이 있고 `deny.toml`이 `ignore = []`이다. 검증에는 공개키 연산 `s^e mod n` 하나면 되므로, `elliptic-curve`가 이미 쓰는 `crypto-bigint`의 고정폭 몽고메리 연산으로 직접 계산한다. 비밀이 없으니 상수 시간은 필요 없고 정확성이 중요하다. 그래서 인코딩을 만들어 비교하고 경계(`s ≥ n`, 짧은 `s`)를 시험한다.
8. **검사 순서.** 구조(DER·CMS·`TSTInfo`) → 인증서 선택과 프로필 → 서명자 식별자 → 핀의 허용 알고리즘 → 각인 → ESS → 메시지 다이제스트 → 서명 → 정책·`tsa`·유효기간. 순서가 고정이므로 같은 토큰은 같은 오류를 낸다. 연결 단계는 어떤 오류든 `TimestampInvalid`로 다룬다(ADR-0034 §7).
   - 개정(ADR-0039 리뷰, 2026-11-05): 처음에는 서명으로 진정성을 세운 뒤 각인을 비교했다. 각인은 서명되지 않은 입력과의 비교일 뿐 무엇도 드러내지 않으므로, 이제 다이제스트와 서명을 계산하기 전에 비교한다. 다른 대상의 토큰(장부에 실린 거짓 기록)이 서명 검증 비용 없이 거부된다. 두 규칙을 함께 어긴 토큰의 오류만 바뀐다(`TSTInfo`의 각인 바이트를 바꾼 토큰은 `MessageDigestMismatch` 대신 `ImprintMismatch`).
9. **연결 단계에 넘기는 것.** 이 크레이트가 판정하지 않고 `TimestampRecord`와 체크포인트 단계(VC-114..118)가 지켜야 하는 것이다.
   - **시각은 구간이다.** `VerifiedTimestamp::earliest()`와 `latest()`는 `genTime ∓ 정확도`를 넘침 없이 계산한다(`Option`; `earliest`는 1970년 이전이면 `None`, `latest`는 검증된 토큰에서 언제나 값이 있다). VC-115(앵커 창)와 VC-116(역산 금지)은 `genTime` 하나가 아니라 이 구간으로 판정한다. "그 시각까지 존재했다"는 결론은 `latest()`로 내린다: 앵커는 `latest()`가 창 안일 때 충족이고, 역산은 `latest()`도 체크포인트 구간보다 앞설 때만 위반이다. 토큰에 정확도가 없으면 구간은 `genTime` 한 점이다. RFC 3161은 정확도를 정책으로 정할 수도 있게 하므로, 그런 기관은 genesis 항목에 정확도를 따로 둬야 한다.
   - **토큰 바이트는 유일하지 않다.** 서명되지 않은 부분(인증서 집합, 서명되지 않은 속성, 서명자 식별자의 형식, `rsaEncryption`과 `sha*WithRSAEncryption` 표기)은 서명을 깨지 않고 바꾸거나 더하거나 뺄 수 있고, ECDSA 서명은 `(r, n − s)`도 검증된다(`tests/strict.rs`). 검증 결과는 같다. 그래서 `TimestampRecord`와 VC-115는 유효 토큰을 기관(핀)과 운영 주체 단위로 센다. 토큰 바이트나 그 해시로 세면 같은 서명 하나가 둘로 셀 수 있다.
   - **기대 nonce는 받지 않는다.** nonce는 요청한 장부 운영자가 응답을 받을 때 요청과 맞춰 본다(`make.sh`와 `freetsa/fetch.sh`는 `openssl ts -verify -queryfile`로 한다). 검증기는 nonce를 보고만 한다.
   - **핀 하나에 인증서 하나다.** 기관이 선거 기간 중 서명 인증서를 바꾸면 genesis에 그 기관의 핀이 여럿 있어야 한다. 같은 운영 주체의 핀들은 VC-115에서 한 기관으로 센다.

## 결과

- `ityv-verify`는 `VerifiedTimestamp`만 받는다: 시각과 그 구간(`earliest`, `latest`), 정책, 일련번호, nonce, 정확도, 각인, 인증서 해시와 출처, 알고리즘. 인증서 출처(`CertificateSource`)만 서명되지 않은 인증서 집합에서 오는 진단값이고, 나머지는 서명됐거나 핀·호출자가 준 값이다.
- OpenSSL이 만든 6개 알고리즘의 토큰과 freetsa.org의 실제 토큰이 모두 엄격한 규칙을 통과한다(freetsa.org는 ESS v1 허용 핀으로). 토큰이 낼 수 있는 `TsaError` 변형 가운데 `Der(_)`를 뺀 59개마다 그 규칙만 어긴 토큰이 있고, 정확히 그 오류로 거부된다(`tests/rules.rs`). `Der(_)`는 DER 규칙마다 `der` 단위 테스트가, 토큰 안에서는 `tests/strict.rs`의 조작 토큰이 맡는다. 변형 목록은 전수 `match`로 쓰므로 새 변형은 토큰 없이 컴파일되지 않는다. 나머지 변형 9개는 핀 바이트·호출자의 각인·핀 인코더의 것으로 단위 테스트가 맡는다. 조작 토큰은 88개다(`forge.py`: `rsa3072-sha384.tst`의 변형 85개, `p256-sha256.tst` 서명의 변형 3개).
- 토큰 TCB는 이 크레이트와 전이 의존성 33개다(호스트 기준, `thumbv7em`에서는 `cpufeatures`가 빠져 32개). 직접 의존성 5개(`sha2`, `sha1`, `crypto-bigint`, `p256`, `p384`)와 그 의존성이고, 그 가운데 15개가 이 크레이트와 함께 잠금 파일에 새로 들어왔다. `der`와 `const-oid`는 `ecdsa`·`sec1`을 거쳐 들어오지만 이 크레이트의 파싱은 그것을 쓰지 않는다. `ityv-verify`와 `ityv-encoding`은 바뀌지 않았다.

## 비용과 위험

- 엄격성은 실제 기관과 어긋날 수 있다. 검토에서 나온 세 가지(인증서 정책의 필수 표시, 정렬되지 않은 인증서 집합과 서명되지 않은 속성, ESS v2의 `{id-sha256, NULL}`)는 받도록 고쳤다. 남은 미확인 항목은 ADR-0034가 정한 대로 지정 기관, 특히 정부 운영(GPKI) 기관의 실제 토큰으로 채택 전에 확인한다.
  - `SignedData` 버전이 3이 아닌 토큰. RFC 5652 §5.1은 `id-ct-TSTInfo`에 3을 요구하지만 1을 쓰는 구현이 있을 수 있다(지금은 `SignedDataVersion`으로 거부).
  - `TSTInfo`의 `tsa`가 `directoryName`이 아닌 `GeneralName`(DNS 이름, URI 등). 지금은 주체와 비교할 수 없어 `TsaNameMismatch`로 거부한다.
  - RSA-PSS 서명(6의 마지막 항목). 지금은 `UnknownSignatureAlgorithm`.
  - 윤초, 인증서 정책 밖의 필수 확장, 한 시간을 넘는 정확도.
  - 이 작업 환경에서는 한국 정부·공인 기관의 공개 시점확인 서비스에 닿지 못했다(2026-11-04: 이름을 확인한 주소는 응답이 없거나 시점확인 응답이 아닌 웹 페이지를 돌려줬다). 정부 기관 토큰 확인은 그 기관의 접근 경로로 한다.
  - 어긋나면 조용히 풀지 않고 이 ADR을 고친다.
- 새 의존성 15개는 cargo-vet 면제로 들어왔다. 감사 기록으로 바꾸는 것은 다른 의존성과 같이 남은 일이다.
- RSA 검증은 자체 구현이다. 범위가 작고(모듈러 거듭제곱 하나와 비교) 실제 토큰, 경계값, 변이 시험으로 확인하지만 형식 검증은 아니다.

## 대안

- **`rsa` 크레이트와 좁은 `ignore`.** 공개키 검증 경로는 RUSTSEC-2023-0071과 무관하지만, 감사 예외가 생기고 개인키 코드까지 TCB에 들어온다. 기각.
- **`der`·`cms`·`x509-cert` 크레이트.** 범용 파서는 BER 관용과 넓은 구조를 갖고, ADR-0034가 요구한 부분집합보다 크다. 크기와 깊이를 고정한 자체 읽기가 Kani로 검사하기 쉽다. 기각.
- **ESS v1 전면 거부.** 실제 공개 기관이 v1을 쓴다. 핀별 허용으로 둔다.
- **핀에 인증서 대신 공개키(SPKI)만.** EKU·유효기간·주체 확인에 인증서가 필요하다. 기각.

## 연결되는 검증

- `crates/ityv-tsa/tests/rules.rs`(규칙마다 토큰 하나), `tests/tokens.rs`, `tests/strict.rs`, `tests/proptests.rs`, 모듈 단위 테스트, `kani/proofs.rs`, `fuzz/`; 시험 벡터 `tests/vectors/make.sh`, `tests/vectors/freetsa/fetch.sh`.
- 연결 단계(ADR-0039): `TimestampRecord` 스키마와 genesis의 기관 목록(핀 바이트 1–4개, 운영 주체, 정부 운영 여부, 정책 정확도), 체크포인트 단계의 역산 금지·앵커 창 판정(9의 구간과 기관 단위 계수), `TimestampMismatch`·`TimestampInvalid` 보류. 이 크레이트의 공개 API(`PinnedTsa::from_bytes`, `verify_token`, `Imprint::of`, `VerifiedTimestamp`)만 쓰며 크레이트는 바뀌지 않았다.
