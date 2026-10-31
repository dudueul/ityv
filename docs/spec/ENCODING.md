# ityv 정규 인코딩 명세 v1 / Canonical Encoding Specification v1

> English summary: A non-recursive, fixed-width, deterministic binary encoding for every object that is hashed or signed in ityv. It has exactly one byte representation per value, is decodable without heap allocation, and rejects every non-canonical input. This document is the single source of truth; the `ityv-encoding` crate implements it and publishes test vectors.

상태: 초안 v1 (ADR-0006, ADR-0007). 이 문서의 변경은 `schema_version` 증가를 수반한다.

## 1. 목표

1. **유일성.** 같은 값은 항상 같은 바이트열로 인코딩된다. 디코딩 후 재인코딩하면 원래 바이트열과 동일하다.
2. **거부.** 정규 형식이 아닌 입력은 어느 위치에서든 거부된다. 자동 정규화, 관대한 파싱, 기본값 채우기를 하지 않는다.
3. **재귀 없음.** 파서는 고정된 깊이(최대 2)로만 중첩을 처리하며 재귀 호출을 하지 않는다. 스택 사용량이 정적으로 유계다.
4. **힙 없음.** 인코더는 호출자가 준 버퍼에 쓰고, 디코더는 입력 슬라이스를 빌려 쓴다. `no_std`, `alloc` 없음.
5. **증명 가능성.** 왕복(decode∘encode = id, encode∘decode = id on canonical inputs)과 거부 성질에 Kani 하네스와 속성 테스트를 붙인다.

## 2. 기본형

| 형 | 폭 | 규칙 |
|---|---|---|
| `u8` | 1 | 그대로 |
| `u16`, `u32`, `u64` | 2, 4, 8 | big-endian 고정폭. 가변 길이 정수(varint)는 쓰지 않는다 |
| `bool` | 1 | `0x00` 또는 `0x01`. 그 외 값은 거부 |
| `Hash512` | 64 | SHA3-512 출력 |
| `Scalar` | 32 | Ristretto255 스칼라, little-endian canonical(곡선 라이브러리의 canonical 검사 통과 필수). 인코딩 크레이트는 길이만 검사하고 canonical 여부는 암호 크레이트가 검사한다 |
| `Point` | 32 | Ristretto255 압축 점. 위와 같은 책임 분리 |
| `Token192` | 24 | 192비트 무작위 토큰(투함 ID, 봉투 라벨) |
| `[u8; N]` | N | 고정폭 바이트열. 길이 접두사가 없고 스키마가 `N`을 정한다(서명, 키, 암호문처럼 길이가 알고리즘으로 고정된 값) |
| `Bytes<N>` | 4 + 길이 | `u32` 길이 접두사 뒤 바이트. 스키마가 정한 최대 길이 `N`을 넘으면 거부 |
| `Ident<N>` | 4 + 길이 | `Bytes<N>`과 같되 알파벳이 `[A-Za-z0-9._:-]`로 제한되고 길이 1 이상. 그 외 바이트는 거부 |
| `Option<T>` | 1 + 0 또는 T | 존재 태그 `0x00`(없음) 또는 `0x01`(있음). 그 외 거부 |
| `Array<T, N>` | 4 + 원소들 | `u32` 원소 수 뒤 원소. 스키마가 정한 최대 수 `N`을 넘으면 거부. 원소 형은 기본형 또는 깊이 1의 구조체만 허용 |

음수 정수, 부동소수점, 문자열(UTF-8), 맵, 재귀 구조는 존재하지 않는다. 사람이 읽는 문자열은 TCB 객체에 들어가지 않으며, 필요하면 해시로 참조한다.

## 3. 객체 헤더

모든 최상위 객체는 16바이트 헤더로 시작한다.

```
offset  size  field
0       4     magic      = 0x49 0x54 0x59 0x56 ("ITYV")
4       4     schema_id  u32 (§6 등록부)
8       2     schema_version u16 (1부터)
10      2     flags      u16, 반드시 0
12      4     body_len   u32, 헤더 뒤 본문 길이
```

디코더는 magic, 알 수 없는 `schema_id`, 지원하지 않는 `schema_version`, 0이 아닌 `flags`, `body_len`과 실제 남은 길이의 불일치, 본문 뒤의 잉여 바이트를 모두 거부한다.

## 4. 해시와 서명 입력

객체 바이트열 `obj`(헤더 포함)에 대해:

- 해시: `SHA3-512( "ityv:hash:v1" ‖ 0x00 ‖ u64_be(len(obj)) ‖ obj )`
- 서명 메시지: `"ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len(obj)) ‖ obj`. `purpose`는 `Ident<32>` 알파벳의 ASCII이며 용도마다 다르다(예: `checkpoint`, `cast-record`, `genesis`, `slip`, `handoff`). 서명 알고리즘에 실제로 넘기는 입력은 이 메시지의 **SHA3-512 다이제스트 64바이트**이며(해시 후 서명, ADR-0015), ML-DSA-87에는 `purpose`를 FIPS 204 컨텍스트 문자열로도 넘긴다.
- Fiat-Shamir 챌린지: `SHA3-512( "ityv:fs:v1:" ‖ proof_system_id ‖ 0x00 ‖ u64_be(len(transcript)) ‖ transcript )`, 64바이트 출력을 스칼라로 균등 축소.
- 해시-투-그룹: `from_uniform_bytes( SHA3-512( label ‖ 0x00 ) )`. `label`은 `ityv:base:val:v1`, `ityv:base:id:v1`, `ityv:base:rand:v1`(PROTOCOL.md §7.4). 라벨 뒤의 `0x00`은 다른 해시 규칙과 같은 구분자다.
- 보존 서명(SLH-DSA-SHAKE-256s)도 같은 64바이트 다이제스트를 서명하며 `purpose`를 FIPS 205 컨텍스트 문자열로 넘긴다. Ed25519는 다이제스트만 서명한다(컨텍스트 없음).
- 서명·키·암호문의 인코딩은 길이 접두사 없는 고정폭 `[u8; N]`이다(§2). 서명 묶음 `HybridSig`는 `mldsa87: [u8; 4627] ‖ ed25519: [u8; 64]`(4,691바이트), 보존 서명은 `[u8; 29792]`다.

서로 다른 용도의 서명을 재사용할 수 없도록 `purpose`가 다르면 메시지가 다르다. 같은 객체를 다른 선거에 재생할 수 없도록 모든 객체 본문은 `election_id: Ident<64>`를 첫 필드로 가진다.

## 5. 정규성 규칙 요약

디코더가 거부해야 하는 입력:

1. 헤더 불일치(§3).
2. `bool`과 존재 태그가 0/1 이외.
3. `Bytes`, `Ident`, `Array` 길이가 스키마 최대치 초과 또는 `Ident` 길이 0.
4. `Ident` 알파벳 밖의 바이트.
5. 본문이 선언된 길이보다 짧거나 긴 경우, 잉여 바이트.
6. 스키마가 "정렬됨, 중복 없음"으로 선언한 배열(예: 예상 투표함 목록)에서 순서 위반이나 중복. 정렬은 바이트열의 사전순.
7. 스키마가 범위를 선언한 정수(예: 수량 ≤ 100,000,000)의 범위 초과.

디코더는 첫 번째 위반 위치의 오프셋을 오류에 담는다. 오류는 열거형이며 문자열을 포함하지 않는다.

## 6. 스키마 등록부

| `schema_id` | 이름 | 깊이 | 비고 |
|---|---|---|---|
| 0x0001 | `LedgerFrame` | 1 | 장부 프레임 헤더: seq, prev_hash, event_hash |
| 0x0002 | `Genesis` | 2 | 명부·키·경로·법적 승인 |
| 0x0003 | `LegalAuthorization` | 1 | scope 집합, 조문 참조 해시, 시행 구간 |
| 0x0004 | `CheckpointBody` | 1 | tree_size, root, prev, box_close_root, dispute_root |
| 0x0005 | `CastRecord` | 1 | 커밋먼트 벡터, 증명, 서명 |
| 0x0006 | `ChallengeOpening` | 1 | 투입 전 검증 공개값 |
| 0x0007 | `BoxClose` | 1 | 수량, 봉인 해시, 장부 head |
| 0x0008 | `CustodyHandoff` | 1 | 인계·인수, 봉인, 이전 인계 해시 |
| 0x0009 | `CheckinCounter` | 1 | 확인 카운터 이벤트 |
| 0x000A | `Slip` | 1 | 추적코드 슬립 |
| 0x000B | `SharePackage` | 1 | 신뢰기관별 암호화 share 묶음(공개하지 않음) |
| 0x000C | `ReceiptMark` | 1 | 관외 수령 라벨 목록 |
| 0x000D | `AuditSeed` | 1 | 표본 추출 시드 의식 |
| 0x000E | `DisputeEvent` | 1 | 분쟁 접수·처리 |
| 0x000F | `LegalDecisionRef` | 1 | 법정 결정 참조 |
| 0x0010 | `SignedCheckpoint` | 1 | 체크포인트 본문 바이트와 증인 서명 묶음(§8.4, ADR-0016) |
| 0x0011 | `WitnessMemory` | 1 | 증인 도구가 영속화하는 마지막 서명 기억(§8.5, ADR-0016 §4). 장부 이벤트가 아니다 |

필드 수준 정의는 `docs/spec/PROTOCOL.md`의 각 절과 `ityv-encoding` 크레이트의 스키마 모듈이 함께 가진다. 둘이 다르면 이 문서와 PROTOCOL.md가 우선하고 크레이트는 결함이다.

## 7. 시험 벡터

`ityv-encoding` 크레이트는 각 스키마의 정상 벡터와 거부 벡터를 `vectors/` 디렉터리에 16진수로 공개한다. 독립 2차 구현(V5)은 이 벡터로 차분 테스트를 한다.

## 8. 예시 스키마 필드 정의

`ityv-encoding` 크레이트가 구현하는 세 스키마의 필드 정의다. 필드는 아래 순서대로 본문에 나열되며, 본문 앞에는 §3의 16바이트 헤더가 온다. 시험 벡터는 `crates/ityv-encoding/vectors/`에 있다.

### 8.1 `LedgerFrame` (`schema_id` 0x0001, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `seq` | `u64` | `>= 1`. 0이면 `ValueOutOfRange`(필드 오프셋) |
| 3 | `prev_hash` | `Hash512` | 첫 프레임은 전부 0 |
| 4 | `event_schema_id` | `u32` | 수록된 이벤트의 스키마 ID |
| 5 | `event_hash` | `Hash512` | 이벤트 객체의 §4 해시 |

### 8.2 `LegalAuthorization` 본문 (`schema_id` 0x0003, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `scopes` | `Array<u8, 16>` | 정렬·중복 없음. 코드: 1 `PUBLIC_BOARD`, 2 `TRUSTEE_BODY`, 3 `BALLOT_MARK`, 4 `CRYPTO_TALLY_AID`, 5 `RLA`, 6 `OBSERVER_ACCESS`, 7 `DEPLOY_AUTH`, 8 `STAGE_GATE`, 9 `VOTER_CODE`. 그 외 코드는 `InvalidScopeCode`, 순서 위반은 `NotSorted`, 중복은 `Duplicate` |
| 3 | `statute_refs_hash` | `Hash512` | 조문 참조 목록의 정규 해시 |
| 4 | `effective_from_day` | `u64` | 유닉스 기원 기준 일수 |
| 5 | `effective_until_day` | `u64` | `>= effective_from_day`. 위반 시 `ValueOutOfRange`(이 필드 오프셋) |

선관위와 독립검증위원회의 서명은 이 본문에 포함되지 않는다. 서명은 이 본문을 감싸는 genesis 객체가 운반하고 암호 크레이트가 검증한다.

### 8.3 `CheckpointBody` (`schema_id` 0x0004, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ledger_id` | `Ident<64>` | |
| 3 | `keyset_id` | `Ident<64>` | 서명이 기대되는 증인 키 집합 |
| 4 | `checkpoint_seq` | `u64` | `>= 1` |
| 5 | `tree_size` | `u64` | 포함된 장부 잎 수 |
| 6 | `root_hash` | `Hash512` | Merkle root |
| 7 | `previous_checkpoint_hash` | `Hash512` | `checkpoint_seq == 1`일 때만 전부 0, 그 외에는 0이 아님. 위반 시 `InvalidPreviousHash`(이 필드 오프셋) |
| 8 | `box_close_root` | `Hash512` | 서명된 투표함 마감 봉투 집합의 root |
| 9 | `dispute_root` | `Hash512` | 미결 분쟁 이벤트 집합의 root |
| 10 | `genesis_hash` | `Hash512` | 결속된 genesis의 §4 해시 |
| 11 | `time_bucket` | `u64` | 체크포인트 제안의 시간 구간 |

### 8.4 `SignedCheckpoint` (`schema_id` 0x0010, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<4096>` | 인코딩된 `CheckpointBody` 객체 전체(§3 헤더 포함). 디코더는 이 바이트를 §8.3 규칙으로 다시 디코딩해 거부 규칙을 적용한다 |
| 2 | `signatures` | `Array<{witness_id: Ident<64>, signature: [u8; 4691]}, 64>` | `witness_id` 바이트 오름차순, 중복 없음. 순서 위반은 `NotSorted`, 중복은 `Duplicate`. 각 `signature`는 `body` 바이트에 대한 purpose `checkpoint`의 하이브리드 서명(PROTOCOL.md §3.1) |

정족수·다양성·명부 검사는 인코딩 규칙이 아니라 `ityv-ledger`의 정책 검사다(ADR-0016 §6).

### 8.5 `WitnessMemory` (`schema_id` 0x0011, `schema_version` 1)

증인 도구의 내부 상태다. 장부에 수록되지 않으며 공개하지 않는다. 헤더의 magic·schema·version·길이 검사로 손상된 파일을 거부한다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `last_seq` | `u64` | 마지막으로 서명한 `checkpoint_seq`. 0이면 아직 서명한 적 없음 |
| 2 | `tree_size` | `u64` | `<= 2^40`. 위반 시 `ValueOutOfRange` |
| 3 | `root_hash` | `Hash512` | 마지막 서명 본문의 `root_hash` |
| 4 | `body_hash` | `Hash512` | 마지막 서명 본문 바이트의 §4 해시 |
| 5 | `ids_hash` | `Hash512` | `election_id ‖ ledger_id ‖ keyset_id`(세 `Ident<64>` 필드의 정규 인코딩)의 §4 해시 |

`last_seq == 0`이면 2–5는 전부 0이어야 하며 그 외는 `ValueOutOfRange`(해당 필드 오프셋).

### 8.6 오류 보고 규칙

디코더는 첫 번째 위반에서 멈추고 `(종류, 오프셋)`을 돌려준다. 오프셋은 객체 시작(헤더의 magic) 기준 절대 오프셋이다. 헤더 위반의 오프셋은 `BadMagic` 0, `SchemaMismatch` 4, `UnsupportedVersion` 8, `NonZeroFlags` 10, `BodyLengthMismatch` 12이고, 본문 뒤 잉여 바이트는 `TrailingBytes`(잉여가 시작되는 오프셋)다.
