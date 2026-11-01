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
| 0x0002 | `Genesis` | 4 | 명부·키·경로·법적 승인. 버전 3에서 `connectivity_manifest_hash: Hash512` 추가(ADR-0022), 버전 4에서 `release_manifest_hash: Hash512`와 장치·모듈 증명 공개키, 참관인 토큰별 확인 키(Ed25519) 추가(ADR-0023) |
| 0x0003 | `LegalAuthorization` | 1 | scope 집합, 조문 참조 해시, 시행 구간 |
| 0x0004 | `CheckpointBody` | 1 | tree_size, root, prev, box_close_root, dispute_root |
| 0x0005 | `CastRecordBody` | 1 | 투함 기록 본문: 커밋먼트 벡터, 증명, 모듈 카운터, share 패키지 해시(§8.6) |
| 0x0006 | `ChallengeOpeningBody` | 1 | 투입 전 검증 공개값 본문(§8.8) |
| 0x0007 | `BoxCloseBody` | 1 | 마감 본문: 수량, 봉인 해시, 저널 head(§8.16) |
| 0x0008 | `CustodyHandoff` | 1 | 인계·인수, 봉인, 이전 인계 해시 |
| 0x0009 | `CheckinCounter` | 1 | 확인 카운터 이벤트(`restricted`, PROTOCOL §6.3) |
| 0x000A | `Slip` | 1 | 슬립 본문 바이트 + 장치 하이브리드 서명(§8.18) |
| 0x000B | `SharePackage` | 1 | 신뢰기관별 암호화 share 묶음(§8.10, 공개하지 않음) |
| 0x000C | `ReceiptMark` | 1 | 관외 수령 라벨 목록 |
| 0x000D | `AuditSeed` | 1 | 표본 추출 시드 추첨 절차 |
| 0x000E | `DisputeEvent` | 1 | 분쟁 접수·처리 |
| 0x000F | `LegalDecisionRef` | 1 | 법정 결정 참조 |
| 0x0010 | `SignedCheckpoint` | 1 | 체크포인트 본문 바이트와 증인 서명 묶음(§8.4, ADR-0016) |
| 0x0011 | `WitnessMemory` | 1 | 증인 도구가 영속화하는 마지막 서명 기억(§8.5, ADR-0016 §4). 장부 이벤트가 아니다 |
| 0x0012 | `BatchAttestBody` | 1 | 배치 증명 본문(§8.12) |
| 0x0013 | `ScanCountAttestBody` | 1 | 스캔 카운터 참관 앵커 본문(§8.14) |
| 0x0014 | `JournalEntry` | 1 | 커밋먼트 유닛 봉인 저널 항목(§8.19, 장치 내부, `ityv-cunit` 구현) |
| 0x0015 | `MemberShare` | 1 | 신뢰기관 구성원 한 명의 share 평문(§8.11, 암호문 안에만 존재) |
| 0x0016 | `CastRecord` | 1 | 투함 기록 본문 바이트 + 기록 서명(§8.7) |
| 0x0017 | `BatchAttest` | 1 | 배치 증명 본문 바이트 + 모듈·장치 하이브리드 서명(§8.13) |
| 0x0018 | `ChallengeOpening` | 1 | 검증 공개 본문 바이트 + 장치 서명(§8.9) |
| 0x0019 | `SlipBody` | 1 | 슬립 본문(§8.18) |
| 0x001A | `BoxClose` | 1 | 마감 본문 바이트 + 장치·사무원·참관인 서명(§8.17) |
| 0x001B | `ScanCountAttest` | 1 | 스캔 카운터 본문 바이트 + 참관인 서명(§8.15) |
| 0x001C | `ConnectivityManifest` | 1 | 연결 목록: 포트별 방향·매체·상대·시간대·슬롯당 프레임 수·프레임 키(§8.21, ADR-0022) |
| 0x001D | `UplinkFrame` | 1 | 고정 크기 송신 프레임. 장부 이벤트가 아닌 전송 단위(§8.22) |
| 0x001E | `UplinkSessionBody` | 1 | 게이트웨이 세션 본문: 링크별 프레임 수·사슬 head(§8.23) |
| 0x001F | `UplinkSession` | 1 | 세션 본문 바이트 + 게이트웨이 하이브리드 서명 + 참관인 서명(§8.24) |
| 0x0020 | `ParticipationSet` | 1 | 투표 종료 뒤 투표소별 정렬 가명 목록. 순번·시간 없음(§8.25, PROTOCOL §6.5) |
| 0x0021 | `ReleaseManifestBody` | 1 | 릴리스 목록 본문: 이미지별 버전·빌드·소스·툴체인·이미지 해시·문구 표 해시, 구성별 해시(§8.26, ADR-0023) |
| 0x0022 | `ReleaseManifest` | 1 | 본문 바이트 + 빌더 서명 3 이상 + 인증기관·위원회 서명(§8.27) |
| 0x0023 | `DeviceAttestationBody` | 1 | 현장 증명 본문: 도전값, 부팅 횟수, 측정 해시, 모듈 진술(§8.28) |
| 0x0024 | `DeviceAttestation` | 1 | 본문 바이트 + 증명 키 하이브리드 서명(§8.29) |
| 0x0025 | `AttestationSummary` | 1 | 현장 QR용 요약 + Ed25519 서명. 장부 이벤트가 아닌 인쇄 객체(§8.30) |
| 0x0026 | `ModuleProvisioned` | 1 | 모듈 발급 기록: 본체·패드 카드 ID, KEM 공개키, 챔버 엔트로피 약속, 보안 칩 여부, 정당 PRF 키 확인값(§8.31, ADR-0024) |
| 0x0027 | `PartyKeyCeremony` | 1 | 정당 열쇠 생성 절차 기록. 키 자료 없음(§8.32, ADR-0024) |
| 0x0101 | `Interpretation` | 1 | 해석 유닛 → 커밋먼트 유닛 링크 객체(§8.19, `ityv-cunit` 구현) |
| 0x0103 | `ModuleIssue` | 1 | 챔버 모듈 → 커밋먼트 유닛 링크 객체(§8.19, `ityv-cunit` 구현) |
| 0x0104 | `VisitEnd` | 1 | 해석 유닛 → 커밋먼트 유닛 방문 끝 알림(§8.19, `ityv-cunit` 구현, ADR-0021) |
| 0x0105 | `AttestChallenge` | 1 | 확인 카드의 도전값을 해석 유닛이 커밋먼트 유닛으로 넘기는 링크 객체(§8.19, ADR-0023) |

필드 수준 정의는 `docs/spec/PROTOCOL.md`의 각 절과 §8이 가지며, 구현은 조직 경계를 넘는 객체는 `ityv-encoding`, 크레이트 내부 객체는 그 크레이트(비고에 표기; 0x0010·0x0011은 `ityv-ledger`)다. 둘이 다르면 이 문서와 PROTOCOL.md가 우선하고 크레이트는 결함이다. 0x0100–0x01FF는 장치 링크 객체 범위다. 0x0102는 커밋먼트 유닛 → 모듈 발급 요청에 남겨 둔다.

## 7. 시험 벡터

`ityv-encoding` 크레이트는 각 스키마의 정상 벡터와 거부 벡터를 `vectors/` 디렉터리에 16진수로 공개한다. 독립 2차 구현(V5)은 이 벡터로 차분 테스트를 한다.

## 8. 예시 스키마 필드 정의

등록된 스키마의 필드 정의다. 필드는 아래 순서대로 본문에 나열되며, 본문 앞에는 §3의 16바이트 헤더가 온다. 시험 벡터는 각 구현 크레이트의 `vectors/`에 있다. 자기 서명을 담는 이벤트는 "본문 객체 + 서명 묶음"의 두 객체로 나뉘고 서명 메시지는 본문 객체 바이트 전체다(ADR-0017 §2).

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

`last_seq == 0`이면 2–5는 전부 0이어야 하며 그 외는 `InvariantViolation`(`last_seq` 필드 오프셋 16). 객체 전체 길이는 헤더 포함 224바이트로 고정이다.

### 8.6 `CastRecordBody` (`schema_id` 0x0005, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `ballot_style_id` | `Ident<64>` | |
| 4 | `proof_system_id` | `u16` | 1(`or-rep:v1`). 그 외는 `ValueOutOfRange` |
| 5 | `commitments` | `Array<Point, 8>` | 개수 = k ≥ 1. 0이면 `ValueOutOfRange`(개수 접두사 오프셋) |
| 6 | `proof` | `Bytes<20483>` | PROTOCOL.md §7.5 증명 인코딩. 머리부 규칙을 디코더가 검사한다: `option_count ∈ 2..=64`, `chunk_count = ⌈option_count/9⌉`, 길이 = `3 + option_count·(chunk_count+2)·32`, `chunk_count` = 5의 개수. 위반은 `InvariantViolation`(이 필드 오프셋). 스칼라의 canonical 여부는 암호 크레이트가 검사한다 |
| 7 | `module_counters` | `Array<{module_id: Ident<64>, counter: u64}, 7>` | `module_id` 오름차순, 중복 없음, 1개 이상(0이면 `ValueOutOfRange`) |
| 8 | `share_package_hash` | `Hash512` | §8.10 객체의 §4 해시 |
| 9 | `transport_flags` | `u8` | 비트0 KEM 대체 사용, 비트1 중립 모듈 위임. 다른 비트가 서 있으면 `ValueOutOfRange` |

### 8.7 `CastRecord` (`schema_id` 0x0016, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<22528>` | 인코딩된 `CastRecordBody` 객체 전체. §8.6 규칙으로 다시 디코딩한다. 추적코드 = 이 바이트의 §4 해시 |
| 2 | `device_sig_ed25519` | `[u8; 64]` | 본문 바이트에 대한 기록 서명(purpose `cast-record`) |
| 3 | `module_sigs` | `Array<{module_id: Ident<64>, ed25519: [u8; 64]}, 7>` | `module_id` 오름차순, 중복 없음, 본문의 `module_counters`와 같은 ID 집합이어야 한다(`InvariantViolation`). 메시지는 `body_hash ‖ module_id ‖ counter`(PROTOCOL.md §7.2.1) |

### 8.8 `ChallengeOpeningBody` (`schema_id` 0x0006, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `ballot_style_id` | `Ident<64>` | |
| 4 | `record_hash` | `Hash512` | 폐기되는 표의 추적코드 |
| 5 | `option_index` | `u16` | `0..=m+1`. 인코딩 수준에서는 `<= 63`(선택지 상한)만 검사하며 초과는 `ValueOutOfRange`; m은 genesis가 정한다 |
| 6 | `cast_id` | `Token192` | |
| 7 | `rand` | `Array<Scalar, 8>` | 합산 난수 `r_0..r_{k−1}`, 개수 = k ≥ 1(0이면 `ValueOutOfRange`) |
| 8 | `modules` | `Array<{module_id: Ident<64>, counter: u64, rand: Array<Scalar, 8>, cid: Token192}, 7>` | `module_id` 오름차순, 중복 없음, 각 `rand` 개수 = k |

### 8.9 `ChallengeOpening` (`schema_id` 0x0018, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<4096>` | 인코딩된 `ChallengeOpeningBody` 객체 전체 |
| 2 | `device_sig` | `[u8; 4691]` | 본문 바이트에 대한 하이브리드 서명(purpose `challenge`) |

### 8.10 `SharePackage` (`schema_id` 0x000B, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `commitments` | `Array<Point, 8>` | 대응 기록의 커밋먼트(기록 해시는 이 객체의 해시에 의존하므로 넣을 수 없다). 개수 ≥ 1(0이면 `ValueOutOfRange`) |
| 4 | `entries` | `Array<{trustee_id: Ident<64>, chamber: u8, transport: u8, pad_id: u32, pad_index: u64, ciphertext: Bytes<4096>, tag: [u8; 16]}, 64>` | `trustee_id` 오름차순, 중복 없음. `chamber` 1 P1, 2 P2, 3 P3, 4 P4, 5 J, 6 A, 7 C, 8 N(ADR-0019). genesis 정당 명부에 없는 정당 챔버 코드는 검증기가 거부한다. `transport` 0 패드(`ciphertext` = `MemberShare` ⊕ 패드, `tag` = Poly1305), 1 KEM(§9.6 배치, `pad_id = pad_index = 0`). 그 외 값은 `ValueOutOfRange` |

서명은 없다. 패키지는 서명된 투함 기록의 `share_package_hash`로 결속된다(PROTOCOL.md §9.3, ADR-0017 §2).

### 8.11 `MemberShare` (`schema_id` 0x0015, `schema_version` 1)

구성원 한 명의 평문이다. `SharePackage` 항목의 암호문 안에만 존재한다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `shares` | `Array<Scalar, 58>` | 비밀 순서: 존재 모듈을 `module_id` 오름차순으로, 모듈마다 `r_{c,0..k−1}`; 그 뒤 `cast_id`; 관외·재외면 그 뒤 `env_label`. 개수 = 모듈 수 × k + 1(+1) ≥ 1(0이면 `ValueOutOfRange`). 상한 58 = 모듈 7 × 청크 8 + 2 |
| 2 | `has_module` | `bool` | 구성원 챔버에 모듈이 있으면 1 |
| 3 | `cid` | `Token192` | `has_module`이면 그 모듈의 `cid_c`, 아니면 전부 0 |
| 4 | `lab` | `Option<Token192>` | 관외·재외이고 `has_module`이면 `lab_c`, 아니면 없음 |
| 5 | `tag` | `[u8; 16]` | `has_module`이면 모듈의 `tag_{c,i}`, 아니면 전부 0 |

객체 길이는 선거 구성(모듈 수, 그 표의 k, 프로필)으로 정해진다. 패드 소비 바이트 `b`는 투표함 단위로 하나이며 그 투표함의 투표양식 전부에 대한 최대 길이에 64를 더한 값이다(PROTOCOL.md §9.4.3).

### 8.12 `BatchAttestBody` (`schema_id` 0x0012, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `batch_index` | `u32` | 투표함별 0부터 1씩 |
| 4 | `record_count` | `u16` | `1..=64` |
| 5 | `records_root` | `Hash512` | 기록 해시의 정렬 집합 root(PROTOCOL.md §5.3) |
| 6 | `module_ranges` | `Array<{module_id: Ident<64>, counter_first: u64, counter_last: u64}, 7>` | `module_id` 오름차순, `counter_first <= counter_last` |
| 7 | `module_refusals` | `Array<Ident<64>, 7>` | 오름차순, 중복 없음. 6의 `module_ranges`에 있는 ID만 허용(`InvariantViolation`) |
| 8 | `journal_head` | `Hash512` | 배치를 닫을 때의 저널 head |
| 9 | `time_bucket` | `u64` | |

### 8.13 `BatchAttest` (`schema_id` 0x0017, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<2048>` | 인코딩된 `BatchAttestBody` 객체 전체 |
| 2 | `module_sigs` | `Array<{module_id: Ident<64>, sig: [u8; 4691]}, 7>` | 오름차순, 중복 없음. 본문의 `module_ranges` ID 중 `module_refusals`에 없는 것과 같은 집합 |
| 3 | `device_sig` | `[u8; 4691]` | 하이브리드 서명(purpose `batch-attest`) |

### 8.14 `ScanCountAttestBody` (`schema_id` 0x0013, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `record_count` | `u64` | 누적 |
| 4 | `challenge_count` | `u64` | 누적 |
| 5 | `quarantine_count` | `u64` | 누적 |
| 6 | `journal_head` | `Hash512` | |
| 7 | `time_bucket` | `u64` | |

### 8.15 `ScanCountAttest` (`schema_id` 0x001B, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<512>` | 인코딩된 `ScanCountAttestBody` 객체 전체 |
| 2 | `observer_sigs` | `Array<{observer_id: Ident<64>, org_id: Ident<64>, sig: [u8; 4691]}, 4>` | 2개 이상, `observer_id` 오름차순. 서로 다른 `org_id`가 2 이상이어야 한다(`InvariantViolation`). purpose `scan-count` |

### 8.16 `BoxCloseBody` (`schema_id` 0x0007, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `paper_count` | `u64` | |
| 4 | `record_count` | `u64` | |
| 5 | `attested_count` | `u64` | |
| 6 | `no_record_count` | `u64` | |
| 7 | `challenge_count` | `u64` | |
| 8 | `quarantine_count` | `u64` | |
| 9 | `visit_count` | `u64` | 넣은 표가 하나 이상인 방문 수(ADR-0021) |
| 10 | `envelope_count` | `u64` | 관외·재외 함의 회송 봉투 실물 수. 투표소 함은 0 |
| 11 | `sticker_count` | `u64` | 관외·재외 함의 라벨 스티커 수(비상 표지 제외). 투표소 함은 0 |
| 12 | `record_set_root` | `Hash512` | 기록 해시 정렬 집합의 root |
| 13 | `journal_head` | `Hash512` | |
| 14 | `seal_digest` | `Hash512` | |
| 15 | `module_counters` | `Array<{module_id: Ident<64>, final_counter: u64}, 7>` | 오름차순, 중복 없음 |
| 16 | `open_batches` | `u8` | |
| 17 | `time_bucket` | `u64` | |

세 필드(9–11)가 더해져 본문이 24바이트 늘지만 `BoxClose.body`의 상한(`Bytes<1024>`) 안이다. 수량 규칙(`visit_count ≤ record_count ≤ 8·visit_count`, 관외·재외 함의 `paper_count` 0과 `sticker_count == visit_count`)은 PROTOCOL §10.2가 정하며 디코더가 아니라 마감 검사와 검증기가 확인한다.

### 8.17 `BoxClose` (`schema_id` 0x001A, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<1024>` | 인코딩된 `BoxCloseBody` 객체 전체 |
| 2 | `device_sig` | `Option<[u8; 4691]>` | 장치가 살아 있을 때의 하이브리드 서명(purpose `box-close`). 없으면 `BoxCloseManual`이다 |
| 3 | `attestations` | `Array<{signer_id: Ident<64>, role: u8, org_id: Ident<64>, sig: [u8; 4691]}, 8>` | `signer_id` 오름차순. `role` 1 사무원, 2 참관인. 사무원 2 이상, 서로 다른 `org_id`의 참관인 2 이상(`InvariantViolation`). purpose `box-close` |

### 8.18 `SlipBody` (`schema_id` 0x0019) and `Slip` (`schema_id` 0x000A), `schema_version` 1

`SlipBody`: `election_id: Ident<64>` ‖ `station_id: Ident<64>` ‖ `time_bucket: u64` ‖ `tracking_codes: Array<Hash512, 8>`(1 이상 8 이하, 방문의 위치 순서. 개수 0은 `ValueOutOfRange`, 같은 코드 두 번은 `Duplicate`). 방문당 슬립 하나(ADR-0021).

`Slip`: `body: Bytes<1024>`(인코딩된 `SlipBody` 객체 전체; 코드 8개에서 약 680바이트) ‖ `device_sig: [u8; 4691]`(purpose `slip`).

### 8.19 장치 링크 객체 (`ityv-cunit` 구현)

`Interpretation` (`schema_id` 0x0101): `election_id: Ident<64>` ‖ `ballot_style_id: Ident<64>` ‖ `option_index: u16`. 커밋먼트 유닛은 이 객체 외의 어떤 바이트도 해석 유닛에서 받지 않는다. `option_index > m+1`은 거부한다(m은 genesis의 투표양식에서).

`VisitEnd` (`schema_id` 0x0104): `election_id: Ident<64>` ‖ `ballot_count: u8`(1 이상 8 이하). 해석 유닛이 한 방문의 투표지를 다 보낸 뒤 보낸다. 커밋먼트 유닛은 `ballot_count`가 직전 `VisitEnd` 이후 받은 `Interpretation` 수와 다르면 그 방문을 결정 없이 격리한다(PROTOCOL §7.3). 해석 유닛은 불신 부품이라 방문 경계를 잘못 알려도 생기는 일은 결정 화면이 둘로 나뉘거나 방문이 격리되는 것뿐이다.

`AttestChallenge` (`schema_id` 0x0105): `election_id: Ident<64>` ‖ `observer_id: Ident<64>` ‖ `nonce: [u8; 32]` ‖ `challenge_sig: [u8; 64]`(참관인 확인 키의 Ed25519 서명, purpose `attest-challenge`, 서명 대상은 `election_id ‖ station_id ‖ observer_id ‖ nonce`; `station_id`는 커밋먼트 유닛이 자기 설정에서 채운다). 해석 유닛은 확인 카드의 QR만 이 객체로 옮기며 다른 필드를 만들 수 없다. 커밋먼트 유닛은 `observer_id`가 genesis의 자기 투표소 참관인 토큰 목록에 없거나, 서명이 틀리거나, 열린 방문이 있거나(마지막 `VisitEnd` 뒤 받은 `Interpretation`이 있거나 대기 구역에 투표지가 있음), 직전 증명 뒤 30초가 지나지 않았으면 이 객체를 버리고 투표 상태를 바꾸지 않는다(PROTOCOL §7.9, VC-088).

`ModuleIssue` (`schema_id` 0x0103): `module_id: Ident<64>` ‖ `chamber: u8`(1 P1, 2 P2, 3 P3, 4 P4, 5 J, 6 A, 7 C. N은 모듈이 없다) ‖ `counter: u64`(≥ 1) ‖ `rand: Array<Scalar, 8>`(개수 = k) ‖ `cid: Token192` ‖ `lab: Option<Token192>` ‖ `tags: Array<[u8; 16], 8>`(챔버 구성원 순서). 비공개부(`rand` 이후)는 링크 밖으로 나가지 않는다.

`JournalEntry` (`schema_id` 0x0014): `prev_head: Hash512`(첫 항목은 0) ‖ `kind: u8`(1 기록, 2 검증 폐기, 3 격리, 4 배치 마감, 5 투표함 마감, 6 각인 완료, 7 방문 결정, 8 라벨 출력, 9 묶음) ‖ `record_hash: Hash512` ‖ `share_package_hash: Hash512`(기록이 아니면 0) ‖ `module_counters: Array<{module_id: Ident<64>, counter: u64}, 7>` ‖ `time_bucket: u64`. `record_hash`의 뜻은 종류마다 다르다: 1·2는 그 표의 기록 해시, 3은 저널에 기록된 표를 격리하면 그 기록 해시이고 기록 전 격리(부분 발급, 각인 전 고장)면 0, 4는 배치의 `records_root`, 5는 투표함의 `record_set_root`, 6은 각인을 마친 기록의 해시, 7은 방문 결정 다이제스트 `SHA3-512("ityv:visit:v1" ‖ 0x00 ‖ n: u8 ‖ (kind_i: u8 ‖ record_hash_i)…)`(바로 앞의 위치 항목 n개, 위치 순), 8은 그 방문의 결정 다이제스트(라벨 값은 저널에 남기지 않는다), 9는 묶은 위치의 기록 해시(0이 아니다). 7·8의 `share_package_hash`는 0이고 `module_counters`는 비어 있다. 9의 `share_package_hash`는 0이다(패키지는 결정 뒤 1과 함께 쓴다). 한 방문의 항목은 묶음(9) n개(위치마다 fsync), 위치 항목(1·2) n개(묶음 항목과 같은 위치 순), 방문 결정(7), 처리 항목(6·3), 관외면 라벨 출력(8) 순이다(PROTOCOL §7.3, VC-069). 결정 전에 끝난 방문은 묶음 항목 뒤에 묶인 위치마다 그 기록을 지목하는 격리(3)를 둔다. `module_counters`는 그 항목이 소비한 카운터(9와 기록 전 격리 3) 또는 배치·마감 시점의 최고값(4·5)이다. 위치 항목(1·2), 기록을 지목하는 격리(3), 각인 완료(6)는 같은 기록의 묶음 항목(9)의 카운터를 되풀이할 뿐 새로 소비하지 않는다. 방문 결정 다이제스트는 위치 항목(1·2)만 덮는다. 묶음 항목은 같은 기록 해시와 카운터로 위치 항목에 결속되므로 다이제스트에 넣지 않는다. head = 항목의 §4 해시. 디스크 스트림은 `u32_be 길이 ‖ 항목`이며, 기록 항목 뒤에는 `u32_be 길이 ‖ SharePackage 객체`가 따른다. `sealed` 등급이다.

### 8.20 오류 보고 규칙

개수에 하한이 있는 배열은 하한 미달을 `ValueOutOfRange`(개수 접두사 오프셋)로 보고한다. 집합 수준 불변식(ID 집합 일치, 역할·조직 수, 중복 없는 정렬 뒤의 교차 검사)은 배열 전체를 읽은 뒤 그 배열의 개수 접두사 오프셋으로 보고하며, 배열 안의 위반(`NotSorted`, `Duplicate`, 범위)이 먼저 발견되면 그것이 우선한다. 디코더는 필드를 읽는 즉시 그 필드의 규칙을 검사한다(뒤 필드를 읽기 전에).

디코더는 첫 번째 위반에서 멈추고 `(종류, 오프셋)`을 돌려준다. 오프셋은 객체 시작(헤더의 magic) 기준 절대 오프셋이다. 헤더 위반의 오프셋은 `BadMagic` 0, `SchemaMismatch` 4, `UnsupportedVersion` 8, `NonZeroFlags` 10, `BodyLengthMismatch` 12이고, 본문 뒤 잉여 바이트는 `TrailingBytes`(잉여가 시작되는 오프셋)다.

### 8.21 `ConnectivityManifest` (`schema_id` 0x001C, `schema_version` 1)

genesis가 해시로 고정하고 본문을 함께 공표한다(PROTOCOL §4.1, §5.8, ADR-0022).

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `frame_body_len` | `u32` | 1,048,576이어야 한다. 그 외 값은 `ValueOutOfRange` |
| 3 | `slot_minutes` | `u16` | 10이어야 한다 |
| 4 | `entries` | `Array<{link_id: Ident<64>, device_class: u8, port: Ident<32>, direction: u8, medium: u8, counterpart: Ident<64>, schedule: u8, frames_per_slot: u16, catchup_frames_per_slot: u16, carries: u32, frame_key: [u8; 32]}, 1024>` | 1개 이상, `link_id` 바이트 오름차순, 중복 없음 |

- `device_class`: 1 해석 유닛, 2 커밋먼트 유닛·스캐너 바깥 포트, 3 카운터·가명 유닛, 4 챔버 모듈, 5 선거일 신원 확인 단말, 6 사전투표 신원 확인 단말, 7 투표소 게이트웨이, 8 관찰 탭, 9 장부 수집 서버, 10 게시판 공표 서버, 11 증인, 12 신뢰기관 수신 시스템, 13 수령 라벨 판독기, 14 각인 판독기, 15 프린터류(각인기·슬립·라벨). 그 외 값은 `ValueOutOfRange`.
- `direction`: 0 없음(봉인 또는 미장착), 1 내보내기만(수신 소자 없음), 2 받기만, 3 양방향.
- `medium`: 0 없음, 1 광 송신 전용, 2 광커플러(장치 내부), 3 유선 이더넷, 4 광 회선, 5 선거 전용회선(통합선거인명부), 6 입회 절차 현장 직결, 7 무선.
- `schedule`: 0 사용 안 함, 1 투표함 개시–마감 처리, 2 사전투표 기간, 3 상시, 4 입회 절차 때만.
- `carries` 비트: 0 공개 기록·배치 증명, 1 봉인 share 패키지, 2 확인 카운터, 3 장치 링크 객체, 4 체크포인트·장부, 5 명부 조회(개인정보), 6 세션 기록. 정의되지 않은 비트가 서 있으면 `ValueOutOfRange`.
- `frame_key`: `UplinkFrame`을 서명하는 Ed25519 공개키. 프레임을 보내지 않는 항목은 0이어야 한다.
- 집합 불변식(`InvariantViolation`, `entries` 개수 접두사 오프셋): `device_class` 1–4의 항목은 `direction` ∈ {0, 1}이고 `medium` ≠ 7이다. `direction` 3은 `device_class` 6(`medium` 5, `schedule` 2), 7(바깥 회선), 9–12에만 쓴다. `device_class` 8은 `direction` 1만 쓴다. `carries` 비트 5는 `device_class` 6과 그 상대에만 쓴다. genesis의 장치·포트가 빠짐없이 덮였는지는 검증기가 genesis와 대조한다(VC-077).

### 8.22 `UplinkFrame` (`schema_id` 0x001D, `schema_version` 1)

본문 길이는 언제나 1,048,576바이트다(헤더의 `body_len` 고정). 모든 필드가 고정폭이다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `link_id_hash` | `Hash512` | 연결 목록 항목 `link_id`의 §4 해시 |
| 2 | `slot` | `u64` | 선거 epoch 기준 10분 슬롯 번호 |
| 3 | `index` | `u16` | 슬롯 안 순번. 일반은 `frames_per_slot` 미만, 따라잡기는 `catchup_frames_per_slot` 미만 |
| 4 | `kind` | `u8` | 0 일반, 1 따라잡기, 2 마감 재전송, 3 입회 재전송. 그 외 값은 `ValueOutOfRange` |
| 5 | `stream_offset` | `u64` | 이 링크 바이트 흐름에서 `payload` 첫 바이트의 위치 |
| 6 | `payload_len` | `u32` | 1,048,425 이하 |
| 7 | `payload` | `[u8; 1048425]` | 앞 `payload_len` 바이트가 흐름의 연속 구간. 나머지는 0이어야 하며 아니면 `NonCanonical` |
| 8 | `frame_sig` | `[u8; 64]` | `frame_key`의 Ed25519 서명(purpose `uplink-frame`), 필드 1–7의 인코딩에 대해 |

흐름은 정규 객체의 연접이며 연결 목록 `carries`가 허용한 스키마만 담는다. 수신자는 흐름을 이어 붙여 객체 경계를 복원하고, 정규 객체가 아닌 바이트나 허용되지 않은 스키마를 위반으로 기록한다(PROTOCOL §5.8 10항).

### 8.23 `UplinkSessionBody` (`schema_id` 0x001E, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `gateway_id` | `Ident<64>` | |
| 4 | `session_index` | `u32` | 게이트웨이마다 1부터 1씩 |
| 5 | `final` | `bool` | 마감 때 최종 기록이면 1 |
| 6 | `start_slot` | `u64` | |
| 7 | `end_slot` | `u64` | `start_slot` 이상 |
| 8 | `links` | `Array<{link_id_hash: Hash512, frames: u64, catchup_frames: u64, missing_slots: u32, last_stream_offset: u64, chain_head: Hash512}, 16>` | `link_id_hash` 오름차순, 중복 없음 |
| 9 | `wan_bytes` | `u64` | 이 세션 동안 게이트웨이가 바깥 회선으로 보낸 바이트 |
| 10 | `previous_session_hash` | `Hash512` | 첫 세션이면 0 |

사슬: `h_0 = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ link_id_hash)`, `h_i = SHA3-512("ityv:uplink:v1" ‖ 0x00 ‖ h_{i−1} ‖ frame_hash_i)`. `frame_hash`는 `UplinkFrame` 객체의 §4 해시다. 세션은 앞 세션의 head에서 이어진다.

### 8.24 `UplinkSession` (`schema_id` 0x001F, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<2048>` | 인코딩된 `UplinkSessionBody` 객체 전체 |
| 2 | `gateway_sig` | `[u8; 4691]` | 하이브리드 서명(purpose `uplink-session`) |
| 3 | `observer_sigs` | `Array<{observer_id: Ident<64>, org_id: Ident<64>, capture_hash: Hash512, sig: [u8; 4691]}, 4>` | 0개 이상, `observer_id` 오름차순, 중복 없음. `capture_hash`는 그 참관인이 받아 둔 캡처 파일의 SHA3-512. purpose `uplink-session` |

### 8.25 `ParticipationSet` (`schema_id` 0x0020, `schema_version` 1)

투표 종료 뒤 카운터·가명 유닛이 투표소마다 하나 만든다. 가명 다중집합의 유일한 공개 형태다(PROTOCOL §6.5, VC-084). 순번과 시간 필드는 없다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | genesis에 등록된 값 |
| 3 | `count` | `u32` | 0..=65536, `pseudonyms` 개수와 같음 |
| 4 | `pseudonyms` | `Array<Hash512, 65536>` | 바이트 사전순 비내림차순. 같은 가명은 나온 횟수만큼 반복(중복 투표를 드러내기 위함) |
| 5 | `counter_sig` | `[u8; 4691]` | 카운터·가명 유닛 하이브리드 서명, purpose `participation-set`, 서명 대상은 필드 1–4의 인코딩 |
| 6 | `module_sigs` | `Array<{module_id: Ident<64>, sig: [u8; 4691]}, 4>` | 정당 모듈 P1…Pn 각각의 하이브리드 서명(챔버 코드 순, 정확히 n개), purpose `participation-set`, 서명 대상은 필드 1–4의 인코딩 |

최대 크기는 약 4.2MB로, 연결 감사의 프레임 1개(§8.22)를 넘으면 같은 일정의 연속 프레임으로 나간다(PROTOCOL §5.8).

### 8.26 `ReleaseManifestBody` (`schema_id` 0x0021, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `release_id` | `Ident<64>` | |
| 3 | `images` | `Array<ImageEntry, 128>` | `component_id` 바이트 순, 중복 없음 |
| 4 | `bundles` | `Array<BundleEntry, 32>` | `bundle_id` 바이트 순, 중복 없음 |
| 5 | `release_keys` | `Array<{key_id: Ident<64>, role: u8, pk: [u8; 2624]}, 16>` | 빌더(role 1)·인증기관(2)·위원회(3) 하이브리드 공개키. 장치 OTP에 넣는 키의 원본 |

`ImageEntry`: `component_id: Ident<64>` ‖ `device_class: u8`(1 해석 유닛, 2 커밋먼트 유닛, 3 챔버 모듈, 4 카운터·가명 유닛, 5 신원 확인 단말, 6 투표소 게이트웨이, 7 각인기 제어기, 8 슬립·라벨 프린터 제어기, 9 개표소 분류기 확장, 10 참관인·유권자 앱) ‖ `supplier_id: Ident<64>` ‖ `version: Ident<32>`(의미 버전 문자열) ‖ `build: u64`(≥ 1, 같은 `component_id`의 이전 릴리스보다 큼) ‖ `source_commit: Ident<64>`(16진 커밋 해시) ‖ `toolchain_id: Ident<64>` ‖ `image_hash: Hash512` ‖ `ui_strings_hash: Hash512`(화면 문구 표의 해시, 화면이 없으면 0).

`BundleEntry`: `bundle_id: Ident<64>` ‖ `bundle_name: Ident<64>`(신원 줄의 프로그램 이름) ‖ `version: Ident<32>` ‖ `build: u64` ‖ `components: Array<Ident<64>, 16>`(바이트 순) ‖ `bundle_hash: Hash512`(= `SHA3-512("ityv:bundle:v1" ‖ 0x00 ‖ image_hash_1 ‖ …)`, 구성 요소 ID 바이트 순. 디코더는 재계산해 다르면 거부).

**소프트웨어 지문 표기.** 이미지 해시나 구성 해시의 앞 20바이트를 Base32(RFC 4648 알파벳, 대문자, 채움 없음)로 적은 32자. 신원 줄에는 앞 16자를 넷씩 넷으로, 상세 화면과 출력물에는 32자를 넷씩 여덟으로 보인다. 체크포인트 지문(PROTOCOL §5.7)과 같은 표기다.

### 8.27 `ReleaseManifest` (`schema_id` 0x0022, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<131072>` | 인코딩된 `ReleaseManifestBody` 객체 전체 |
| 2 | `builder_sigs` | `Array<{key_id: Ident<64>, org_id: Ident<64>, sig: [u8; 4691]}, 8>` | 3개 이상, `key_id` 오름차순, `org_id` 서로 다름, purpose `release-build` |
| 3 | `cert_sig` | `[u8; 4691]` | 인증기관, purpose `release-cert` |
| 4 | `committee_sig` | `[u8; 4691]` | 독립검증위원회, purpose `release-cert` |

### 8.28 `DeviceAttestationBody` (`schema_id` 0x0023, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `device_id` | `Ident<64>` | genesis에 등록된 장치 |
| 3 | `device_class` | `u8` | §8.26의 값 |
| 4 | `challenge` | `{path: u8, observer_id: Ident<64>, nonce: [u8; 32], challenge_sig: [u8; 64]}` | `path` 1 토큰, 2 확인 카드 |
| 5 | `time_bucket` | `u64` | |
| 6 | `boot_count` | `u32` | OTP 부팅 횟수 |
| 7 | `components` | `Array<{component_id: Ident<64>, version: Ident<32>, build: u64, image_hash: Hash512}, 16>` | 부팅 때 잰 값, `component_id` 바이트 순 |
| 8 | `bundle_hash` | `Hash512` | 7에서 §8.26 규칙으로 계산 |
| 9 | `modules` | `Array<{module_id: Ident<64>, build: u64, image_hash: Hash512, boot_count: u32, sig: [u8; 4691]}, 7>` | 챔버 모듈마다 같은 `challenge`와 `device_id`에 대해 모듈 증명 키로 서명한 진술(purpose `module-attestation`), 챔버 코드 순. 모듈이 없는 장치는 0개 |

투표에 관한 값(기록 수, 선택, 투함 ID, 가명, 저널 head)은 담지 않는다.

### 8.29 `DeviceAttestation` (`schema_id` 0x0024, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<40960>` | 인코딩된 `DeviceAttestationBody` 객체 전체 |
| 2 | `attestation_sig` | `[u8; 4691]` | 장치 증명 키 하이브리드 서명, purpose `device-attestation` |

### 8.30 `AttestationSummary` (`schema_id` 0x0025, `schema_version` 1)

현장 QR용. 장부 이벤트가 아니며 슬립 프린터로 인쇄한다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `device_id` | `Ident<64>` | |
| 2 | `observer_id` | `Ident<64>` | |
| 3 | `nonce` | `[u8; 32]` | 도전값 |
| 4 | `time_bucket` | `u64` | |
| 5 | `boot_count` | `u32` | |
| 6 | `bundle_hash` | `Hash512` | |
| 7 | `body_hash` | `Hash512` | 같은 증명의 `DeviceAttestationBody` 해시(나중에 게시판 이벤트와 대조) |
| 8 | `summary_sig` | `[u8; 64]` | 증명 키의 Ed25519 부분 서명, purpose `attest-summary` |

전체 크기는 약 450바이트로 QR 하나에 들어간다.

### 8.31 `ModuleProvisioned` (`schema_id` 0x0026, `schema_version` 1)

모듈 발급 절차의 기록이다(PROTOCOL §9.4.2). 패드 값, 패드 해시, 챔버 엔트로피 원본은 담지 않는다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `module_id` | `Ident<64>` | genesis에 등록된 값 |
| 3 | `device_id` | `Ident<64>` | 이 모듈을 꽂을 장치 |
| 4 | `chamber` | `u8` | 챔버 코드 1–7(N은 모듈이 없다) |
| 5 | `member_count` | `u8` | 1..=8 |
| 6 | `pad_length` | `u64` | 구성원당 패드 바이트 수 |
| 7 | `chassis_id` | `Ident<64>` | 재사용 본체 ID |
| 8 | `pad_card_id` | `Ident<64>` | 패드 카드 ID |
| 9 | `reprovision_count` | `u32` | 본체 재발급 횟수 |
| 10 | `chassis_check_hash` | `Hash512` | 본체 변조 검사·펌웨어 측정 결과 문서의 해시 |
| 11 | `kem_ek` | `[u8; 1600]` | 모듈 하이브리드 KEM 공개키(`mlkem1024_ek ‖ x25519`). 정당 PRF 키 주입에 쓴다 |
| 12 | `entropy_commitment` | `Hash512` | `SHA3-512("ityv:entropy:v1" ‖ 0x00 ‖ 챔버 엔트로피)` |
| 13 | `se_present` | `bool` | 보안 칩이 있으면 1. 카운터·가명 유닛의 정당 모듈이면 반드시 1 |
| 14 | `prf_key_check` | `Option<[u8; 32]>` | 카운터·가명 유닛의 정당 모듈이면 존재, 그 밖에는 부재. `HMAC-SHA-256(key_c, "ityv:prfcheck:v2")` |
| 15 | `signatures` | `Array<{actor_id: Ident<64>, sig: [u8; 4691]}, 16>` | 위원회·챔버·참관인 하이브리드 서명, `actor_id` 오름차순, 중복 없음, purpose `module-provisioned`. 서명 대상은 필드 1–14의 인코딩 |

### 8.32 `PartyKeyCeremony` (`schema_id` 0x0027, `schema_version` 1)

정당 열쇠 생성 절차의 기록이다(PROTOCOL §6.4). 키, 몫, 엔트로피는 담지 않는다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `chamber` | `u8` | 정당 챔버 코드 1–4 |
| 3 | `wrapped_module_count` | `u32` | `key_c`를 감싸 보낸 확인 모듈 수 |
| 4 | `share_threshold` | `u8` | k(기본 2) |
| 5 | `share_count` | `u8` | n(기본 3), `share_threshold ≤ share_count ≤ 8` |
| 6 | `share_holders` | `Array<{trustee_id: Ident<64>, hsm_model: Ident<64>, hsm_serial_hash: Hash512}, 8>` | 몫 보관 구성원과 장비, `trustee_id` 오름차순, 개수 = `share_count` |
| 7 | `prf_key_check` | `[u8; 32]` | 이 정당 모든 확인 모듈의 `ModuleProvisioned`와 같아야 함(VC-093) |
| 8 | `time_bucket` | `u64` | |
| 9 | `signatures` | `Array<{actor_id: Ident<64>, sig: [u8; 4691]}, 16>` | 위원회, 참석 정당 구성원, 서로 다른 조직의 참관인 2 이상. purpose `party-key`. 서명 대상은 필드 1–8의 인코딩 |
