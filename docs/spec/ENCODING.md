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

- 헤더 없는 필드 묶음: 다음 여섯 용도는 객체가 아니라 필드의 정규 인코딩(§2)을 헤더 없이 이어 붙인 바이트열을 위 서명 메시지의 `obj`로 쓴다. `attest-challenge`(Ed25519만): `election_id ‖ station_id ‖ observer_id ‖ nonce`(§8.19). `module-attestation`(하이브리드): `device_id ‖ challenge ‖ module_id ‖ build ‖ image_hash ‖ boot_count`(§8.28). `attest-summary`(Ed25519만): `AttestationSummary`의 1–7번 필드(§8.30). `participation-set`(하이브리드): `ParticipationSet`의 1–4번 필드(§8.25). `module-provisioned`(하이브리드): `ModuleProvisioned`의 1–14번 필드(§8.31). `party-key`(하이브리드): `PartyKeyCeremony`의 1–8번 필드(§8.32). 필드 묶음은 해시하거나 공표하지 않으며 서명 입력으로만 쓴다. 뒤의 세 객체는 필드 묶음이 객체 본문의 앞부분 그대로이므로, 검증기는 본문에서 그 바이트를 잘라 서명을 확인한다(다시 인코딩하지 않는다).

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
| 0x0002 | `GenesisBody` | 8 | genesis 본문: 핀·키·정족수·명부 보관 정족수·정당 명부·챔버, 항목 집합 13개의 (수, root)(§8.54, ADR-0028). 버전 1–5는 내용만 나열한 명세 초안(3에서 연결 목록 해시, 4에서 릴리스 목록 해시와 증명 키·참관인 확인 키, 5에서 `progress_policies[]`)이었고 인코딩된 적이 없다. 버전 6이 처음 인코딩된 형식이다(집합 11개). 버전 7(ADR-0039): 집합 12(시점확인 기관)를 더한다. 버전 8(ADR-0040): 명부 보관 정족수와 집합 13(명부 기관)을 더한다. 앞 버전 본문은 받지 않는다 |
| 0x0003 | `LegalAuthorization` | 1 | scope 집합, 조문 참조 해시, 시행 구간 |
| 0x0004 | `CheckpointBody` | 1 | tree_size, root, prev, box_close_root, dispute_root |
| 0x0005 | `CastRecordBody` | 1 | 투함 기록 본문: 커밋먼트 벡터, 증명, 모듈 카운터, share 패키지 해시(§8.6) |
| 0x0006 | `ChallengeOpeningBody` | 1 | 투입 전 검증 공개값 본문(§8.8) |
| 0x0007 | `BoxCloseBody` | 1 | 마감 본문: 수량, 봉인 해시, 저널 head(§8.16) |
| 0x0008 | `CustodyHandoffBody` | 1 | 인계 본문: 순번, 송신·수신자, 이전 인계 해시, 봉인, 수량(§8.33). 서명은 `WitnessedEvent`(0x0028) |
| 0x0009 | `CheckinCounter` | 1 | 확인 카운터 이벤트(`restricted`, PROTOCOL §6.3) |
| 0x000A | `Slip` | 1 | 슬립 본문 바이트 + 장치 하이브리드 서명(§8.18) |
| 0x000B | `SharePackage` | 1 | 신뢰기관별 암호화 share 묶음(§8.10, 공개하지 않음) |
| 0x000C | `ReceiptMark` | 1 | 관외 수령 라벨 목록 |
| 0x000D | `AuditSeedBody` | 1 | 표본 추출 시드(`AuditSeed`): 주사위 기록 해시, 비콘 회차와 값, 고정 체크포인트 해시, 시드(§8.67, ADR-0036). 서명은 `WitnessedEvent` |
| 0x000E | `DisputeEventBody` | 1 | 분쟁 접수·처리 본문(§8.34). 서명은 `WitnessedEvent` |
| 0x000F | `LegalDecisionRefBody` | 1 | 법적 결정 참조 본문: 결정 기관, 결정문 해시, 대상 분쟁, 결과, 집계 효과(§8.35). 서명은 `WitnessedEvent` |
| 0x0010 | `SignedCheckpoint` | 1 | 체크포인트 본문 바이트와 증인 서명 묶음(§8.4, ADR-0016) |
| 0x0011 | `WitnessMemory` | 2 | 증인 도구가 영속화하는 마지막 서명 기억(§8.5, ADR-0016 §4). 장부 이벤트가 아니다. 버전 2(ADR-0036 개정): 마지막 서명 본문의 `time_bucket`을 더해 기억한다(시각 단조, VC-012). 버전 1은 읽지 않는다 |
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
| 0x0028 | `WitnessedEvent` | 1 | 사람이 서명하는 장부 이벤트의 공통 봉투: 본문 객체 바이트 + 역할별 하이브리드 서명(§8.42, ADR-0025). 버전 2(ADR-0035): 역할 9(구·시·군 선관위 위원장)와 본문 `PaperCountReportBody`를 받는다. 버전 3(ADR-0036): 역할 10(감사인)과 감사 본문 0x000D·0x0048·0x004B·0x004C·0x004D·0x004E를 받는다. 버전 4(ADR-0040): 역할 11(명부 출처 기관)·12(명부 보관 기관)와 명부 본문 0x0052–0x0055를 받는다 |
| 0x0029 | `BoxOpenedBody` | 1 | 투표함 개시 본문(§8.36) |
| 0x002A | `FallbackBody` | 1 | `FallbackDeclared`·`FallbackEnded` 본문(§8.37) |
| 0x002B | `IssuanceCountBody` | 1 | 투표소 교부 회계 본문(§8.38) |
| 0x002C | `ImprintAuditBody` | 1 | 개표소 각인 판독 결과 본문(§8.39) |
| 0x002D | `SealChangeBody` | 1 | 봉인 변경 본문(§8.40) |
| 0x002E | `LateBatchCloseBody` | 1 | 늦은 배치 마감 본문(§8.41) |
| 0x002F | `BoxProgressBody` | 1 | 투표함 진행 기록 본문: 슬롯, 투입 장수 누계, 상태(§8.44, ADR-0027) |
| 0x0030 | `CheckinProgressBody` | 1 | 투표소 진행 기록 본문: 슬롯, 본인 확인·교부·훼손 회수·반납 누계, 상태(§8.45) |
| 0x0031 | `ProgressTick` | 1 | 진행 기록 본문 바이트 + 장치 하이브리드 서명(§8.46) |
| 0x0032 | `ProgressCheckBody` | 1 | 진행 경보의 현장 확인 본문(§8.47). 서명은 `WitnessedEvent` |
| 0x0033 | `SignedGenesis` | 1 | genesis 또는 변경 본문 바이트 + 선관위·위원회·증인 서명(§8.56, ADR-0028) |
| 0x0034 | `GenesisAmendmentBody` | 1 | genesis 변경 본문: 번호, 이전 본문 해시, 사유, 바뀔 수 있는 집합 8개의 (수, root)(§8.55) |
| 0x0035 | `GenesisBox` | 1 | genesis 항목: 예정 투표함(§8.43) |
| 0x0036 | `StationEntry` | 1 | genesis 항목: 투표소(§8.49) |
| 0x0037 | `StationProgressPolicy` | 1 | genesis 항목: 투표소 진행 경보 기준(§8.48) |
| 0x0038 | `ReportingUnitEntry` | 1 | genesis 항목: 보고 단위(§8.50). 버전 2(ADR-0035): 종이 개표를 보고하는 구·시·군 선관위 `commission_org`를 더한다 |
| 0x0039 | `CustodyRoute` | 1 | genesis 항목: 보관 경로(§8.43) |
| 0x003A | `RosterSigner` | 1 | genesis 항목: 서명자 명부(§8.43). 버전 2(ADR-0035): 역할 5(구·시·군 선관위 위원장)를 받는다. 버전 3(ADR-0036): 역할 6(감사인)을 받는다 |
| 0x003B | `ModuleEntry` | 1 | genesis 항목: 챔버 모듈(§8.51) |
| 0x003C | `BallotStyleEntry` | 1 | genesis 항목: 투표양식(§8.52) |
| 0x003D | `TrusteeEntry` | 1 | genesis 항목: 신뢰기관 구성원(§8.53) |
| 0x003E | `WitnessRosterEntry` | 1 | genesis 항목: 증인(§8.53) |
| 0x003F | `ObserverCountAttestBody` | 1 | 참관인 확인 인원 증명 본문(§8.57). 서명은 `WitnessedEvent` |
| 0x0040 | `CheckinUnitSwapBody` | 1 | 카운터·가명 유닛 교체 본문(§8.58). 서명은 `WitnessedEvent` |
| 0x0041 | `BoxUnitSwapBody` | 1 | 커밋먼트 유닛 교체 본문(§8.59). 서명은 `WitnessedEvent` |
| 0x0042 | `SignedLegalAuthorization` | 1 | 법적 승인 본문 바이트 + 선관위·위원회 하이브리드 서명(§8.60, ADR-0030) |
| 0x0043 | `TallyScopeBody` | 1 | 집계 범위: 투표양식·보고 단위별 포함 기록 수와 root, 비상 투입 수, 제외 목록(기록 해시·사유·근거)(§8.61, ADR-0035). 서명은 `QuorumSigned` |
| 0x0044 | `AggregateOpeningBody` | 1 | 합계 열기: 범위 본문 해시, 청크, `T_j`·`R_j`·`S`(§8.62). 서명은 `QuorumSigned` |
| 0x0045 | `QuorumSigned` | 1 | 신뢰기관 정족수의 봉투: 본문 객체 바이트 + 참여 구성원 서명(§8.63). 서명 메시지는 본문 해시와 참여 구성원 목록. 버전 2(ADR-0036): 본문 `SampleOpeningRefBody`(0x004A)를 받는다 |
| 0x0046 | `PaperCountReportBody` | 1 | 보고 단위별 종이 개표 결과: 후보별 득표, 무효 수(§8.64). 서명은 `WitnessedEvent` |
| 0x0047 | `ReceiptResolutionBody` | 1 | 관외 투표함 기록별 수령 대조 결과(§8.65, PROTOCOL §10.6). 서명은 `QuorumSigned` |
| 0x0048 | `AuditManifestFreezeBody` | 1 | 투표양식 하나의 감사 동결: 표본 프레임(수, root), 규칙 문서 해시, 위험 한도, 비콘 지정, 라운드(누적 표본 크기, 불일치 상한)(§8.66, ADR-0036). 서명은 `WitnessedEvent` |
| 0x0049 | `SampleOpeningBody` | 1 | 표본 기록 하나의 제한 등급 열기 `(option_index, cast_id, r_j)`(§8.68). 공개 장부에 싣지 않는다 |
| 0x004A | `SampleOpeningRefBody` | 1 | 제한 열기의 공개 흔적: 투표양식, 기록 해시, 제한 본문 객체 해시(§8.69). 서명은 `QuorumSigned` |
| 0x004B | `SampleComparisonBody` | 1 | 표본 대조: 기록 해시, 열기 해시, 장치, 사유 코드 0–6, `transfer_mark`(§8.70). 서명은 `WitnessedEvent` |
| 0x004C | `AuditFindingBody` | 1 | 감사 발견: 투표양식, 장치, 발견 문서 해시(§8.71). 서명은 `WitnessedEvent` |
| 0x004D | `HandCountReportBody` | 1 | 보고 단위별 수검표 결과(`PaperCountReportBody`와 같은 필드, §8.72). 서명은 `WitnessedEvent` |
| 0x004E | `AuditCommitBody` | 1 | 감사 약정(`AuditCommit`): 모든 동결 뒤, 비콘 공표 전에 주사위 기록 해시, 비콘 지정 문서 해시와 회차, 동결 본문들의 정렬 집합 root를 고정(§8.73, ADR-0036). 서명은 `WitnessedEvent` |
| 0x004F | `TimestampRecord` | 1 | 장부 이벤트: 기관 하나의 RFC 3161 토큰과 그 대상인 앞 이벤트(스키마, 객체 해시), 또는 응답 없음(§8.75, ADR-0034, ADR-0039). 자기 서명 없음 |
| 0x0050 | `TimestampAuthorityEntry` | 1 | genesis 항목(집합 12): 시점확인 기관, 운영 주체, 정부 운영 여부, 정책 정확도, `ityv-tsa` 핀 1–4개(§8.74, ADR-0039) |
| 0x0051 | `RollAuthorityEntry` | 1 | genesis 항목(집합 13): 명부의 출처 기관이나 보관 기관 하나, 그 조직, 기능 하나, 하이브리드 공개키(§8.76, ADR-0040) |
| 0x0052 | `RollSourceExtractBody` | 1 | 출처 추출(`RollSourceExtract`)의 공개부: 출처 기관, 종류, 투표구(주민등록 추출만), 기준일, 항목 수, 항목 commitment root(§8.77, ADR-0033, ADR-0040). 서명은 `WitnessedEvent` |
| 0x0053 | `RollFreezeBody` | 1 | 명부 동결(`RollFreeze`): 항목 root와 수, 인원수 표 해시, 명부 가명 root, 병합한 추출들의 정렬 집합 root와 수(§8.78). 서명은 `WitnessedEvent` |
| 0x0054 | `RollCustodyReceiptBody` | 1 | 보관 영수증(`RollCustodyReceipt`): 보관 기관이 다시 계산한 값과 답하는 동결·변경 본문 해시(§8.79). 서명은 `WitnessedEvent` |
| 0x0055 | `RollAmendmentBody` | 1 | 동결 뒤 변경(`RollAmendment`): 번호, 앞 본문 해시, 사유와 그 출처 기관, 근거 해시, 변경 뒤 값(§8.80). 서명은 `WitnessedEvent` |
| 0x0056 | `ContestedCheckin` | 1 | 이의 투표의 확인 기록(restricted): 투표소, 유닛, 가명, 봉투 라벨과 유닛·정당 모듈 서명(§8.81, PROTOCOL §6.2). 공개 장부는 프레임만 싣는다 |
| 0x0101 | `Interpretation` | 1 | 해석 유닛 → 커밋먼트 유닛 링크 객체(§8.19, `ityv-cunit` 구현) |
| 0x0103 | `ModuleIssue` | 1 | 챔버 모듈 → 커밋먼트 유닛 링크 객체(§8.19, `ityv-cunit` 구현) |
| 0x0104 | `VisitEnd` | 1 | 해석 유닛 → 커밋먼트 유닛 방문 끝 알림(§8.19, `ityv-cunit` 구현, ADR-0021) |
| 0x0105 | `AttestChallenge` | 1 | 확인 카드의 도전값을 해석 유닛이 커밋먼트 유닛으로 넘기는 링크 객체(§8.19, ADR-0023) |

필드 수준 정의는 `docs/spec/PROTOCOL.md`의 각 절과 §8이 가지며, 구현은 조직 경계를 넘는 객체는 `ityv-encoding`, 크레이트 내부 객체는 그 크레이트(비고에 표기; 0x0010·0x0011은 `ityv-ledger`)다. 둘이 다르면 이 문서와 PROTOCOL.md가 우선하고 크레이트는 결함이다. 0x0100–0x01FF는 장치 링크 객체 범위다. 0x0102는 커밋먼트 유닛 → 모듈 발급 요청에 남겨 둔다.

## 7. 시험 벡터

`ityv-encoding` 크레이트는 각 스키마의 정상 벡터와 거부 벡터를 `vectors/` 디렉터리에 16진수로 공개한다. 독립 2차 구현(V5)은 이 벡터로 차분 테스트를 한다. 파일 첫 줄에 스키마 ID와 버전이 있고, 거부 벡터는 오류 종류와 위치를 함께 적는다. genesis(ADR-0028) 벡터는 `genesis_body.txt`(버전 7), `signed_genesis.txt`, `genesis_amendment_body.txt`, `genesis_box.txt`, `station_entry.txt`, `station_progress_policy.txt`, `reporting_unit_entry.txt`, `custody_route.txt`, `roster_signer.txt`, `module_entry.txt`, `ballot_style_entry.txt`, `trustee_entry.txt`, `witness_roster_entry.txt`, `observer_count_attest_body.txt`, `checkin_unit_swap_body.txt`, `box_unit_swap_body.txt`다. 장부의 법적 승인(ADR-0030) 벡터는 `signed_legal_authorization.txt`다. 시점확인(ADR-0039) 벡터는 `timestamp_authority_entry.txt`, `timestamp_record.txt`다. 명부(ADR-0040) 벡터는 `roll_authority_entry.txt`, `roll_source_extract_body.txt`, `roll_freeze_body.txt`, `roll_custody_receipt_body.txt`, `roll_amendment_body.txt`, `contested_checkin.txt`다.

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

선관위와 독립검증위원회의 서명은 이 본문에 포함되지 않는다. 서명은 이 본문을 감싸는 `SignedLegalAuthorization`(0x0042, §8.60)이 운반하고, genesis는 이 본문의 객체 해시를 고정한다(§8.54 `legal_authorization_hash`).

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
| 8 | `box_close_root` | `Hash512` | 덮는 프레임에서 받은 `BoxClose` 객체(0x001A) 해시의 정렬 집합 root |
| 9 | `dispute_root` | `Hash512` | 덮는 프레임 기준 미해결 분쟁의 접수 본문(0x000E) 객체 해시의 정렬 집합 root |
| 10 | `genesis_hash` | `Hash512` | 결속된 genesis의 §4 해시 |
| 11 | `time_bucket` | `u64` | 증인이 증언하는 시각 구간: genesis의 `election_epoch_day`(유닉스 기원 이후의 날 수) 00:00 UTC부터의 15분 구간 번호. 증인은 자기 시계의 구간 `now`에 대해 `now − 1 ≤ time_bucket ≤ now`이고 직전 서명 이상일 때만 서명하며, 사슬에서 줄지 않는다(PROTOCOL §5.4, VC-012) |

### 8.4 `SignedCheckpoint` (`schema_id` 0x0010, `schema_version` 1)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<4096>` | 인코딩된 `CheckpointBody` 객체 전체(§3 헤더 포함). 디코더는 이 바이트를 §8.3 규칙으로 다시 디코딩해 거부 규칙을 적용한다 |
| 2 | `signatures` | `Array<{witness_id: Ident<64>, signature: [u8; 4691]}, 64>` | `witness_id` 바이트 오름차순, 중복 없음. 순서 위반은 `NotSorted`, 중복은 `Duplicate`. 각 `signature`는 `body` 바이트에 대한 purpose `checkpoint`의 하이브리드 서명(PROTOCOL.md §3.1) |

정족수·다양성·명부 검사는 인코딩 규칙이 아니라 `ityv-ledger`의 정책 검사다(ADR-0016 §6).

### 8.5 `WitnessMemory` (`schema_id` 0x0011, `schema_version` 2)

증인 도구의 내부 상태다. 장부에 수록되지 않으며 공개하지 않는다. 헤더의 magic·schema·version·길이 검사로 손상된 파일을 거부한다.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `last_seq` | `u64` | 마지막으로 서명한 `checkpoint_seq`. 0이면 아직 서명한 적 없음 |
| 2 | `tree_size` | `u64` | `<= 2^40`. 위반 시 `ValueOutOfRange` |
| 3 | `root_hash` | `Hash512` | 마지막 서명 본문의 `root_hash` |
| 4 | `body_hash` | `Hash512` | 마지막 서명 본문 바이트의 §4 해시 |
| 5 | `ids_hash` | `Hash512` | `election_id ‖ ledger_id ‖ keyset_id`(세 `Ident<64>` 필드의 정규 인코딩)의 §4 해시 |
| 6 | `time_bucket` | `u64` | 마지막 서명 본문의 `time_bucket`. 다음 서명은 이 값 이상이어야 한다 |

`last_seq == 0`이면 2–6은 전부 0이어야 하며 그 외는 `InvariantViolation`(`last_seq` 필드 오프셋 16). 객체 전체 길이는 헤더 포함 232바이트로 고정이다. 버전 1(224바이트, 6번 필드 없음)은 버전 2에서 정상 입력이 아니므로 번호를 올렸다(§3, ADR-0028).

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
| 12 | `spoil_envelope_count` | `u64` | 폐기·격리 봉투 실물 수(사무원 2인이 센다). 기대값 `challenge_count + quarantine_count`(VC-038) |
| 13 | `record_set_root` | `Hash512` | 기록 해시 정렬 집합의 root |
| 14 | `journal_head` | `Hash512` | |
| 15 | `seal_digest` | `Hash512` | |
| 16 | `module_counters` | `Array<{module_id: Ident<64>, final_counter: u64}, 7>` | 오름차순, 중복 없음 |
| 17 | `open_batches` | `u8` | |
| 18 | `time_bucket` | `u64` | 마감 구간. 늦은 마감 기한(24시간, 96구간)은 이 값부터 센다 |

네 필드(9–12)가 더해져 본문이 32바이트 늘지만 `BoxClose.body`의 상한(`Bytes<1024>`) 안이다. 수량 규칙(`visit_count ≤ record_count ≤ 8·visit_count`, 관외·재외 함의 `paper_count` 0과 `sticker_count == visit_count`)은 PROTOCOL §10.2가 정하며 디코더가 아니라 마감 검사와 검증기가 확인한다.

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

`AttestChallenge` (`schema_id` 0x0105): `election_id: Ident<64>` ‖ `observer_id: Ident<64>` ‖ `nonce: [u8; 32]` ‖ `challenge_sig: [u8; 64]`(참관인 확인 키의 Ed25519 서명, purpose `attest-challenge`. 서명 대상은 `election_id: Ident<64>` ‖ `station_id: Ident<64>` ‖ `observer_id: Ident<64>` ‖ `nonce: [u8; 32]`의 정규 인코딩을 헤더 없이 이어 붙인 바이트열이며(§4 헤더 없는 필드 묶음) `station_id`는 커밋먼트 유닛이 자기 설정에서 채운다). 참관인 토큰도 같은 네 값을 넘기며 경로만 다르다(§8.28 `path`). 해석 유닛은 확인 카드의 QR만 이 객체로 옮기며 다른 필드를 만들 수 없다. 커밋먼트 유닛은 `observer_id`가 genesis의 자기 투표소 참관인 토큰 목록에 없거나, 서명이 틀리거나, 열린 방문이 있거나(마지막 `VisitEnd` 뒤 받은 `Interpretation`이 있거나 대기 구역에 투표지가 있음), 직전 증명 뒤 30초가 지나지 않았으면 이 객체를 버리고 투표 상태를 바꾸지 않는다(PROTOCOL §7.9, VC-088).

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

- `device_class`: 1 해석 유닛, 2 커밋먼트 유닛·스캐너 바깥 포트, 3 카운터·가명 유닛, 4 챔버 모듈, 5 선거일 신원 확인 단말, 6 사전투표 신원 확인 단말, 7 투표소 게이트웨이, 8 관찰 탭, 9 장부 수집 서버, 10 공개원장 공표 서버, 11 증인, 12 신뢰기관 수신 시스템, 13 수령 라벨 판독기, 14 각인 판독기, 15 프린터류(각인기·슬립·라벨). 그 외 값은 `ValueOutOfRange`.
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

디코더 규칙: `count`가 65,536을 넘으면 `ValueOutOfRange`(`count` 위치), `pseudonyms` 개수와 다르면 `InvariantViolation`(배열 개수 위치), 앞 가명보다 작은 가명은 `NotSorted`(그 가명 위치). `module_sigs`는 4개 이하(`CountExceedsMax`)이고 같은 `module_id`가 두 번 나오면 `Duplicate`. 개수(genesis 정당 수 n)와 순서(챔버 코드 순, 각각 서명한 카운터·가명 유닛의 정당 모듈)는 genesis가 있어야 알 수 있어 검증기가 확인한다(PROTOCOL §14 6항). `counter_sig`의 키는 그 투표소의 카운터·가명 유닛(사용 중 또는 예비) 키이고, 집합을 실은 프레임에 시행 중인 상태까지의 어느 genesis 상태의 키든 된다.

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
| 3 | `device_class` | `u8` | §8.26의 값(1–10). 커밋먼트 유닛은 2 |
| 4 | `challenge` | `{path: u8, observer_id: Ident<64>, nonce: [u8; 32], challenge_sig: [u8; 64]}` | `path` 1 토큰, 2 확인 카드(그 밖은 거부) |
| 5 | `time_bucket` | `u64` | |
| 6 | `boot_count` | `u32` | OTP 부팅 횟수 |
| 7 | `components` | `Array<{component_id: Ident<64>, version: Ident<32>, build: u64, image_hash: Hash512}, 16>` | 부팅 때 잰 값, 1개 이상, `component_id` 바이트 순(중복 없음) |
| 8 | `bundle_hash` | `Hash512` | 7에서 §8.26 규칙으로 계산 |
| 9 | `modules` | `Array<{module_id: Ident<64>, build: u64, image_hash: Hash512, boot_count: u32, sig: [u8; 4691]}, 7>` | 챔버 모듈마다 같은 `challenge`와 `device_id`에 대해 모듈 증명 키로 하이브리드 서명한 진술(purpose `module-attestation`), 챔버 코드 순, 같은 모듈 두 번 없음. 모듈이 없는 장치는 0개. 서명 대상은 `device_id: Ident<64>` ‖ `challenge`(4번 필드의 인코딩) ‖ `module_id: Ident<64>` ‖ `build: u64` ‖ `image_hash: Hash512` ‖ `boot_count: u32`의 정규 인코딩을 헤더 없이 이어 붙인 바이트열이다(§4) |

투표에 관한 값(기록 수, 선택, 투함 ID, 가명, 저널 head)은 담지 않는다. 디코더는 `bundle_hash`를 다시 계산하지 않는다(해시는 암호 크레이트의 일이다). 검증기가 7번에서 다시 계산해 대조한다. 가장 큰 본문(64바이트 식별자, 구성 요소 16, 모듈 7)은 헤더 포함 37,063바이트다.

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
| 7 | `body_hash` | `Hash512` | 같은 증명의 `DeviceAttestationBody` 해시(나중에 공개원장 이벤트와 대조) |
| 8 | `summary_sig` | `[u8; 64]` | 증명 키의 Ed25519 부분 서명, purpose `attest-summary`. 서명 대상은 1–7번 필드의 정규 인코딩을 헤더 없이 이어 붙인 바이트열(§4) |

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

디코더 규칙: `chamber`가 1–7 밖이면 `ValueOutOfRange`, `member_count`가 1–8 밖이면 `ValueOutOfRange`. `prf_key_check`가 있으면 챔버가 정당 챔버(1–4)이고 `se_present`가 1이어야 한다(아니면 `InvariantViolation`, 존재 태그 위치). 그 모듈이 정말 카운터·가명 유닛의 정당 모듈인지는 genesis가 정하므로 검증기가 확인한다. `signatures`의 `actor_id`: 위원회는 예약 ID `committee`(genesis 본문의 위원회 키), 챔버 구성원은 그 챔버 `TrusteeEntry`의 `trustee_id`, 참관인은 명부(그 프레임에 시행 중인 상태까지)의 참관인 `signer_id`. 서명자는 위원회, 그 모듈 챔버의 구성원 1명 이상, 서로 다른 조직의 참관인 2명 이상이며, 서명자들의 키는 어느 반쪽도 같지 않다(VC-098). 검증기는 또 genesis 모듈 항목의 `provisioned_hash`가 이 객체의 해시이고, `chamber`가 그 항목의 챔버, `device_id`가 이 기록을 고정하면서 이 모듈을 목록에 둔 가장 이른 상태의 장치(투표함 `box_id` 또는 카운터·가명 유닛 `unit_id`; 어느 장치 목록에도 없는 예비 모듈이면 어느 genesis 상태의 투표함이나 카운터·가명 유닛), `member_count`가 genesis `chambers`의 그 챔버 `members`, `entropy_commitment`가 0이 아님(VC-095)을 확인한다.

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

디코더 규칙: `chamber`가 1–4 밖이면 `ValueOutOfRange`. `share_threshold`는 1 이상(0이면 `ValueOutOfRange`, 그 위치), `share_threshold ≤ share_count ≤ 8`을 어기면 `ValueOutOfRange`(`share_count` 위치). `share_holders` 개수가 `share_count`와 다르면 `InvariantViolation`, `trustee_id`가 오름차순이 아니면 `NotSorted`/`Duplicate`. 검증기 규칙: 챔버가 genesis 정당의 챔버이고, 몫 보관자가 모두 그 정당 챔버의 구성원이며 `hsm_model`이 서로 다르다(§6.4 2항 "구성원마다 서로 다른 제품"). 서명자는 위원회(`committee`), 모든 몫 보관자, 서로 다른 조직의 참관인 2명 이상이다(몫을 HSM에 받은 사람은 그 자리에 있었으므로). 같은 정당의 두 번째 유효 절차가 다른 필드를 가지면 충돌이다.

### 8.33–8.43 사람이 서명하는 이벤트와 genesis 항목 (M5 1단계, ADR-0025)

> English summary: the human-signed ledger events get canonical bodies (0x0008, 0x000E, 0x000F, 0x0029–0x002E) and one common envelope, `WitnessedEvent` (0x0028), that carries the body object bytes and role-tagged hybrid signatures; every signature covers exactly the body bytes under the body's purpose. The decoder enforces each body's rules and the signer roles each body needs; `ityv-state` binds every signature to a verification token from the key the genesis registers. Three genesis entry types (`GenesisBox`, `CustodyRoute`, `RosterSigner`) fix the encoding of the expected boxes, custody routes and the signer roster; since ADR-0028 they are objects of their own in the genesis entry sets (§8.54).

모든 본문은 `election_id: Ident<64>`가 첫 필드이고, 서명은 `WitnessedEvent`(§8.42)가 싣는다. 서명 메시지는 본문 객체 바이트이며 purpose는 본문마다 하나다(아래 표). 수량은 디코더가 서로 비교하지 않는다. 어긋난 수량도 수록되고 `ityv-state`가 보류로 판정한다(PROTOCOL §10.2).

| schema | 본문 | purpose | 서명자(역할) |
|---|---|---|---|
| 0x0008 | `CustodyHandoffBody` | `handoff` | 송신자 1, 수신자 1 |
| 0x000E | `DisputeEventBody` | `dispute` | 선관위 1, 위원회 1 |
| 0x000F | `LegalDecisionRefBody` | `legal-decision` | 결정 기관 1 |
| 0x0029 | `BoxOpenedBody` | `box-open` | 장치 1, 사무원 2 이상, 서로 다른 조직 참관인 2 이상 |
| 0x002A | `FallbackBody` | `fallback` | 사무원 2 이상, 서로 다른 조직 참관인 2 이상 |
| 0x002B | `IssuanceCountBody` | `issuance-count` | 같음 |
| 0x002C | `ImprintAuditBody` | `imprint-audit` | 같음 |
| 0x002D | `SealChangeBody` | `seal-change` | 같음 |
| 0x002E | `LateBatchCloseBody` | `late-batch-close` | 같음 |
| 0x0032 | `ProgressCheckBody` | `progress-check` | 같음 |
| 0x003F | `ObserverCountAttestBody` | `observer-count` | 서로 다른 조직 참관인 2 이상, 그 밖의 역할 없음 |
| 0x0040 | `CheckinUnitSwapBody` | `checkin-swap` | 사무원 2 이상, 서로 다른 조직 참관인 2 이상 |
| 0x0041 | `BoxUnitSwapBody` | `box-swap` | 같음 |
| 0x0046 | `PaperCountReportBody` | `paper-count` | 구·시·군 선관위 위원장 1(그 보고 단위의 `commission_org`, `ityv-state`가 확인), 서로 다른 조직 참관인 2 이상, 그 밖의 역할 없음 |
| 0x000D | `AuditSeedBody` | `audit-seed` | 위원회 1, 서로 다른 조직 참관인 2 이상, 그 밖의 역할 없음(버전 3부터) |
| 0x0048 | `AuditManifestFreezeBody` | `audit-freeze` | 같음 |
| 0x004E | `AuditCommitBody` | `audit-commit` | 같음 |
| 0x004B | `SampleComparisonBody` | `sample-comparison` | 서로 다른 조직 감사인 2 이상, 서로 다른 조직 참관인 2 이상, 그 밖의 역할 없음(버전 3부터) |
| 0x004C | `AuditFindingBody` | `audit-finding` | 같음 |
| 0x004D | `HandCountReportBody` | `hand-count` | 위원장 1(그 보고 단위의 `commission_org`), 서로 다른 조직 참관인 2 이상, 그 밖의 역할 없음(버전 3부터) |
| 0x0052 | `RollSourceExtractBody` | `roll-source` | 명부 출처 기관 1, 그 밖의 역할 없음(버전 4부터) |
| 0x0053 | `RollFreezeBody` | `roll-freeze` | 선관위 1, 위원회 1(버전 4부터) |
| 0x0054 | `RollCustodyReceiptBody` | `roll-receipt` | 명부 보관 기관 1, 그 밖의 역할 없음(버전 4부터) |
| 0x0055 | `RollAmendmentBody` | `roll-amendment` | 선관위 1, 위원회 1, 명부 출처 기관 1(버전 4부터) |

#### 8.33 `CustodyHandoffBody` (0x0008)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | 투표함 또는 용기 |
| 3 | `index` | `u32` | 1부터(`ValueOutOfRange`) |
| 4 | `from_signer` | `Ident<64>` | 송신자 |
| 5 | `from_org` | `Ident<64>` | |
| 6 | `to_signer` | `Ident<64>` | 수신자 |
| 7 | `to_org` | `Ident<64>` | `from_org`와 달라야 함(`InvariantViolation`, VC-040) |
| 8 | `previous_handoff_hash` | `Hash512` | 앞 인계 본문의 객체 해시. `index == 1`이면 0, 아니면 0이 아님(`InvalidPreviousHash`) |
| 9 | `seal_digest` | `Hash512` | 인계 때 봉인 번호 목록의 해시 |
| 10 | `count` | `u64` | 넘긴 투표지 수. 관외·재외 함은 회송 봉투 수 |
| 11 | `time_bucket` | `u64` | |

#### 8.34 `DisputeEventBody` (0x000E)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `action` | `u8` | 1 접수, 2 조사, 3 기술 해결, 4 법적 회부 |
| 3 | `dispute_type` | `u8` | 1–8(PROTOCOL §13). 뒤 이벤트는 접수와 같은 값 |
| 4 | `box_id` | `Option<Ident<64>>` | |
| 5 | `record_hash` | `Option<Hash512>` | `box_id` 없이 있을 수 없음(`InvariantViolation`) |
| 6 | `evidence_hash` | `Hash512` | 원본은 `restricted` |
| 7 | `filing_hash` | `Hash512` | 접수 본문의 객체 해시. 접수(1)일 때만 0(`InvalidPreviousHash`) |
| 8 | `result_hash` | `Hash512` | 처리 결과 문서 해시. 3·4일 때만 0이 아님(`InvariantViolation`) |
| 9 | `time_bucket` | `u64` | |

#### 8.35 `LegalDecisionRefBody` (0x000F)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `authority_id` | `Ident<64>` | 결정 기관 |
| 3 | `decision_doc_hash` | `Hash512` | 결정문 해시 |
| 4 | `dispute_hash` | `Hash512` | 대상 분쟁 접수 본문의 객체 해시. 0이 아님(`InvalidPreviousHash`) |
| 5 | `outcome` | `u8` | 1 인용, 2 일부 인용, 3 기각, 4 각하, 5 기타(결정문 참조) |
| 6 | `tally_effect` | `u8` | 0 집계 영향 없음, 1 그 기록을 포함, 2 그 기록을 `LEGAL_EXCLUDED`로 제외(PROTOCOL §10.6 6항, §11.1) |
| 7 | `decided_day` | `u64` | 결정일 |

#### 8.36 `BoxOpenedBody` (0x0029)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `modules` | `Array<Ident<64>, 7>` | 붙인 챔버 모듈, 오름차순, 중복 없음(2단계 전에는 빈 배열) |
| 4 | `seal_digest` | `Hash512` | 확인한 봉인 번호 목록의 해시 |
| 5 | `seals_match` | `bool` | 봉인 번호가 모두 발급 기록과 같은가 |
| 6 | `initial_count` | `u64` | 개시 때 들어 있던 수(정상이면 0) |
| 7 | `time_bucket` | `u64` | |

봉인 불일치와 0이 아닌 초기 수량은 거부가 아니라 보류로 연다(PROTOCOL §10.1).

#### 8.37 `FallbackBody` (0x002A)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `kind` | `u8` | 1 `FallbackDeclared`, 2 `FallbackEnded` |
| 4 | `reason` | `u8` | 선언: 1 스캐너 고장, 2 전원, 3 모듈 고장, 4 기타(진술). 종료: 0. 이 대응이 아니면 `InvariantViolation` |
| 5 | `statement_hash` | `Hash512` | 참관인 진술 해시 |
| 6 | `markers` | `Option<{first: u64, last: u64}>` | 관외·재외 함의 비상 표지 일련번호 범위, `first ≤ last` |
| 7 | `time_bucket` | `u64` | |

#### 8.38 `IssuanceCountBody` (0x002B)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `stock_received` | `u64` | 받은 투표용지 수(사전 인쇄분 또는 현장 인쇄용 백지) |
| 4 | `issued` | `u64` | 교부 수(재교부 포함) |
| 5 | `voter_spoiled` | `u64` | 유권자가 훼손해 재교부한 수 |
| 6 | `returned` | `u64` | 쓰지 않고 반납한 수 |
| 7 | `unused` | `u64` | 교부하지 않은 수 |
| 8 | `printer_waste` | `u64` | 인쇄 실패로 봉인 보관한 용지 수 |
| 9 | `envelopes` | `Option<{issued: u64, returned_empty: u64}>` | 관외 투표소의 회송용 봉투 교부 수와 빈 봉투 회수 수 |
| 10 | `time_bucket` | `u64` | |

등식(`stock_received = issued + unused + printer_waste` 등)은 `ityv-state`가 판정한다(PROTOCOL §10.2).

#### 8.39 `ImprintAuditBody` (0x002C)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `unimprinted` | `u64` | 각인 없는 투표지 수 |
| 4 | `duplicate_cast_ids` | `u64` | 중복 `cast_id` 수 |
| 5 | `time_bucket` | `u64` | |

#### 8.40 `SealChangeBody` (0x002D)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `reason` | `u8` | 1 훼손 발견 후 재봉인(언제나 보류), 2 참관 점검 뒤 재봉인, 3 용기 교체·합침, 4 법원·선관위 명령에 따른 개봉, 5 기타(진술) |
| 4 | `previous_seal_digest` | `Hash512` | |
| 5 | `new_seal_digest` | `Hash512` | 앞 값과 달라야 함(`InvariantViolation`) |
| 6 | `statement_hash` | `Hash512` | 서명자 진술 해시 |
| 7 | `time_bucket` | `u64` | |

#### 8.41 `LateBatchCloseBody` (0x002E)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `batch_body_hash` | `Hash512` | 닫는 `BatchAttestBody` 객체의 해시. 0이 아님(`InvalidPreviousHash`) |
| 4 | `reason` | `u8` | 1 장치 재기동, 2 전원 복구, 3 모듈 교체, 4 기타(진술) |
| 5 | `time_bucket` | `u64` | 마감 후 96구간 안이어야 받는다(PROTOCOL §7.2.1) |

#### 8.42 `WitnessedEvent` (0x0028)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<2048>` | 위 표의 본문 객체 전체. 다른 스키마는 `SchemaMismatch` |
| 2 | `sigs` | `Array<{signer_id: Ident<64>, role: u8, org_id: Ident<64>, sig: [u8; 4691]}, 8>` | `signer_id` 엄격 오름차순. `role` 1 사무원, 2 참관인, 3 선관위, 4 위원회, 5 송신자, 6 수신자, 7 결정 기관, 8 장치, 9 구·시·군 선관위 위원장(버전 2부터), 10 감사인(버전 3부터), 11 명부 출처 기관, 12 명부 보관 기관(버전 4부터). 그 밖의 코드는 `ValueOutOfRange`. 본문별 역할 조합(위 표)이 아니면 `InvariantViolation` |

`WitnessedEvent`는 버전 4다(ADR-0040). 버전 1에는 역할 9와 본문 0x0046이 없었고, 버전 1의 거부 벡터 `role 9`는 버전 2에서 정상 입력이 되므로 같은 번호를 다시 쓰지 않고 버전을 올렸다(§3, ADR-0028, ADR-0035). 버전 3은 역할 10(감사인)과 감사 본문 여섯(0x000D, 0x0048, 0x004B, 0x004C, 0x004D, 0x004E)을 받는다. 0x004E는 같은 단계(ADR-0036)의 독립 리뷰에서 더했고, 버전 3이 아직 공개 장부에 쓰인 적이 없어 같은 버전에 넣었다. 버전 2의 거부 벡터 `role 10`은 버전 3에서 역할 조합 위반(`InvariantViolation`)이 되므로 다시 버전을 올렸다. 버전 4는 역할 11(명부 출처 기관)·12(명부 보관 기관)와 명부 본문 넷(0x0052–0x0055)을 받는다. 버전 3의 거부 벡터 `role 11`이 같은 이유로 바뀌었다(지금의 거부 벡터는 `role 13`). 디코더는 현재 버전만 받는다. 본문 안의 오류는 봉투 안 위치로 옮겨 보고한다(§8.20). 서명 바이트의 유효성, 등록된 키와의 결속, 서명자 사이 키 반쪽 중복 금지(VC-098)는 `ityv-state`가 검증 토큰으로 확인한다.

#### 8.43 genesis 항목 `GenesisBox`(0x0035), `CustodyRoute`(0x0039), `RosterSigner`(0x003A)

M5 1단계에서는 필드형이었고 ADR-0028에서 각자 객체가 되었다. 집합에 넣는 방식은 §8.54를 따른다.

`GenesisBox`(`expected_boxes[]`, 열쇠 `box_id`): `box_id: Ident<64>` ‖ `station_id: Ident<64>` ‖ `ballot_style_id: Ident<64>` ‖ `profile: u8`(1 투표소, 2 관외·재외, 3 수령 스캐너) ‖ `route_id: Ident<64>` ‖ `reporting_unit_id: Ident<64>` ‖ `device_key: [u8; 2624]`(하이브리드 공개키, ML-DSA-87 2592 ‖ Ed25519 32) ‖ `attest_key: [u8; 2624]`(증명 키, PROTOCOL §7.9) ‖ `modules: Array<Ident<64>, 7>`(오름차순).

`CustodyRoute`(`custody_routes[]`, 열쇠 `route_id`): `route_id: Ident<64>` ‖ `count_at_origin: bool` ‖ `stops: Array<Ident<64>, 8>`(조직 순서, 2개 이상, 이웃한 두 조직이 같으면 `InvariantViolation`).

`RosterSigner`(서명자 명부, 열쇠 `signer_id`, 버전 3): `signer_id: Ident<64>` ‖ `role: u8`(1 사무원, 2 참관인, 3 보관 담당자, 4 법정 권한 기관, 5 구·시·군 선관위 위원장, 6 감사인. 버전 1에는 5가, 버전 2에는 6이 없었다, ADR-0036) ‖ `org_id: Ident<64>` ‖ `station_id: Option<Ident<64>>` ‖ `key: [u8; 2624]` ‖ `appointment_hash: Hash512`(0이 아님, VC-009).

시험 벡터는 `crates/ityv-encoding/vectors/`의 `custody_handoff_body.txt`, `dispute_event_body.txt`, `legal_decision_ref_body.txt`, `box_opened_body.txt`, `fallback_body.txt`, `issuance_count_body.txt`, `imprint_audit_body.txt`, `seal_change_body.txt`, `late_batch_close_body.txt`, `witnessed_event.txt`다.

### 8.44–8.48 투표 진행 기록 (ADR-0027)

> English summary: per-slot progress ticks from the commitment unit (`BoxProgressBody`) and the check-in unit (`CheckinProgressBody`), each carried in a `ProgressTick` with the device's hybrid signature; the on-site check after an alarm (`ProgressCheckBody`, in a `WitnessedEvent`); and the per-station alarm limit fixed in genesis (`StationProgressPolicy`). Ticks carry cumulative station- or box-level totals only.

진행 기록 본문에는 아래 필드 말고 아무것도 없다. 특히 투표양식별 내역, 기록 해시, 가명, 순번, 저널 head, `time_bucket`이 없다(PROTOCOL §7.10 2항, VC-102). 누계끼리의 비교와 경보는 디코더가 아니라 `ityv-state`와 검증기가 한다.

#### 8.44 `BoxProgressBody` (0x002F)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | |
| 3 | `slot` | `u64` | 선거 epoch 기준 10분 슬롯 번호(ADR-0022) |
| 4 | `sheets_in` | `u64` | 기록 + 검증 폐기 + 격리 누계 |
| 5 | `state` | `u8` | 1 투입 중, 2 비상 투입 중, 3 마감. 그 밖은 `InvariantViolation` |

#### 8.45 `CheckinProgressBody` (0x0030)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `unit_id` | `Ident<64>` | 카운터·가명 유닛 ID(예비 유닛이면 예비 ID) |
| 4 | `slot` | `u64` | |
| 5 | `checkins` | `u64` | 본인 확인 인원 누계 |
| 6 | `issued` | `u64` | 교부 장수 누계(재교부 포함) |
| 7 | `spoiled` | `u64` | 훼손 회수 장수 누계. `spoiled ≤ issued` |
| 8 | `returned` | `u64` | 반납 장수 누계. `spoiled + returned ≤ issued`(넘으면 `InvariantViolation`) |
| 9 | `state` | `u8` | 1 확인 중, 2 교체 뒤, 3 마감 |

#### 8.46 `ProgressTick` (0x0031)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<512>` | `BoxProgressBody` 또는 `CheckinProgressBody` 객체 전체. 다른 스키마는 `SchemaMismatch` |
| 2 | `sig` | `[u8; 4691]` | 장치 하이브리드 서명. 메시지는 본문 객체 바이트, purpose는 `BoxProgressBody`면 `box-progress`, `CheckinProgressBody`면 `checkin-progress` |

서명 키와 장치의 결속(커밋먼트 유닛은 genesis `GenesisBox.device_key`, 카운터·가명 유닛은 genesis `stations[]`의 유닛 공개키)은 `ityv-state`가 검증 토큰으로 확인한다.

#### 8.47 `ProgressCheckBody` (0x0032)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `alarm_slot` | `u64` | 경보가 성립한 슬롯 |
| 4 | `alarm` | `u8` | 1 음수, 2 과다, 3 바닥 |
| 5 | `holding` | `u64` | 투표지를 든 사람 수(기표소 안과 대기 줄) |
| 6 | `finding` | `u8` | 1 현장 인원으로 설명됨, 2 반출 확인, 3 입력 누락 정정, 4 설명 안 됨 |
| 7 | `carried_out` | `u64` | 판정 2면 1 이상, 그 밖에는 0(어기면 `InvariantViolation`) |
| 8 | `statement_hash` | `Hash512` | 서명자 진술 해시 |
| 9 | `time_bucket` | `u64` | |

#### 8.48 `StationProgressPolicy` (0x0037, genesis `progress_policies[]`)

`station_id: Ident<64>` ‖ `booth_count: u16`(1 이상) ‖ `limit_sheets: u32`(1 이상). 열쇠는 `station_id`이고 투표소마다 하나다. 기본값은 `limit_sheets = booth_count × 2 × 한 방문의 최대 장수`이고, 다른 값이면 위원회가 사유를 genesis 근거 문서에 적는다.

시험 벡터는 `crates/ityv-encoding/vectors/`의 `box_progress_body.txt`, `checkin_progress_body.txt`, `progress_tick.txt`, `progress_check_body.txt`다. `unit_id`의 형은 `UnitId`(`Ident<64>`)다.

### 8.49–8.59 genesis와 투표소 사건 (ADR-0028)

> English summary: the genesis is a bounded body (`GenesisBody`, 0x0002 version 8) with the scalar fields, pins, the two authority keys, the witness quorum, the roll's custody quorum, the party roster and chamber thresholds, and the count and Merkle root of thirteen entry sets (version 6 had eleven; the twelfth, the timestamp authorities, is §8.74; the thirteenth, the roll's authorities, and the custody quorum came with version 8, §8.76). Each entry is its own object (0x0035–0x003E, 0x0050, 0x0051); a set is strictly ascending by the entry key, its leaves are the entries' object hashes, and its root is the RFC 9162-shaped SHA3-512 root. `SignedGenesis` (0x0033) carries the body with the commission's, the committee's and at least `q` witness signatures; `GenesisAmendmentBody` (0x0034) replaces the eight amendable set commitments. Three witnessed station events: `ObserverCountAttestBody` (0x003F), `CheckinUnitSwapBody` (0x0040), `BoxUnitSwapBody` (0x0041).

#### 8.49 `StationEntry` (0x0036, genesis `stations[]`, 열쇠 `station_id`)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `station_id` | `Ident<64>` | |
| 2 | `kind` | `u8` | 1 선거일 투표소, 2 사전투표소, 3 수령 선관위. 그 밖은 `ValueOutOfRange` |
| 3 | `primary` | 유닛 | 사용 중인 카운터·가명 유닛 |
| 4 | `spare` | 유닛 | 봉인된 예비 유닛. `unit_id`가 `primary`와 같거나 `key`가 반쪽 하나라도 같으면 `InvariantViolation`(위치는 이 필드) |
| 5 | `boxes` | `Array<Ident<64>, 8>` | 이 투표소의 모든 투표함, 1개 이상(0이면 `InvariantViolation`), 엄격 오름차순 |
| 6 | `id_terminals_hash` | `Hash512` | 신원 확인 단말 목록 문서 해시(단말은 TCB 밖이며 등록 키가 없다) |
| 7 | `tokens` | `Array<{observer_id: Ident<64>, org_id: Ident<64>, check_key: [u8; 32]}, 16>` | 참관인 토큰과 Ed25519 확인 키, `observer_id` 엄격 오름차순 |

유닛 = `unit_id: Ident<64>` ‖ `key: [u8; 2624]` ‖ `attest_key: [u8; 2624]` ‖ `modules: Array<Ident<64>, 7>`(그 유닛에 꽂힌 정당 모듈, 오름차순).

#### 8.50 `ReportingUnitEntry` (0x0038, 열쇠 `unit_id`)

버전 2(ADR-0035): `unit_id: Ident<64>` ‖ `box_count: u32`(1 이상, 0이면 `ValueOutOfRange`) ‖ `commission_org: Ident<64>`(그 단위의 종이 개표를 보고하는 구·시·군 선관위. 그 조직의 명부 위원장만 단위의 `PaperCountReport`에 서명한다, PROTOCOL §11.5). 투표함은 `GenesisBox.reporting_unit_id`로 자기 단위를 가리키고, 단위는 그런 투표함의 수를 적는다. 버전 1에는 `commission_org`가 없었다.

#### 8.51 `ModuleEntry` (0x003B, 열쇠 `module_id`)

`module_id: Ident<64>` ‖ `chamber: u8`(1–4 `P1`–`P4`, 5 `J`, 6 `A`, 7 `C`. `N`(8)은 모듈이 없어 `ValueOutOfRange`) ‖ `key: [u8; 2624]`(배치 서명, Ed25519 반쪽은 기록 서명) ‖ `attest_key: [u8; 2624]` ‖ `provisioned_hash: Hash512`(`ModuleProvisioned` 객체 해시, 0이 아님).

#### 8.52 `BallotStyleEntry` (0x003C, 열쇠 `ballot_style_id`)

`ballot_style_id: Ident<64>` ‖ `choices: u16` ‖ `chunks: u8` ‖ `layout_hash: Hash512`. `1 ≤ choices ≤ 70`(벗어나면 `ValueOutOfRange`), `chunks = ⌈(choices + 2)/9⌉`(다르면 `InvariantViolation`, PROTOCOL §7.4).

#### 8.53 `TrusteeEntry` (0x003D), `WitnessRosterEntry` (0x003E)

`TrusteeEntry`(열쇠 `trustee_id`): `trustee_id: Ident<64>` ‖ `chamber: u8`(1–8) ‖ `org_id: Ident<64>` ‖ `key: [u8; 2624]` ‖ `appointment_hash: Hash512`(0이 아님).

`WitnessRosterEntry`(열쇠 `witness_id`): `witness_id: Ident<64>` ‖ `org_id: Ident<64>` ‖ `provider: Ident<64>` ‖ `region: Ident<64>` ‖ `key: [u8; 2624]`(purpose `checkpoint`, `genesis`, `genesis-amendment`) ‖ `appointment_hash: Hash512`(0이 아님).

#### 8.54 `GenesisBody` (0x0002, 버전 8)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `election_epoch_day` | `u64` | 유닉스 기원(1970-01-01 UTC) 이후의 날 수. 모든 `time_bucket`은 이 날 00:00 UTC부터의 15분 구간 번호다 |
| 3 | `policy_hash` | `Hash512` | 0이 아님(`InvalidPreviousHash`) |
| 4 | `proof_system_id` | `Ident<64>` | |
| 5 | `legal_authorization_hash` | `Hash512` | `LegalAuthorizationBody` 객체 해시, 0이 아님 |
| 6 | `connectivity_manifest_hash` | `Hash512` | 0이 아님 |
| 7 | `release_manifest_hash` | `Hash512` | 0이 아님 |
| 8 | `commission_key` | `[u8; 2624]` | 선관위 하이브리드 공개키 |
| 9 | `committee_key` | `[u8; 2624]` | 위원회 하이브리드 공개키. 선관위 키와 반쪽 하나라도 같으면 `InvariantViolation` |
| 10 | `quorum` | `u8` × 6 | `n`, `q`, `f`, 조직·공급자·지역 하한. `13 ≤ n ≤ 64`, `9 ≤ q ≤ n`, `2q − n > f`, 하한은 7·4·3 이상 `q` 이하(아니면 `ValueOutOfRange`) |
| 10a | `custody_quorum` | `u8` | 명부 상태 하나에 같은 값을 확인해야 하는 서로 다른 보관 기관의 수, 3 이상(아니면 `ValueOutOfRange`, ADR-0033 2항, 개정안 14 제44조의3 ④의 하한). 수는 하위 규정이 정한다. 버전 8부터 |
| 11 | `parties` | `Array<{chamber: u8, name: Bytes<128>, seats: u16, evidence_hash: Hash512}, 4>` | 2–4개(1개 이하 `InvariantViolation`), i번째의 `chamber`는 `P(i+1)`, 이름은 비지 않은 UTF-8(아니면 `ValueOutOfRange`), 의석 내림차순(어기면 `InvariantViolation`, VC-067), `evidence_hash` 0이 아님 |
| 12 | `chambers` | `Array<{chamber: u8, threshold: u8, members: u8}, 8>` | 정확히 `P1`…`Pn`, `J`, `A`, `C`, `N` 순서, `1 ≤ threshold ≤ members`(어기면 `InvariantViolation`). `members`가 8을 넘는 genesis는 검증기가 받지 않는다(임계 분산의 용량, `Rule::ChamberSize`, ADR-0035) |
| 13 | `sets` | `{count: u64, root: Hash512}` × 13 | 아래 집합 순서. 증인 집합의 `count`가 `n`과 다르면 `InvariantViolation` |

집합 순서: 1 투표함(`GenesisBox`), 2 투표소(`StationEntry`), 3 진행 경보 기준(`StationProgressPolicy`), 4 보고 단위(`ReportingUnitEntry`), 5 보관 경로(`CustodyRoute`), 6 서명자 명부(`RosterSigner`), 7 챔버 모듈(`ModuleEntry`), 8 임명 해시, 9 투표양식(`BallotStyleEntry`), 10 신뢰기관(`TrusteeEntry`), 11 증인(`WitnessRosterEntry`), 12 시점확인 기관(`TimestampAuthorityEntry`, §8.74), 13 명부 기관(`RollAuthorityEntry`, §8.76). 1–8은 변경할 수 있고 9–13은 선거 동안 고정이다. 버전 6에는 집합 12가, 버전 7에는 집합 13과 `custody_quorum`이 없었다(ADR-0039, ADR-0040).

집합의 리프 입력은 항목 객체의 §4 객체 해시이고, 항목은 열쇠 바이트 엄격 오름차순이다. 임명 집합은 해시 자체를 바이트 오름차순으로 둔다. root는 PROTOCOL §5.3의 트리 root(리프 접두 0x00, 노드 접두 0x01, 빈 집합은 빈 트리의 root)다. genesis 핀은 이 본문 객체의 객체 해시다.

#### 8.55 `GenesisAmendmentBody` (0x0034)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `seq` | `u64` | 1 이상(0이면 `ValueOutOfRange`) |
| 3 | `previous_hash` | `Hash512` | 1번이면 genesis 핀, 그 뒤는 직전 변경 본문의 객체 해시. 0이 아님 |
| 4 | `reason` | `u8` | 1 장치 교체, 2 명부 변경, 3 릴리스 변경, 4 기타 |
| 5 | `reason_hash` | `Hash512` | 공표한 사유 문서 해시, 0이 아님 |
| 6 | `time_bucket` | `u64` | 시행 구간 |
| 7 | `release_manifest_hash` | `Hash512` | 이후 적용할 릴리스 목록, 0이 아님 |
| 8 | `sets` | `{count: u64, root: Hash512}` × 8 | 집합 1–8의 새 값(바뀌지 않는 집합도 다시 적는다) |

#### 8.56 `SignedGenesis` (0x0033)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<16384>` | `GenesisBody`(버전 8) 또는 `GenesisAmendmentBody` 객체 전체. 다른 스키마는 `SchemaMismatch` |
| 2 | `commission_sig` | `[u8; 4691]` | |
| 3 | `committee_sig` | `[u8; 4691]` | |
| 4 | `witness_sigs` | `Array<{witness_id: Ident<64>, sig: [u8; 4691]}, 64>` | `witness_id` 엄격 오름차순. genesis면 본문의 `q` 이상, 변경이면 9 이상(모자라면 `InvariantViolation`, 위치는 개수 필드) |

모든 서명의 메시지는 `body` 바이트이고 purpose는 genesis면 `genesis`, 변경이면 `genesis-amendment`다. 서명 바이트의 유효성, 증인 항목과의 결속, 정족수(변경은 genesis의 `q`)와 다양성, 서명자 사이 키 반쪽 중복 금지는 `ityv-state`의 `genesis` 모듈이 검증 토큰으로 확인한다.

#### 8.57 `ObserverCountAttestBody` (0x003F)

`election_id: Ident<64>` ‖ `station_id: Ident<64>` ‖ `unit_id: Ident<64>` ‖ `count: u64`(확인 인원 누계 = 마지막 순번) ‖ `kind: u8`(1 정기, 2 마감. 그 밖은 `ValueOutOfRange`) ‖ `time_bucket: u64`.

#### 8.58 `CheckinUnitSwapBody` (0x0040)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `failed_unit` | `Ident<64>` | |
| 4 | `spare_unit` | `Ident<64>` | `failed_unit`과 같으면 `InvariantViolation` |
| 5 | `at_slot` | `u64` | 예비 유닛이 진행 기록을 시작하는 슬롯 |
| 6 | `confirmed` | `bool` | 고장 유닛의 마지막 값을 확인했는지 |
| 7 | `next_seq` | `u64` | 예비 유닛의 첫 순번, 1 이상(0이면 `ValueOutOfRange`) |
| 8 | `issued` | `u64` | |
| 9 | `spoiled` | `u64` | |
| 10 | `returned` | `u64` | 확인하지 못했으면 8–10이 모두 0(아니면 `InvariantViolation`, 위치는 8) |

예비 유닛이 이어 세는 진행 기록 누계는 `[next_seq − 1, issued, spoiled, returned]`다.

#### 8.59 `BoxUnitSwapBody` (0x0041)

`election_id: Ident<64>` ‖ `box_id: Ident<64>` ‖ `at_slot: u64` ‖ `confirmed: bool` ‖ `sheets_in: u64`(확인하지 못했으면 0, 아니면 `InvariantViolation`). 예비 커밋먼트 유닛의 키는 이 사건이 아니라 `GenesisAmendment`가 등록한다.

### 8.60 `SignedLegalAuthorization` (0x0042, ADR-0030)

> English summary: the ledger object that carries the legal authorization: the `LegalAuthorizationBody` object bytes (at most 512) with the commission's and the committee's hybrid signatures under purpose `legal-auth`. The genesis pins the body's object hash; the verifier accepts only the pinned body and verifies both signatures under the two keys the genesis body registers.

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<512>` | `LegalAuthorizationBody`(§8.2) 객체 전체. 다른 스키마는 `SchemaMismatch`, 본문이 정규가 아니면 그 오류 |
| 2 | `commission_sig` | `[u8; 4691]` | 선관위 하이브리드 서명 |
| 3 | `committee_sig` | `[u8; 4691]` | 독립검증위원회 하이브리드 서명 |

두 서명의 메시지는 `body` 바이트이고 purpose는 `legal-auth`다. 서명 바이트의 유효성, genesis의 두 기관 키와의 결속, 본문이 genesis가 고정한 것인지, 범위 전제 규칙(PROTOCOL §4.4)은 `ityv-verify`의 `authorize_ledger`가 검증 토큰을 만들어 `ityv-state`의 `authorize`로 확인한다.

### 8.61–8.65 집계 (ADR-0035)

> English summary: the tally's ledger objects. `TallyScopeBody` (0x0043) fixes, per ballot style and reporting unit, the included records' count and sorted-set root, the ballots cast without a record, and every excluded record with the first reason of PROTOCOL §11.1 and the object hash of the event that gives it. `AggregateOpeningBody` (0x0044) opens one chunk of a scope's sum (`T_j`, `R_j`, `S`). `ReceiptResolutionBody` (0x0047) gives each cast record of one out-of-district box its receipt outcome. `QuorumSigned` (0x0045) carries any of the three with the participating trustees' hybrid signatures over the quorum message `body_hash ‖ trustees`, so the list of participants is signed. `PaperCountReportBody` (0x0046) is a `WitnessedEvent` body: the paper votes per candidate and the invalid ballots of one unit, signed by the chair of the unit's district commission and observers of two organisations. Counts are at most `2^26 − 1`. The encoding checks form only; `ityv-state` and `ityv-verify` check the quorum, the chair's unit, the scope against the ledger, the opening against the commitments and the paper against the opened counts (PROTOCOL §14 7).

수량(`included_count`, `no_record_count`, 득표, 무효 수)은 `2^26 − 1` 이하다(넘으면 `ValueOutOfRange`). 26비트 자릿수에서 자리올림이 없게 하는 상한이다(PROTOCOL §7.4).

#### 8.61 `TallyScopeBody` (0x0043)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `reporting_unit_id` | `Ident<64>` | genesis `reporting_units[]` |
| 4 | `included_count` | `u64` | 포함 기록 수 |
| 5 | `included_root` | `Hash512` | 포함 기록 추적코드의 정렬 집합 root(마감의 `record_set_root`와 같은 계산) |
| 6 | `no_record_count` | `u64` | 그 단위 투표함 마감의 `no_record_count` 합 |
| 7 | `exclusions` | `Array<{record_hash: Hash512, reason: u8, basis: Hash512}, 65536>` | `record_hash` 엄격 오름차순(`NotSorted`, `Duplicate`). `reason` 1 `TEST_BALLOT`, 2 `CHALLENGED_SPOILED`, 3 `QUARANTINED`, 4 `CAST_NOT_RECEIVED`, 5 `RECEIVED_LATE`, 6 `LEGAL_EXCLUDED`, 7 `SHARE_MISSING`, 8 `UNATTESTED`(§11.1 순서, 그 밖은 `ValueOutOfRange`). `basis`는 사유를 주는 장부 이벤트의 객체 해시, 0이 아님(`InvalidPreviousHash`) |
| 8 | `time_bucket` | `u64` | 정족수가 적은 시각. 늦은 마감 기한은 이것이 아니라 증인 체크포인트의 시각으로 잰다(PROTOCOL §11.1) |

#### 8.62 `AggregateOpeningBody` (0x0044)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `reporting_unit_id` | `Ident<64>` | |
| 4 | `scope_hash` | `Hash512` | 여는 `TallyScopeBody` 객체의 해시. 0이 아님(`InvalidPreviousHash`) |
| 5 | `chunk` | `u8` | 8 미만(`ValueOutOfRange`) |
| 6 | `packed_sum` | `Scalar` | `T_j` |
| 7 | `rand_sum` | `Scalar` | `R_j` |
| 8 | `id_sum` | `Scalar` | `S` |
| 9 | `time_bucket` | `u64` | |

스칼라의 canonical 여부는 `ityv-crypto`가 확인한다(§2).

#### 8.63 `QuorumSigned` (0x0045)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `body` | `Bytes<8454456>` | `TallyScopeBody`, `AggregateOpeningBody`, `ReceiptResolutionBody`, `SampleOpeningRefBody`(버전 2부터) 객체 전체. 다른 스키마는 `SchemaMismatch`, 본문 오류는 봉투 위치로 옮긴다 |
| 2 | `sigs` | `Array<{trustee_id: Ident<64>, sig: [u8; 4691]}, 64>` | 1개 이상(0이면 `InvariantViolation`), `trustee_id` 엄격 오름차순 |

purpose는 본문에 따라 `tally-scope`, `aggregate-opening`, `receipt-resolution`, `sample-opening`이다. `QuorumSigned`는 버전 2다(ADR-0036): 버전 1은 `SampleOpeningRefBody`를 `SchemaMismatch`로 거부했다. 서명 메시지는 본문 바이트가 아니라 **정족수 메시지**다: `body_hash: Hash512`(본문 객체의 §4 해시) ‖ `trustees: Array<Ident<64>, 64>`(봉투의 `trustee_id`를 같은 순서로). 메시지 길이는 최대 4,420바이트다. 참여 구성원 목록이 서명 안에 있으므로 누구도 본문을 다른 참여자 목록으로 다시 싸지 못한다. 서명자가 genesis 신뢰기관이고 등록된 키로 서명했으며 접근구조 Γ의 자격 집합인지는 `ityv-state`의 `check_quorum`이 확인한다.

#### 8.64 `PaperCountReportBody` (0x0046)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `reporting_unit_id` | `Ident<64>` | |
| 3 | `ballot_style_id` | `Ident<64>` | |
| 4 | `votes` | `Array<u64, 70>` | 후보 1부터의 종이 득표. 1개 이상(0이면 `InvariantViolation`) |
| 5 | `invalid` | `u64` | 무효 수 |
| 6 | `time_bucket` | `u64` | |

`WitnessedEvent`(버전 2)의 본문이며 purpose는 `paper-count`, 서명자는 위원장 1과 서로 다른 조직 참관인 2 이상이다(§8.33 표). 위원장이 그 단위 `commission_org`의 명부 위원장인지와 후보 수가 투표양식의 것인지는 검증기가 확인한다.

#### 8.65 `ReceiptResolutionBody` (0x0047)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `box_id` | `Ident<64>` | 관외·재외 투표함 |
| 3 | `entries` | `Array<{record_hash: Hash512, outcome: u8}, 65536>` | `record_hash` 엄격 오름차순. `outcome` 1 `RECEIVED`, 2 `RECEIVED_DAMAGED`, 3 `RECEIVED_LATE`, 4 `WRONG_DISTRICT`, 5 `CAST_NOT_RECEIVED`(그 밖은 `ValueOutOfRange`) |
| 4 | `time_bucket` | `u64` | |

어떤 기록과도 맞지 않는 라벨과 중복 라벨의 수(VC-060)는 투표함이 아니라 수령 선관위의 것이므로 이 본문에 없다. 목록이 그 투표함의 투함 기록 전부와 같은지는 검증기가 확인한다.

시험 벡터는 `tally_scope_body.txt`, `aggregate_opening_body.txt`, `quorum_signed.txt`, `paper_count_report_body.txt`, `receipt_resolution_body.txt`이고, 버전을 올린 `witnessed_event.txt`, `roster_signer.txt`, `reporting_unit_entry.txt`도 다시 만들었다. 왕복 속성 테스트는 `tests/m5_tally.rs`에 있다.

### 8.66–8.73 감사 (ADR-0036)

> English summary: the audit's ledger objects. `AuditManifestFreezeBody` (0x0048) freezes one ballot style's sample frame (the count and sorted-set root of its included records) and sampling rule: the rule document's hash, the risk limit in parts per million, the designated beacon and its round, and one to eight rounds of cumulative sample size and tolerated discrepancies. `AuditCommitBody` (0x004E) fixes, after every freeze and before the beacon round is published, the dice transcript hash, the designated beacon and round and the sorted-set root of the freeze bodies. `AuditSeedBody` (0x000D) carries the dice transcript hash, the beacon round and value (the published output mapped to 64 bytes), the binding checkpoint's hash (the first valid checkpoint covering the commit) and the seed. A round's threshold must be below its size. `SampleOpeningBody` (0x0049) is the restricted opening of one record and never reaches the public ledger; `SampleOpeningRefBody` (0x004A), in a `QuorumSigned`, is its public reference by object hash. `SampleComparisonBody` (0x004B) gives the reason code 0–6 and the transfer mark; `AuditFindingBody` (0x004C) a device's finding; `HandCountReportBody` (0x004D) a unit's full hand count with the paper count's fields. Per-record objects carry no time bucket. The encoding checks form only; `ityv-state` and `ityv-verify` check the signers, the frame, the seed, the sample, the openings and the escalation (PROTOCOL §12, §14 8).

기록 하나에 관한 객체(0x0049, 0x004A, 0x004B)에는 시각이 없다(VC-001). 0이 아니어야 하는 해시가 0이면 `InvalidPreviousHash`다(§8.35와 같은 규칙).

#### 8.66 `AuditManifestFreezeBody` (0x0048)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `frame_count` | `u64` | 표본 프레임의 기록 수, `2^26 − 1` 이하(`ValueOutOfRange`) |
| 4 | `frame_root` | `Hash512` | 프레임(그 투표양식 모든 보고 단위의 포함 기록)의 정렬 집합 root |
| 5 | `rule_hash` | `Hash512` | 표본 크기 공식과 확대 규칙 문서의 해시(`policy_hash` 묶음 안), 0이 아님 |
| 6 | `risk_limit_ppm` | `u32` | 위험 한도, 백만분율 `1..=999999`(`ValueOutOfRange`) |
| 7 | `beacon_source` | `Hash512` | 공개 분산 난수 비콘 지정 문서의 해시, 0이 아님 |
| 8 | `beacon_round` | `u64` | 시드가 쓰는 비콘 회차 |
| 9 | `rounds` | `Array<{sample_size: u64, threshold: u32}, 8>` | 1개 이상(0이면 `InvariantViolation`). `sample_size`는 누적 표본 크기, `1..=2^26−1`(`ValueOutOfRange`), 엄격히 커짐(같으면 `Duplicate`, 작으면 `NotSorted`). `threshold`는 그 라운드에서 감사를 끝내는 비 0 코드 수의 상한으로 그 라운드의 `sample_size`보다 작고(같거나 크면 `ValueOutOfRange`: 모든 표본이 통과하는 라운드; 프레임으로 자른 크기보다 작은지는 프레임 수를 아는 검증기가 확인한다), 줄지 않음(`InvariantViolation`, 그 라운드의 위치). 코드에 가중치가 없으므로 상한은 가장 나쁜 불일치 유형을 가정해 정한다(PROTOCOL §12.4) |
| 10 | `time_bucket` | `u64` | |

#### 8.67 `AuditSeedBody` (0x000D)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `dice_hash` | `Hash512` | 주사위 추첨 공개 기록의 해시(약정이 고정한 것), 0이 아님 |
| 3 | `beacon_round` | `u64` | |
| 4 | `beacon_value` | `Hash512` | 그 회차의 비콘 값: `SHA3-512("ityv:beacon:v1" ‖ 0x00 ‖ u32_be(len(source)) ‖ source ‖ u64_be(round) ‖ output)`, `source`는 비콘 지정 문서 해시(64바이트), `output`은 공표 출력(길이 무관, PROTOCOL §12.1) |
| 5 | `checkpoint_hash` | `Hash512` | 고정 체크포인트(약정을 덮는 첫 유효 체크포인트) 본문의 객체 해시, 0이 아님 |
| 6 | `seed` | `Hash512` | `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice_hash ‖ beacon_value ‖ checkpoint_hash)`. 디코더는 계산하지 않고 검증기가 다시 계산한다(VC-045) |
| 7 | `time_bucket` | `u64` | |

#### 8.68 `SampleOpeningBody` (0x0049, restricted)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | 기록의 투표양식 |
| 3 | `record_hash` | `Hash512` | 표본 기록의 추적코드 |
| 4 | `option_index` | `u16` | 63 이하(`ValueOutOfRange`) |
| 5 | `cast_id` | `[u8; 24]` | |
| 6 | `rand` | `Array<Scalar, 8>` | `r_0..r_{k−1}`, 1개 이상(0이면 `ValueOutOfRange`). 투표양식의 청크 수와 같은지와 canonical 여부는 검증기가 확인한다 |

공개 장부의 이벤트가 아니다. 열람 권한이 있는 검증기에 호출자가 넘긴다. 구현은 값을 복사하지 않고 디버그 출력에 선택을 내지 않으며 해제 때 지운다.

#### 8.69 `SampleOpeningRefBody` (0x004A)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `record_hash` | `Hash512` | 연 기록의 추적코드 |
| 4 | `opening_hash` | `Hash512` | 제한 본문 `SampleOpeningBody` 객체의 해시, 0이 아님 |

`QuorumSigned`(버전 2)의 본문이며 purpose는 `sample-opening`이다.

#### 8.70 `SampleComparisonBody` (0x004B)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `record_hash` | `Hash512` | |
| 4 | `opening_hash` | `Hash512` | 감사인이 대조한 열기의 객체 해시, 0이 아님 |
| 5 | `device_id` | `Ident<64>` | 기록의 투표함(장치) |
| 6 | `code` | `u8` | 0 일치, 1 다른 후보, 2 후보·종이 무효, 3 `UNREADABLE`·종이 유효, 4 `BLANK`·종이 유효, 5 투표지 없음, 6 `cast_id` 중복·각인 불일치(PROTOCOL §12.3). 그 밖은 `ValueOutOfRange` |
| 7 | `transfer_mark` | `bool` | |

#### 8.71 `AuditFindingBody` (0x004C)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `ballot_style_id` | `Ident<64>` | |
| 3 | `device_id` | `Ident<64>` | |
| 4 | `finding_hash` | `Hash512` | 발견 문서의 해시, 0이 아님 |
| 5 | `time_bucket` | `u64` | |

#### 8.72 `HandCountReportBody` (0x004D)

필드와 규칙은 `PaperCountReportBody`(§8.64)와 같다. 스키마가 다를 뿐이며, 감사가 마지막 라운드를 넘은 뒤의 보고 단위별 수검표(법적 결과)다.

#### 8.73 `AuditCommitBody` (0x004E)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `dice_hash` | `Hash512` | 주사위 추첨 공개 기록의 해시, 0이 아님 |
| 3 | `beacon_source` | `Hash512` | 비콘 지정 문서의 해시(모든 동결의 것), 0이 아님 |
| 4 | `beacon_round` | `u64` | 비콘 회차(모든 동결의 것) |
| 5 | `freezes_root` | `Hash512` | 모든 투표양식 동결 본문의 객체 해시를 정렬한 집합의 root, 0이 아님 |
| 6 | `time_bucket` | `u64` | 비콘 공표 구간보다 앞서야 하고 고정 체크포인트의 증인 시각 이하여야 함(검증기) |

0이 아니어야 하는 해시가 0이면 `InvalidPreviousHash`다. 비콘과 동결이 받아들인 것과 같은지, 약정이 선거마다 하나인지, 고정 체크포인트와 약정이 비콘 공표 전인지는 검증기가 확인한다(VC-045, VC-119).

시험 벡터는 `audit_manifest_freeze_body.txt`, `audit_commit_body.txt`, `audit_seed_body.txt`, `sample_opening_body.txt`, `sample_opening_ref_body.txt`, `sample_comparison_body.txt`, `audit_finding_body.txt`, `hand_count_report_body.txt`이고, 버전을 올린 `witnessed_event.txt`(버전 3), `roster_signer.txt`(버전 3), `quorum_signed.txt`(버전 2)도 다시 만들었다. 왕복 속성 테스트는 `tests/m5_audit.rs`에 있다.

### 8.74–8.75 시점확인 (ADR-0034, ADR-0039)

> English summary: the genesis's timestamp authorities (set 12, fixed for the election) and the ledger event that carries one authority's RFC 3161 token over one earlier ledger event. The pins are `ityv-tsa`'s byte form (ADR-0037 §1), opaque to this crate; the verifier reads them, verifies the token over SHA-512 of the target's object hash, and judges it by the latest instant the authority allows (PROTOCOL §5.5).

#### 8.74 `TimestampAuthorityEntry` (0x0050, genesis 집합 12, 열쇠 `tsa_id`)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `tsa_id` | `Ident<64>` | 기관 ID. `TimestampRecord`가 이 값으로 기관을 가리킨다 |
| 2 | `operator` | `Ident<64>` | 운영 주체. 같은 운영 주체의 기관들은 앵커에서 하나로 센다 |
| 3 | `kind` | `u8` | 1 정부 운영, 2 정부 밖. 그 밖은 `ValueOutOfRange` |
| 4 | `policy_accuracy_ms` | `u32` | 기관의 정확도(밀리초): 핀이 허용하는 모든 정책이 보장하는 정확도를 덮는 값. 3,600,000 이하(넘으면 `ValueOutOfRange`). 검증기는 1,000–60,000만 받는다(ADR-0039 1·5항) |
| 5 | `pins` | `Array<Bytes<16952>, 4>` | `ityv-tsa` 핀 바이트(서명 인증서마다 하나), 1–4개(0이면 `InvariantViolation`), 각 1바이트 이상(빈 핀은 `InvariantViolation`), 바이트 엄격 오름차순(`NotSorted`, `Duplicate`) |

핀의 상한 16,952는 `ityv-tsa` 핀의 고정부(36)와 길이 두 개(4), 정책 8개(각 66 이하), 인증서(16,384 이하)의 합이다. 핀이 `ityv-tsa`로 읽히고 SHA-512를 허용하며 인증서 사본과 그 키가 만드는 허용 알고리즘을 갖는지, 한 인증서와 한 공개키가 두 번 고정되지 않는지, 정확도가 1초–1분인지, 같은 운영 주체(대소문자 무시)의 기관이 한 구분인지, 정부 운영과 정부 밖이 각각 있는지(VC-114), 운영 주체가 증인이나 선관위의 조직이 아닌지는 검증기의 genesis 규칙이다(ADR-0039 2항).

#### 8.75 `TimestampRecord` (0x004F, 장부 이벤트)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `target_schema` | `u32` | 대상 이벤트의 스키마(그 프레임이 적은 것): 0x0010 `SignedCheckpoint`, 0x0028 `WitnessedEvent`, 0x0033 `SignedGenesis`만. 그 밖은 `ValueOutOfRange`(VC-117) |
| 3 | `target_hash` | `Hash512` | 대상 이벤트의 객체 해시(그 프레임의 `event_hash`), 0이 아님(`InvalidPreviousHash`). 토큰의 `messageImprint`는 이 64바이트의 SHA-512다 |
| 4 | `authority_id` | `Ident<64>` | genesis 집합 12의 기관 ID |
| 5 | `token` | `Option<Bytes<16384>>` | DER `TimeStampToken`. 없음은 기관이 응답하지 않았다는 운영자의 기록(ADR-0034 3항). 있으면 1바이트 이상(빈 토큰은 `InvariantViolation`) |

기록에는 자기 서명이 없다. 토큰이 기관의 서명이고 프레임은 체크포인트가 덮는다. 대상이 앞 프레임에 받아들여진 이벤트인지, `WitnessedEvent`의 본문이 시점확인을 받는 종류(법적 결정, 명부 동결, 보관 영수증, ADR-0040)인지, 토큰이 그 기관의 어느 핀으로 그 각인에 대해 검증되는지는 검증기가 확인한다(PROTOCOL §5.5, ADR-0039 3·4항).

시험 벡터는 `timestamp_authority_entry.txt`, `timestamp_record.txt`이고, 집합이 하나 늘어 `genesis_body.txt`(버전 7)와 `signed_genesis.txt`를 다시 만들었다. 왕복 속성 테스트는 `tests/m5_timestamp.rs`에 있다.

### 8.76–8.81 선거인명부 (ADR-0033, ADR-0040)

> English summary: the roll's authorities (genesis set 13, fixed for the election) and its events. A source signs the public part of its extract, the commission and the committee freeze the roll as the merge of the extracts, each custodian signs what it recomputed from its copy, and an amendment carries the signature of the source its reason needs. The counts per precinct and age band are carried as the hash of the published counts table: a witnessed body is at most 2,048 bytes, and the table's form and its small-cell rule are the sub-regulation's (LEGAL_ANNEX amendment 14). A contested check-in is restricted; the public ledger carries its frame only. Every rule between events (who signed, the merge, the quorum, the chain) is the verifier's (PROTOCOL §6.1, §14 6).

#### 8.76 `RollAuthorityEntry` (0x0051, genesis 집합 13, 열쇠 `authority_id`)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `authority_id` | `Ident<64>` | 기관 ID. 명부 본문과 서명의 `signer_id`가 이 값으로 기관을 가리킨다 |
| 2 | `org_id` | `Ident<64>` | 조직 |
| 3 | `kind` | `u8` | 기능 하나. 출처: 1 주민등록 추출(구·시·군의 장), 2 전국 주민등록 스냅숏(행정안전부), 3 사망(법원행정처), 4 선거권 제한(검찰·법원), 5 재외선거인·국적 상실(외교부·법무부), 6 불복 결정 법원. 보관: 11 법원행정처, 12 행정안전부, 13 독립검증위원회, 14 보관을 신청한 정당. 그 밖은 `ValueOutOfRange` |
| 4 | `key` | `[u8; 2624]` | 하이브리드 공개키 |

항목 하나는 기능 하나와 키 하나다. 두 기능을 가진 조직(행정안전부는 스냅숏 출처이자 보관 기관이다)은 항목 둘을 가진다. 보관 기관들의 조직이 서로 다른지, 보관 기관 수가 `custody_quorum` 이상이고 법원행정처와 행정안전부가 있는지, 구·시·군의 장이 있고 스냅숏 출처가 정확히 하나인지, 키가 유효하고 genesis의 다른 키와 반쪽을 함께 쓰지 않는지는 검증기의 genesis 규칙이다(ADR-0040 2항).

#### 8.77 `RollSourceExtractBody` (0x0052)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `authority_id` | `Ident<64>` | 서명하는 출처 기관 |
| 3 | `kind` | `u8` | 1 투표구의 주민등록 추출, 2 전국 주민등록 스냅숏, 3 사망, 4 선거권 제한, 5 재외선거인·국적 상실. 그 밖은 `ValueOutOfRange` |
| 4 | `precinct` | `Option<Ident<64>>` | 투표구(genesis의 선거일 투표소). 종류 1에만 있고 그 밖에는 없다(어기면 `InvariantViolation`, 위치는 이 필드) |
| 5 | `reference_day` | `u64` | 기준일(유닉스 기원 이후의 날 수) |
| 6 | `entry_count` | `u64` | 항목 수 |
| 7 | `entries_root` | `Hash512` | 항목 commitment `C_i`(PROTOCOL §6.1)의 정렬 집합 root. 스냅숏이면 그 해시. 0이 아님(`InvalidPreviousHash`) |

#### 8.78 `RollFreezeBody` (0x0053)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `entries_root` | `Hash512` | 명부 항목 commitment의 정렬 집합 root, 0이 아님 |
| 3 | `entry_count` | `u64` | 항목 수 |
| 4 | `counts_hash` | `Hash512` | 공표하는 인원수 표(투표구별·연령대별, ADR-0033 4항)의 해시, 0이 아님. 표의 형식과 작은 칸 규칙은 하위 규정 |
| 5 | `pseudonym_root` | `Hash512` | 명부 가명 다중집합의 Merkle root(§6.5), 0이 아님 |
| 6 | `sources_root` | `Hash512` | 병합한 출처 추출 본문 객체 해시들의 정렬 집합 root, 0이 아님 |
| 7 | `source_count` | `u32` | 병합한 추출 수, 1 이상(0이면 `ValueOutOfRange`) |
| 8 | `time_bucket` | `u64` | 동결 시점 |

필드 2–5는 명부 상태이고 `RollAmendmentBody`가 같은 순서로 다시 적는다. 0인 해시는 `InvalidPreviousHash`다.

#### 8.79 `RollCustodyReceiptBody` (0x0054)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `custodian` | `Ident<64>` | 서명하는 보관 기관 |
| 3 | `subject_hash` | `Hash512` | 답하는 `RollFreezeBody` 또는 `RollAmendmentBody`의 객체 해시, 0이 아님 |
| 4 | `entries_root` | `Hash512` | 다시 계산한 항목 root, 0이 아님 |
| 5 | `entry_count` | `u64` | 다시 계산한 항목 수 |
| 6 | `counts_hash` | `Hash512` | 다시 계산한 인원수 표 해시, 0이 아님 |
| 7 | `sources_root` | `Option<Hash512>` | 동결에 답하면 다시 계산한 병합의 출처 root, 변경에 답하면 없음. 있으면 0이 아님 |
| 8 | `pseudonym_root` | `Option<Hash512>` | 이 보관 기관이 인증된 유닛과 모든 정당 모듈로 계산했거나 다시 계산한 명부 가명 root(VC-109). 없으면 계산하지 않았다. 있으면 0이 아님 |
| 9 | `time_bucket` | `u64` | 서명 시점 |

#### 8.80 `RollAmendmentBody` (0x0055)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `seq` | `u64` | 1부터, 0이면 `ValueOutOfRange` |
| 3 | `previous_hash` | `Hash512` | 1번이면 동결 본문, 그 뒤는 직전 변경 본문의 객체 해시. 0이 아님 |
| 4 | `reason` | `u8` | 1 이의신청 결정(구·시·군의 장), 2 불복 결정(법원), 3 사망(법원행정처), 4 선거권 제한(검찰·법원), 5 재외선거인·국적 상실(외교부·법무부). 그 밖은 `ValueOutOfRange` |
| 5 | `authority_id` | `Ident<64>` | 사유의 출처 기관(서명한다) |
| 6 | `basis_hash` | `Hash512` | 그 기관의 결정이나 통지 문서 해시, 0이 아님 |
| 7–10 | 명부 상태 | §8.78 필드 2–5 | 변경 뒤 값 |
| 11 | `time_bucket` | `u64` | 수록 시점 |

#### 8.81 `ContestedCheckin` (0x0056, restricted)

| 순서 | 필드 | 형 | 규칙 |
|---|---|---|---|
| 1 | `election_id` | `Ident<64>` | |
| 2 | `station_id` | `Ident<64>` | |
| 3 | `unit_id` | `Ident<64>` | 가명을 계산한 카운터·가명 유닛 |
| 4 | `pseudonym` | `[u8; 64]` | 선거권자의 가명(§6.4). 그 투표소의 `ParticipationSet`에 넣지 않는다 |
| 5 | `envelope_label` | `[u8; 24]` | 투표지를 넣은 봉투의 라벨 |
| 6 | `unit_sig` | `[u8; 4691]` | 유닛 서명 |
| 7 | `module_sigs` | `Array<{module_id: Ident<64>, sig: [u8; 4691]}, 4>` | 정당 모듈 서명, 서로 다른 모듈(같으면 `Duplicate`) |

서명은 모두 필드 1–5의 헤더 없는 인코딩에 대해 purpose `contested-checkin`이다(`ParticipationSet`과 같은 방식, §8.25). 순번과 시각은 담지 않는다. 가명 옆의 시각은 확인 순서를 드러낸다(VC-084). 모듈의 순서와 수(정당마다 하나, 챔버 순서), 유닛과 모듈의 키는 검증기가 확인한다. 공개 장부는 이 객체의 프레임(객체 해시)만 싣고, 본문은 열람 권한이 있는 검증기가 받는다(ADR-0040 8항).

시험 벡터는 `roll_authority_entry.txt`, `roll_source_extract_body.txt`, `roll_freeze_body.txt`, `roll_custody_receipt_body.txt`, `roll_amendment_body.txt`, `contested_checkin.txt`이고, 버전을 올린 `genesis_body.txt`(버전 8), `signed_genesis.txt`, `witnessed_event.txt`(버전 4)도 다시 만들었다. 왕복 속성 테스트는 `tests/m5_roll.rs`에 있다.
