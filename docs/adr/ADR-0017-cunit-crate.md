# ADR-0017: 커밋먼트 유닛 크레이트 `ityv-cunit`의 경계, 장치 링크 객체, 표별 상태기계

> English summary: `ityv-cunit` is the TCB core of the casting scanner's commitment unit: a `no_std`, allocation-free state machine per ballot (interpreted → issued → committed → built → durable → imprinted → slipped, or challenged), the batch and box accounting, the sealed journal hash chain, and the construction of every object the unit emits (cast record, share package, slip, challenge opening, batch attestation, scan-count and box-close bodies). It owns no I/O: the host supplies the interpretation link, the chamber-module port, the journal sink, the printer and imprinter, and the time bucket; it gets back bytes and typed tokens. Objects that cross an organizational boundary are schemas of `ityv-encoding`; device-internal objects (journal entries, link messages) are schemas of this crate. Secrets are zeroized at fixed points (the V3 target). Typestate makes "no imprint before the journal write is durable" and "no record after close" compile-time rules (checked with trybuild).

- 상태: 채택
- 날짜: 2026-10-31
- 관련: ADR-0005, ADR-0006, ADR-0007, ADR-0012, ADR-0014, ADR-0015, ADR-0016; `docs/spec/PROTOCOL.md` §7, §8, §9, §10.2; `docs/spec/ENCODING.md` §6, §8.6–§8.19; `CONSTITUTION.md` §4; `docs/ROADMAP.md` M3

## 맥락

커밋먼트 유닛은 표 하나의 모든 암호 산출물(커밋먼트, 정형성 증명, share 패키지, 기록 서명, 추적코드, 각인 명령)을 만드는 장치 부품이며 검증 사다리의 최상위 대상이다(CONSTITUTION §4, GLOSSARY `cunit`). 명세는 산출물의 내용과 생성 순서(§7.3)를 정하지만, 유닛이 호스트·모듈과 주고받는 객체의 바이트 배치, 표별 상태 전이, 배치·투표함 회계의 코드 경계는 정하지 않았다. 해석 유닛은 불신이고 모듈은 챔버가 공급하므로 유닛은 입력을 고정 스키마 디코더로만 받아야 한다(ITYV-BEH-013).

## 결정

1. **범위.** `ityv-cunit`는 `link`(해석 유닛·모듈 링크 객체의 디코더와 `ModulePort` trait), `ballot`(표별 typestate), `record`(투함 기록 본문·기록 서명), `shares`(share 패키지: 비밀분산, 구성원 평문, 패드 전송·KEM 대체), `journal`(봉인 저널 사슬과 `Durable` 토큰), `batch`(`BatchAttest`, 모듈 구간 규칙), `boxstate`(투표함 카운터, `ScanCountAttest`, `BoxClose` 본문과 마감 불변식), `challenge`(투입 전 검증 공개), `slip`을 담는다. 이미지 해석, 모든 입출력(링크 전송, fsync, 인쇄, 각인), 키 보관(HSM), 벽시계, 모듈 펌웨어(M8), 사람이 서명하는 이벤트의 조립은 밖이다.
2. **스키마의 위치.** 조직 경계를 넘는 객체(공개 이벤트, 신뢰기관에 가는 봉인 패키지)는 `ityv-encoding`의 스키마다: `CastRecordBody` 0x0005, `ChallengeOpeningBody` 0x0006, `BoxCloseBody` 0x0007, `Slip` 0x000A, `SharePackage` 0x000B, `BatchAttestBody` 0x0012, `ScanCountAttestBody` 0x0013, `MemberShare` 0x0015, `CastRecord` 0x0016, `BatchAttest` 0x0017, `ChallengeOpening` 0x0018, `SlipBody` 0x0019, `BoxClose` 0x001A, `ScanCountAttest` 0x001B. 장치 내부 객체는 이 크레이트의 스키마다: `JournalEntry` 0x0014, `Interpretation` 0x0101, `ModuleIssue` 0x0103. 자기 서명을 담는 이벤트는 모두 "본문 객체 + 서명 묶음" 두 객체로 나눈다(`SignedCheckpoint`와 같은 규칙): 서명 메시지는 본문 객체 바이트 전체다.
3. **링크 객체.** 해석 유닛 → 유닛은 `Interpretation`(0x0101: `election_id`, `ballot_style_id`, `option_index: u16`)만 통과하며, `option_index`는 `0..=m+1`이어야 한다(0 BLANK, m+1 UNREADABLE). 모듈 → 유닛은 `ModuleIssue`(0x0103: 공개부 `module_id`, `chamber: u8`, `counter: u64`; 비공개부 `rand: Array<Scalar, 8>`, `cid: Token192`, `lab: Option<Token192>`, `tags: Array<[u8; 16], 8>`). 유닛 → 모듈 요청(발급, 패드 봉인, 기록 서명, 배치 서명)은 `ModulePort` trait의 타입 인자로 두고 링크 인코딩은 M8에서 정한다.
4. **유도 규칙.** `r_j = Σ_c r_{c,j} (mod ℓ)`; `cast_id = SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_{c_1} ‖ … ‖ cid_{c_n})[0..24]`, `env_label = SHA3-512("ityv:envlabel:v1" ‖ 0x00 ‖ lab_{c_1} ‖ … ‖ lab_{c_n})[0..24]`, 두 경우 모두 존재하는 모듈을 `module_id` 바이트 오름차순으로 연접한다. 모듈 기록 서명의 메시지는 `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`의 정규 인코딩이고 purpose는 `module-record`다.
5. **표별 typestate.** `Ballot<Interpreted> → Issued → Committed → Built → {Durable → Imprinted → Done | Challenged}`. `Built`에서 `cast()`는 저널 항목 바이트와 share 패키지 바이트를 내고 호스트의 `JournalSink::append`가 `Ok`을 돌려준 뒤에만 `Durable`을 만든다. 각인 명령(`ImprintCommand { cast_id }`)과 슬립 본문은 `Durable`에서만 나온다(VC-054, ITYV-BEH-065; trybuild로 컴파일 실패를 고정). 투입·검증·격리 어느 경로든 `finish()`가 모든 비밀(선택, 난수, 투함 ID, 라벨, share, 패드 평문)을 소거한다(VC-020; V3 증명 대상). 각인 실패는 호스트가 `ImprintFailed`로 보고하고 유닛은 저널에 `kind = 3`(격리) 항목을 덧붙인다(VC-023).
6. **share 패키지.** 비밀은 §9.1(모듈별 `r_{c,j}`, `cast_id` 스칼라, 관외·재외면 `env_label` 스칼라)이고 분산은 §9.2를 `ityv-crypto::shares::split`로 수행한다. 구성원 평문은 `MemberShare`(0x0015) 객체이며 길이는 선거 구성(존재 모듈 수, k, 프로필)으로 고정된다: `b = len(MemberShare) + 32 + 32`가 §9.4.3의 패드 소비 바이트다. 모듈이 있는 챔버의 구성원은 `transport = 0`으로 모듈 포트에서 암호문·태그·`pad_index`를 받고, 모듈이 없거나(`N`) 모듈이 `EXHAUSTED`를 돌려주면 `transport = 1`(§9.6 KEM, 수신자 키는 genesis)이다. 중립 모듈 위임은 `transport_flags` 비트1로 표기한다.
7. **봉인 저널.** `JournalEntry`(0x0014) = `prev_head: Hash512 ‖ kind: u8 ‖ record_hash: Hash512 ‖ share_package_hash: Hash512 ‖ module_counters: Array<{module_id, counter}, 6> ‖ time_bucket: u64`, head = 항목의 §4 해시, 첫 항목의 `prev_head`는 0. `kind`: 1 기록, 2 검증 폐기, 3 격리, 4 배치 마감, 5 투표함 마감. 호스트는 항목과(기록이면) share 패키지 바이트를 함께 내구 기록한 뒤에만 `append`에서 돌아온다. 유닛은 메모리의 head를 유지하고, 배치 서명 전에 호스트가 다시 읽은 저널 head와 대조해 다르면 `JournalMismatch`로 서명을 거부한다(VC-056).
8. **배치.** 기록 64건, 또는 마지막 기록 후 1 구간(15분) 경과, 또는 마감 직전에 배치를 닫는다. `BatchAttestBody`(0x0012) = `election_id ‖ box_id ‖ batch_index: u32 ‖ record_count: u16 ‖ records_root: Hash512`(기록 해시의 정렬 집합 root, `ityv-ledger::merkle::sorted_set_root`) `‖ module_ranges ‖ module_refusals ‖ journal_head: Hash512 ‖ time_bucket`. `BatchAttest`(0x0017) = 본문 바이트 + 모듈 하이브리드 서명 묶음 + 장치 하이브리드 서명(purpose `batch-attest`). 모듈이 서명하는 규칙 "미증명 카운터 목록이 구간과 정확히 일치"는 모듈 펌웨어도 쓰도록 이 크레이트의 순수 함수 `module_may_sign_batch`로 둔다(VC-021).
9. **투표함 회계.** `BoxState`는 `record_count`, `attested_count`, `challenge_count`, `quarantine_count`, `no_record_count`(사무원 `FallbackDeclared`에서 호스트가 전달), `open_batches`, 모듈별 `final_counter`, 저널 head, 마지막 `ScanCountAttest`의 수량·구간을 가진다. 50건마다 또는 8 구간(2시간)마다 `ScanCountAttestBody`(0x0013)를 내고 참관인 서명은 밖에서 붙는다(VC-052). `BoxCloseBody`(0x0007)는 §10.2의 필드를 담고 장치 하이브리드 서명(purpose `box-close`)을 받으며, VC-038의 불변식은 순수 함수 `close_verdict`가 판정해 위반 목록을 돌려준다(위반이 있어도 마감은 수록되고 상태는 `HOLD_REVIEW`). 마감 뒤 `BoxState`는 `Closed`가 되어 새 표를 받지 않는다(VC-039, ITYV-BEH-049·079).
10. **투입 전 검증.** `Challenged`에서 `ChallengeOpeningBody`(0x0006)를 만든다: `record_hash`, `option_index`, `cast_id`, `rand`(합산 `r_j`), 모듈별 `(module_id, counter, rand_c, cid_c)`. 장치 하이브리드 서명(purpose `challenge`)을 붙인 `ChallengeOpening`(0x0018)이 공개 이벤트다. 누구나 §7.4·§7.5로 `C_j`와 `π`를 재구성해 기록과 대조한다(VC-028). 검증 폐기도 모듈 카운터를 소비하므로 `challenge_count`와 저널 `kind = 2`에 남는다.
11. **슬립.** `SlipBody`(0x0019) = `election_id ‖ station_id ‖ time_bucket ‖ tracking_code`, `Slip`(0x000A) = 본문 바이트 + 장치 하이브리드 서명(purpose `slip`). `VOTER_CODE` 범위가 없으면 만들지 않는다.
12. **고정 용량과 타입 경계.** 모듈 6, 챔버당 구성원 8, 구성원 64, 비밀 50(모듈 6 × 청크 8 + 2), 배치 64, 선택지 64, 청크 8. `alloc` 없음, 벽시계 없음(`TimeBucket`은 호스트 인자). 검증 결과와 전이 토큰은 이 크레이트의 `Verified<T>`·typestate이며 호출자가 만들 수 없다. 키는 `ityv-crypto`의 서명 키 타입을 호스트가 넘기고(HSM 자리는 P0-05), 유닛은 사본을 소거한다.
13. **검증 사다리.** V1(속성·변이·회귀 벡터·링크 디코더 퍼징 타깃), V2(Kani: 카운터·마감 불변식·배치 구간·패드 인덱스 산술·`option_index` 범위·상태 전이), trybuild(typestate), V4(M7의 TLA+에 배치·마감 모델 추가는 후속). 소거 성질의 V3는 미해결 항목이며 M3에서는 `Zeroizing`과 소거 지점 테스트로 대신한다.

## 결과

- `ENCODING.md` §6에 0x0012–0x001B와 장치 링크 범위 0x0100–0x01FF를 등록하고 §8.6–§8.19에 필드 정의를 둔다. `PROTOCOL.md` §7.2.1·§7.3·§7.6·§7.7·§7.8·§8·§9.3·§10.2와 부록 A를 맞춘다.
- M3는 두 단계로 구현한다: (1) `ityv-encoding`에 공유 스키마 14개와 벡터·Kani 왕복, (2) `ityv-cunit` 로직. 각 단계에 독립 리뷰를 둔다.
- M8의 모듈 펌웨어는 `ModulePort`의 링크 인코딩과 `module_may_sign_batch`를 그대로 쓴다. M4 상태기계는 `BoxCloseBody`·`ScanCountAttestBody`에 사람 서명을 붙인 래퍼를 조립한다.

## 기각한 대안

- 서명 필드를 0으로 채운 객체를 서명 메시지로 쓰기: 정규 인코딩의 단일성을 깨고 두 번째 구현의 실수 지점이 된다. 본문·서명 분리로 대체.
- 유닛이 fsync·인쇄를 직접 수행: 입출력이 TCB에 들어오고 하드웨어마다 달라진다. 호스트 trait와 typestate로 순서만 강제.
- 패드 XOR를 유닛에서 수행: 선관위 부품에 패드가 존재하게 되어 VC-035 위반.
