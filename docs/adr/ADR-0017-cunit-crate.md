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

## 개정 (2026-11-01, 독립 리뷰 반영)

첫 구현의 독립 리뷰(명세 대조)에서 나온 결정이다. 위 결정과 충돌하면 이 절이 우선한다.

1. **투표함 단위 패드 소비.** 청크 수가 다른 투표양식이 한 투표함에 섞이면 표마다 b가 달라 패드 구간이 겹친다(이중 사용, VC-034 위반). b는 투표함의 투표양식 전부에 대한 최대 `MemberShare` 길이 + 64로 하나만 두고(genesis에 고정), 구간 안의 배치는 MAC 키·모듈 태그 키·평문 패드 순서로 고정한다(PROTOCOL §9.4.3). 모듈이 돌려줄 `rand` 개수를 알도록 `ModulePort::issue`는 그 표의 k를 받는다.
2. **카운터 최고값.** 유닛은 모듈별로 소비한 카운터의 최고값을 기억하고 그 값 이하의 카운터는 거부하며 기억을 바꾸지 않는다. 뒤로 간 카운터가 기준을 되돌려 이미 쓴 카운터를 다시 받는 경로를 없앤다.
3. **선택의 소거.** 선택 인덱스는 소거되는 비밀 영역 안에만 두며 종료 상태(투입 완료, 검증 폐기, 격리)는 선택을 갖지 않는다.
4. **비밀의 단일 위치.** 상태 전이마다 모듈 기여·합산 난수·투함 ID·DRBG를 값으로 옮기면 지워지지 않는 사본이 스택에 남는다. 비밀과 증명은 호출자가 준 작업 영역 하나에 두고 전이는 그 영역을 `&mut`로 빌려 쓴다. 작업 영역은 drop과 모든 오류 경로에서 소거된다. `ityv-crypto`의 SHA3는 `zeroize` 기능으로 스펀지 상태를 지운다. 비밀을 담은 타입은 `Clone`·`Copy`가 없고 `Debug`는 내용을 찍지 않는다(`ImprintCommand` 포함).
5. **격리의 회계.** 저널에 기록된 표가 각인되지 못하면 격리 항목은 그 기록 해시를 담고, 기록은 기록 수와 열린 배치에서 빠져 격리 수로 옮겨진다. 기록 전 격리(부분 발급 등)는 기록 해시 0과 소비된 카운터를 남기며, 일부 모듈만 발급한 표는 `ModuleCounters` 불일치로 `HOLD_REVIEW`와 `ModuleIncident`가 된다(의도된 결과). 각인 명령과 슬립은 표가 여전히 그 투표함의 진행 중인 표일 때만 나온다.
6. **배치 서명 한 번.** 거부 목록이 본문에 들어가므로 유닛은 먼저 모듈마다 구간 확인(서명·상태 변화 없음)을 묻고, 본문을 확정한 뒤 동의한 모듈에게 한 번씩만 서명을 받는다. 시간 역행과 저널 전제는 서명 요청 전에 검사한다. 모듈의 기록·배치 서명은 genesis의 모듈 공개키(설정에 포함)로 검증한 뒤에만 객체에 넣는다.
7. **저널 불일치 고정.** 배치 마감 때 호스트가 저장 매체에서 다시 읽은 head가 유닛의 head와 다르면 유닛은 고장 상태로 고정되어 새 표·배치·스캔 카운터·마감(장치 서명)을 거부한다(VC-056). 호스트는 head를 유닛 접근자에서 복사하지 않고 저장 매체에서 읽어야 한다.
8. **스캔 카운터.** 진행 중인 표가 있으면 `ScanCountAttestBody`를 만들지 않는다(VC-052 단조성).
9. **마감 불변식과 프로필.** 관외·재외 투표함은 봉투 수가 필수이고 `record_count`와 같아야 하며, 관내 투표함에는 봉투 수가 없다. 마감 토큰은 그 투표함에 묶여 다른 투표함을 닫지 못한다. `record_set_root`는 호스트가 저널에서 계산해 넘기며 유닛은 그 값에 서명한다. 공개 검증기가 게시된 기록과 배치 root로 대조하므로 틀린 값은 `HOLD_REVIEW`가 된다.
10. **챔버 구성.** X·Y는 자체 모듈이 필수이고 J·A·C는 자체 모듈 또는 중립 모듈 위임이 필수다. N만 모듈이 없다. 중립 모듈 위임은 위임한 챔버마다 별도의 논리 모듈(자기 `module_id`와 카운터)로 모델링하고 `transport_flags` 비트1을 세운다. 비트0은 모듈이 있는 챔버의 패드 고갈 대체만 뜻한다.
11. **재개.** 전원 상실 뒤 유닛은 저널 스트림을 처음부터 읽어 head 사슬을 검증하고 카운터 최고값·열린 배치·누적 수량을 복원한다. 대기 구역에 투표지가 남았으면(사무원·참관인 확인을 호스트가 전달) 마지막 기록을 격리한다. 투함 ID를 영속 저장하지 않으므로 재개 후 각인은 없다(PROTOCOL §7.3).
12. **은닉 채널 검사의 복원 범위.** 표본 기록마다 챔버 기여 하나만 복원한다(PROTOCOL §9.5, VC-058). 모든 챔버의 `cid_c`와 `r_c`가 모이면 투함 ID와 합산 난수가 계산되어 선택이 드러나기 때문이다. 이 규칙은 신뢰기관 측(M5·M8)이 강제하며 유닛과는 무관하다.
14. **각인 완료 항목.** 재개 때 각인 없는 투표지가 마지막 기록의 것인지 저널에 오르지 않은 새 투표지인지 가를 수 없어 잘못된 기록을 격리할 수 있었다. 인쇄가 끝나면 종류 6 항목을 확정한 뒤 낙하하고, 재개는 대기 구역 상태(비어 있음 / 각인된 투표지 / 각인 없는 투표지)와 마지막 기록의 각인 항목 유무로 판정한다(PROTOCOL §7.3). 표마다 저널 쓰기가 한 번 늘지만 판정이 모호하지 않다.
15. **소거 강화.** `ityv-encoding`의 비밀 담는 타입(`Scalars`, `MemberShare`, 검증 공개의 모듈 열기)은 `zeroize`로 지우고, `ityv-crypto`는 증명을 호출자 영역에 직접 쓰는 `prove_into`를 둬 20KB 임시 사본을 없앤다.
13. **표기.** typestate 컴파일 실패 검사는 trybuild 대신 `compile_fail` doctest로 한다. 별도의 `finish()` 대신 종료 상태의 drop과 작업 영역의 소거가 §5의 소거를 수행한다. 소스 아래의 `#[expect]` 완화는 CONSTITUTION §1.1에 따라 없앤다.

## 기각한 대안

- 서명 필드를 0으로 채운 객체를 서명 메시지로 쓰기: 정규 인코딩의 단일성을 깨고 두 번째 구현의 실수 지점이 된다. 본문·서명 분리로 대체.
- 유닛이 fsync·인쇄를 직접 수행: 입출력이 TCB에 들어오고 하드웨어마다 달라진다. 호스트 trait와 typestate로 순서만 강제.
- 패드 XOR를 유닛에서 수행: 선관위 부품에 패드가 존재하게 되어 VC-035 위반.
