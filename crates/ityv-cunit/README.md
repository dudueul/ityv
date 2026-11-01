# ityv-cunit

> English summary: The trusted core of the casting scanner's commitment unit (ADR-0017 and its 2026-11-01 amendment). A `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate that turns one interpreted ballot into every object the scanner emits: the generalized Pedersen commitments and their 1-of-(m+2) OR proof, the share package for the trustees (each secret split over the chamber access structure, sealed per member through the chamber module's one-time pad or the hybrid KEM), the device and module record signatures (module signatures verified against their genesis keys), the tracking code, the imprint command and the imprint-complete journal entry that must be durable before the paper drops, and on request the signed pre-cast challenge opening or the code slip. Every per-ballot secret (the choice, module contributions, summed randomness, cast id, envelope label, generator state, share plaintexts) and the proof live in one caller-provided work area that the ballot borrows and that is wiped on every exit path. The crate also keeps the box state: per-module counter high-water marks, the sealed journal hash chain, batch attestations (a dry run first, then one verified signature per consenting module), scan-count bodies, a fault latch on a journal mismatch, the box close with the VC-038 verdict (including papers lost or unmatched at a resume, and the visit, envelope and sticker counts of ADR-0021) and a box-bound close token, and resume from the journal after a power loss, deciding from the attested waiting-area state what happens to the paper there. Shares follow the per-party access structure of ADR-0019: party chambers P1..Pn (2 ≤ n ≤ 4) each with its own module, never delegated, and at most seven modules per scanner. A box accepts up to 4,096 ballot styles (an early-voting scanner holds every district's), sorted by identifier and found by binary search. The crate owns no I/O: the host implements the module ports, the journal sink and source, and supplies time buckets and per-operation seeds. Ordering rules are types: an imprint command or a slip exists only after the journal sink reported the record durable, a cast ballot cannot be challenged, and a closed box has no method that accepts a ballot.

## 무엇인가

커밋먼트 유닛은 투함 스캐너의 검증 부품이다(PROTOCOL.md §7.1, CONSTITUTION §4). 이 크레이트는 그 TCB 핵심이며 명세는 `docs/spec/PROTOCOL.md` §7–§10, `docs/spec/ENCODING.md` §8.6–§8.19, `docs/adr/ADR-0017-cunit-crate.md`(2026-11-01 개정 포함)다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `config` | genesis에서 호스트가 만드는 선거 구성: 투표양식(최대 4,096개, ID 오름차순, 이진 탐색), 모듈(챔버당 하나, 최대 7개; 정당 챔버 P1…Pn(2 ≤ n ≤ 4)은 자체 모듈만 쓰고 위임하지 않으며 n 밖의 정당 챔버는 모듈도 구성원도 없음, J·A·C는 자체 또는 중립 위임, N은 없음)과 모듈 공개키(Ed25519 기록 키, 하이브리드 배치 키), 신뢰기관 명부, 접근구조, `VOTER_CODE`. 투표함 단위 패드 소비 `b`를 검증 시 고정한다 | ADR-0017 §2, §12, 개정 1·10·16, ADR-0019 |
| `link` | 해석 유닛 링크 `Interpretation`(0x0101)과 방문 끝 알림 `VisitEnd`(0x0104), 모듈 링크 `ModuleIssue`(0x0103), 봉인 저널 `JournalEntry`(0x0014, 종류 1–8) | ENCODING.md §8.19, ADR-0021 |
| `port` | 호스트 trait `ModulePort`(발급 `issue(k)`, 패드 봉인, 기록 서명, 배치 구간 확인 `check_batch`, 배치 서명)·`JournalSink`(내구 추가)·`JournalSource`(재개 시 읽기), 모듈의 배치 서명 규칙 `module_may_sign_batch` | ADR-0017 §3, §7–§8, 개정 6·11, VC-021 |
| `rng` | SHA3-512 카운터 모드 생성기 `DeviceRng`(표 생성기: 장치 시드와 모든 모듈의 비공개 기여로 시드, 작업 영역 안에서 재시드; 서명 생성기: 장치 시드) | ADR-0017 §12 |
| `ballot` | 작업 영역 `BallotWork`, 표별 typestate `Interpreted → Issued → Committed → Built → Durable → Done` 또는 `Built → Challenged`, share 패키지·투함 기록·검증 공개·슬립 | PROTOCOL.md §7.3–§7.7, §8, §9, 개정 3–5 |
| `boxstate` | `OpenBox`: 카운터 최고값, 저널 사슬, 배치 마감(`BatchAttest`), 스캔 카운터 본문, 고장 고정, 마감(`BoxCloseBody` + 장치 서명 + VC-038 판정 + 투표함에 묶인 토큰), 재개와 대기 구역 판정, 투표지 사건 수, `ClosedBox` | PROTOCOL.md §7.2.1, §7.3, §7.8, §10.2, 개정 5–9·11·14 |
| `rules` | 순수 규칙(Kani 대상): 선택지 범위, 카운터 최고값, 패드 소비·인덱스·구간 배치, 배치·스캔 카운터 시점, 마감 불변식, 재개 때의 대기 구역 판정표 | §7.2, §7.3, VC-021, VC-034, VC-038, VC-052 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음. 워크스페이스 lint 집합을 그대로 쓰며 `src/`에는 `#[allow]`·`#[expect]`가 하나도 없다(CONSTITUTION §1.1).
- 해석 유닛에서는 `Interpretation` 객체 하나만 받는다. 다른 선거, 모르는 투표양식, `t > m+1`은 거부한다(ITYV-BEH-013).
- 표는 한 번에 하나만 처리한다. 새 해석은 진행 중인 표가 있거나 배치가 가득 차면 거부된다. 배치 마감과 스캔 카운터 본문은 표와 표 사이에서만 나오므로 배치가 증명하는 모든 카운터는 이미 저널에 있는 표의 것이고, 스캔 카운터의 수량과 head는 뒤로 가지 않는다(VC-052).
- 각인이 끝나면 `imprinted`가 각인 완료 항목(종류 6, 기록 해시와 그 기록의 카운터를 되풀이하며 새로 소비하지 않음)을 저널에 확정한 뒤에만 `Done`을 돌려주고, 호스트는 그때만 투표지를 함으로 떨어뜨린다(PROTOCOL.md §7.3 단계 8). 항목 쓰기가 실패하면 표는 진행 중으로 남고 호스트가 격리한다.
- 각인 명령과 슬립은 `Durable` 상태에만 있고, `Durable`은 저널 싱크가 기록과 share 패키지의 내구 기록을 보고한 뒤에만 생긴다(VC-054). 둘 다 그 표가 여전히 투표함의 진행 중인 표일 때만 나온다(격리된 표는 `NoBallotInFlight`/`StaleBallot`). 투입된 표는 검증 폐기할 수 없다. 이 순서들은 컴파일 실패 문서 테스트로 고정한다. 마감한 투표함(`ClosedBox`)에는 표를 받는 메서드가 없다(VC-039).
- 모듈 카운터는 모듈별 최고값 + 1일 때만 받는다. 최고값 이하(되감기·재사용)는 `CounterRegression`, 건너뛰기는 `CounterGap`이며 둘 다 최고값을 바꾸지 않는다(개정 2). 패드 인덱스는 `카운터 × b`여야 하고(VC-034) `b`는 투표함에 하나다. 청크 수가 다른 투표양식이 섞여도 패드 구간이 겹치지 않는다(개정 1).
- 모듈의 기록 서명과 배치 서명은 설정의 genesis 공개키로 검증한 뒤에만 객체에 넣는다(`RecordSignature`, `BatchSignature`).
- 배치 마감은 모든 전제(투표함 상태, 진행 중인 표, 호스트가 저장 매체에서 다시 읽은 head, 빈 배치, 포트 수, 시간 구간, 작업 버퍼)를 먼저 검사한다. 그다음 모든 모듈에 구간 확인(서명·상태 변화 없음)을 묻고, 거부 목록을 넣은 최종 본문에 동의한 모듈마다 한 번씩 서명을 받는다. 한 모듈의 거부가 다른 모듈의 재서명이나 연쇄 거부를 부르지 않는다(개정 6).
- 저널 head가 다르면 투표함은 고장 상태로 고정되어 새 표, 배치, 스캔 카운터, 마감 서명을 모두 거부한다(VC-056, 개정 7).
- 마감은 프로필과 봉투 수를 대조한다(관외·재외는 봉투·스티커 수와 회송용 봉투 교부·빈 봉투 회수 수가 필수, 관내는 없음; `EnvelopeCountProfile`). 판정은 VC-038 전체다: 관내는 `paper_count == record_count + no_record_count`, 관외·재외는 `paper_count == 0`, `sticker_count == visit_count`, `envelope_count == 교부 − 빈 봉투 회수`, 그리고 모든 함에서 `visit_count ≤ record_count ≤ 8·visit_count`. 마감 토큰은 서명한 `BoxCloseBody`의 해시를 담아 그 투표함만 닫는다(`ForeignCloseToken`).
- 격리의 회계(개정 5): 저널에 기록된 표의 격리는 그 기록 해시를 담은 항목 3을 쓰고, 기록을 기록 수와 열린 배치에서 빼 격리 수로 옮긴다. 기록 전 격리는 기록 해시 0과 소비된 카운터를 쓴다. 카운터를 하나도 소비하지 않은 표는 유권자에게 돌려준다(항목 없음).
- 증명·비밀분산의 난수는 장치 시드와 모든 모듈 기여로 시드된 생성기에서만 나오므로 장치 혼자도, 모듈 하나도 그 난수를 정하지 못한다.

## 작업 영역 계약

비밀은 한 곳에만 있다(개정 3·4). 호스트는 `BallotWork`(64비트에서 36,408바이트, 생성자는 `const`)를 하나 두고 표마다 `OpenBox::interpret(link, &mut work)`로 빌려준다. 소형 대상에서는 `static`에 둔다.

- 작업 영역에 있는 것: 선택 인덱스, 모듈 기여(카운터, `r_{c,j}`, `cid_c`, `lab_c`, 태그), 투함 ID, 봉투 라벨, 합산 난수 `r_j`, 표 생성기 상태, 공유 비밀 값, 구성원별 share 스칼라와 `MemberShare` 평문, 증명(`Proof`), 검증 공개 본문 작성 공간.
- 증명은 `ityv_crypto::prove_into`가 작업 영역의 `Proof`에 제자리로 쓴다(20 KB 임시값 없음). 소거는 `Proof::clear`, 빈 상태 확인은 `Proof::is_empty`다.
- 표 상태가 들고 다니는 것은 공개값뿐이다: `Committed`는 커밋먼트, `Built`·`Durable`은 기록 해시와 호스트 버퍼의 슬라이스. 상태 하나는 64비트에서 300바이트 이하이며(단위 테스트가 상한을 고정한다) 20 KB 증명이나 2.6 KB 기여를 상태마다 복사하지 않는다.
- 소거 시점: 표가 작업 영역을 빌릴 때, share 봉인을 마쳤을 때(공유 값과 평문), 투입(`cast`)으로 `Durable`이 될 때(투함 ID와 봉투 라벨만 남김), 종료 상태(`Done`, `Challenged`)에 이를 때, 전이가 실패할 때(소비된 표가 drop된다), 표 값이 버려질 때, 작업 영역 자체가 drop될 때. 종료 상태는 비밀도 선택도 갖지 않는다.
- 검증 공개의 저널 쓰기가 실패하면 호스트 버퍼에 쓴 공개 객체도 0으로 덮는다.
- `BallotWork::is_clear()`는 모든 필드가 비었는지 알려 준다. 호스트는 표마다 확인할 수 있고, 테스트는 이것으로 종료·실패 경로의 소거를 관찰한다.
- 증명은 영지식이고 공개되므로 비밀이 아니다. 상태가 증명을 들고 다니지 않도록 작업 영역에 두며, 기록 본문을 쓰는 동안 인코딩은 호스트의 기록 버퍼에 잠시 둔다(기록은 그 위에 쓰인다).
- `ityv-encoding`의 비밀 담는 값(`Scalars`, `MemberShare`, `ModuleOpening`, `ChallengeOpeningBody`)은 drop 때 스스로 지워지므로 구성원 평문과 검증 공개를 만드는 동안의 사본도 지워진다(개정 15).

## 재개

전원 상실 뒤 `OpenBox::resume(config, source, sink, inputs, package_buf)`는 `JournalSource`가 처음부터 읽어 주는 저널만으로 투표함을 다시 만들고 `(OpenBox, WaitingAction)`을 돌려준다(개정 11·14).

- 항목마다 검사한다: 0에서 시작하는 head 사슬, 디코딩, 시간 구간의 단조성(개함 구간 이상), 기록 항목 바로 뒤에만 share 패키지가 있고 그 해시가 맞는지, 소비된 카운터가 모듈마다 최고값 + 1인지, 기록을 지목하는 격리(종류 3)와 각인 완료(종류 6)가 바로 앞의 그 기록과 같은 카운터인지(카운터 최고값은 바뀌지 않는다), 배치 마감의 root와 카운터가 재생한 배치와 맞는지, 투표함 마감 뒤에 항목이 없는지. 하나라도 어긋나면 `JournalCorrupt`, 마감으로 끝나면 `BoxClosed`다.
- 복원하는 것: head, 카운터 최고값, 열린 배치의 기록 해시와 마지막 기록 구간, 증명된 카운터, 배치 번호, 누적 수량, 투표지 사건 수. 진행 중인 표는 없다. 실제 운영에서 기록 뒤에는 그 기록의 각인이나 격리가 다른 어떤 항목보다 먼저 오므로, 기록 뒤에 다른 항목이 바로 오면 이전 재개에서 투표지가 사라진 것이고 사건 하나로 센다.
- 대기 구역 판정(`rules::waiting_area_action`): 입력은 사무원 2인과 참관인 2인이 확인한 대기 구역 상태(`Empty`, `Imprinted`, `Unimprinted`)와 저널 마지막 기록의 상태다.

| 대기 구역 \ 마지막 기록 | 기록 없음 | 열림(각인·격리 없음) | 각인 완료 | 격리됨 | 사라짐 |
|---|---|---|---|---|---|
| 비어 있음 | 없음 | `PaperMissing`: 사건, 항목 없음 | 없음 | 없음 | 없음 |
| 각인된 투표지 | `QuarantineUnmatched`: 기록 없는 격리 + 사건 | `JournalImprint`: 종류 6 후 낙하 | `Drop`: 낙하(두 번째 전원 상실) | `Divert`: 격리 봉투로, 항목 없음 | `QuarantineUnmatched` |
| 각인 없는 투표지 | `QuarantineUnjournaled`: 기록 없는 격리 | `QuarantineRecord`: 그 기록 해시로 격리 | `QuarantineUnjournaled` | `QuarantineUnjournaled` | `QuarantineUnjournaled` |

  덧붙이는 항목은 `inputs.time_bucket`을 쓴다. Kani 하네스가 이 표를 독립적으로 적은 표와 대조한다.
- 마감 판정에는 `paper_incidents` 사실과 `Invariant::PaperIncidents`를 더했다. 투표지가 사라지면 기록 수와 투표지 수가 우연히 맞더라도 마감은 `HOLD_REVIEW`다.
- 재개 직후에는 스캔 카운터가 바로 기한이 된다(참관인이 복원된 head를 다시 증명한다).

## 남은 명세 편차와 한계

- 소거의 연역 증명(V3, VC-020)은 미해결이다. `Opening::new`와 `CastId`는 값으로 복사된다(`Opening`은 drop 때 지운다). 컴파일러가 이동 때 남기는 스택 사본은 Rust에서 보장해 지울 수 없다.
- 투표함 마감의 `record_set_root`는 호스트가 저널에서 계산해 넘기고 유닛은 그 값에 서명한다(투표함 전체의 기록 해시를 고정 메모리에 담을 수 없다). 공개 검증기가 공표된 기록과 배치 root로 대조하므로 틀린 값은 `HOLD_REVIEW`다(개정 9, VC-027).
- 마지막 배치 뒤 검증 폐기·격리로만 소비된 카운터는 `BatchAttest`에 들어가지 않는다(배치는 기록 1건 이상). `BoxClose`의 `module_counters`(장치 하이브리드 서명)와 해당 검증 공개·격리 항목이 그 구간을 덮는다(PROTOCOL.md §7.2.1).
- 기록 해시를 담은 격리 항목(종류 3)은 그 기록의 카운터를 다시 적는다. 새로 소비하는 카운터가 아니라 기록을 재분류하는 표시다.
- 대기 구역 판정에서 명세가 직접 정하지 않은 칸은 보수적으로 정했다. 각인 없는 투표지인데 마지막 기록이 이미 격리됐으면, 그 기록의 투표지가 아직 격리 봉투로 가지 않은 것인지 저널에 오르지 않은 새 투표지인지 가를 수 없다. 새 투표지로 보고 기록 없는 격리를 쓰므로, 앞의 경우라면 `SpoiledEnvelopes`가 어긋나 `HOLD_REVIEW`가 된다. 검증 폐기된 투표지가 대기 구역에 남은 경우도 같다. 각인된 투표지가 어떤 기록과도 맞지 않는 사건(`QuarantineUnmatched`)은 저널만으로는 다시 알아낼 수 없어 그 재개의 메모리에만 남는다. 호스트가 사건 이벤트로 기록해야 하며, 사라진 투표지 사건은 저널에서 다시 계산된다.
- 순서가 바뀐 포트로 발급을 요청하면 그 모듈은 유닛이 받지 않은 카운터를 소비하고, 이후 그 모듈의 응답은 모두 `CounterGap`이 된다(모듈 사건, 장치 교체).
- 장치 키 보관(HSM)과 모듈 펌웨어(M8), 링크 전송, fsync, 인쇄는 범위 밖이다.

## 유도와 해시 규칙

| 값 | 규칙 |
|---|---|
| 합산 난수 | `r_j = Σ_c r_{c,j} (mod ℓ)` |
| 투함 ID | `SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_{c_1} ‖ … ‖ cid_{c_n})[0..24]`, 모듈 ID 오름차순 |
| 봉투 라벨(관외·재외) | `SHA3-512("ityv:envlabel:v1" ‖ 0x00 ‖ lab_{c_1} ‖ … )[0..24]` |
| 표 생성기 키 | `SHA3-512("ityv:ballotrng:v1" ‖ 0x00 ‖ device_seed ‖ 모듈마다 r_{c,0..k−1} ‖ cid_c ‖ lab_c)` |
| 비밀 i의 분산 스트림 | `fork("ityv:split:v1", i)`: `SHA3-512(key ‖ "ityv:fork:v1" ‖ 0x00 ‖ domain ‖ u64_be(i))` |
| 생성기 블록 | `SHA3-512(key ‖ u64_be(counter))` |
| 모듈 기록 서명 메시지 | `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`(최대 140바이트), purpose `module-record` |
| KEM 연관 데이터 | `election_id ‖ box_id ‖ commitments: Array<Point, 8> ‖ trustee_id ‖ 1u8 ‖ 0u32 ‖ 0u64` 정규 인코딩(PROTOCOL.md §9.6 개정) |
| 패드 구간(기록 n, 구성원마다) | `[n·b, n·b+32)` 전송 MAC 키, `[n·b+32, n·b+64)` 모듈 태그 키, `[n·b+64, n·b+64+len)` 평문 패드(`rules::PAD_*_OFFSET`) |
| 저널 head | 마지막 `JournalEntry` 객체의 §4 해시(첫 항목의 `prev_head`는 0) |

구성원 평문 `MemberShare`(0x0015)의 길이는 `16 + (4 + 32·s) + 1 + 24 + (1 [+ 24]) + 16 = 62 + 32·s [+ 24]`바이트다(`s` = 공유 비밀 수 = 모듈 수 × k + 1 [+ 1]; 라벨 24바이트는 관외 프로필의 모듈 챔버 구성원만). 패드 소비는 투표함에 하나로 `b = max_style len(MemberShare) + 64`이며 `ElectionConfig::pad_consumption`이 돌려준다. 기록 n의 패드 인덱스는 `n × b`다.

시험 구성: 정당 둘(n = 2), 모듈 5개(A·C 중립, J·P1·P2 자체), 투표양식 `P-4`(k = 1)와 `L-12`(k = 2), 참여 챔버당 신뢰기관 2명(정당 챔버 2-of-2, 나머지 1-of-2). 관내는 `s` = 6 / 11, 길이 254 / 414, `b = 478`. 관외는 `s` = 7 / 12, 길이 310 / 470, `b = 534`.

## 바이트 배치

| 객체 | 인코딩(§3 헤더 16바이트 뒤) |
|---|---|
| `Interpretation`(0x0101) | `election_id: Ident<64>` ‖ `ballot_style_id: Ident<64>` ‖ `option_index: u16` (최대 154바이트) |
| `VisitEnd`(0x0104) | `election_id: Ident<64>` ‖ `ballot_count: u8`(1–8) (최대 85바이트) |
| `ModuleIssue`(0x0103) | `module_id: Ident<64>` ‖ `chamber: u8`(1–7: P1–P4, J, A, C) ‖ `counter: u64`(≥ 1) ‖ `rand: Array<Scalar, 8>`(1개 이상) ‖ `cid: Token192` ‖ `lab: Option<Token192>` ‖ `tags: Array<[u8; 16], 8>` (최대 534바이트) |
| `JournalEntry`(0x0014) | `prev_head: Hash512` ‖ `kind: u8`(1–8) ‖ `record_hash: Hash512` ‖ `share_package_hash: Hash512`(기록이 아니면 0) ‖ `module_counters: Array<{module_id, counter}, 7>` ‖ `time_bucket: u64` (최대 753바이트) |

`JournalEntry`의 `record_hash`와 `module_counters`는 종류마다 뜻이 다르다(ENCODING.md §8.19 개정): 1 기록·2 검증 폐기는 그 표의 기록 해시와 소비한 카운터, 3 격리는 기록된 표면 그 기록 해시와 그 카운터, 기록 전이면 0과 소비한 카운터(재개의 기록 없는 격리는 빈 목록), 4 배치 마감은 배치의 `records_root`와 모든 모듈의 최고값, 5 투표함 마감은 `record_set_root`와 모든 모듈의 최고값, 6 각인 완료는 그 기록 해시와 그 카운터, 7 방문 결정과 8 라벨 출력은 방문 결정 다이제스트와 빈 목록(ADR-0021). 기록을 지목하는 3과 6은 카운터를 새로 소비하지 않는다. 이 판은 아직 방문 단위로 투입하지 않으므로(투입 기록마다 방문 하나) 종류 7·8을 쓰지 않고, 재개에서 만나면 `JournalCorrupt`다. `VisitEnd`는 객체와 디코더만 있다.

나머지 객체(`CastRecordBody`, `CastRecord`, `SharePackage`, `MemberShare`, `ChallengeOpening`, `BatchAttest`, `ScanCountAttestBody`, `BoxCloseBody`, `Slip`)는 `ityv-encoding`이 구현한다(ENCODING.md §8.6–§8.18).

## 호스트 계약

1. 모듈마다 `ModulePort`를 구현하고 구성의 모듈 순서(모듈 ID 오름차순)로 포트를 넘긴다. `issue(k, out)`은 그 표의 청크 수만큼 `rand`를 돌려준다. `seal_member`는 위 패드 구간 배치를 따르고, 패드가 소진되면 버퍼를 바꾸지 않고 `Exhausted`를 돌려준다. `check_batch`는 서명도 상태 변화도 없는 확인이고, `sign_batch`는 서명하면서 그 구간을 증명된 것으로 표시한다.
2. `JournalSink::append`는 항목과(기록이면) share 패키지를 안정 저장소에 쓴(fsync) 뒤에만 `Ok`을 돌려준다. `JournalSource::next_item`은 스트림 틀(`u32_be 길이 ‖ 객체`)을 벗겨 항목과 패키지를 넘긴다.
3. 배치 마감의 `host_head`는 저장 매체에서 다시 읽은 값이어야 한다. `OpenBox::journal_head`를 그대로 넘기면 VC-056 검사가 무의미해진다.
4. 시간 구간은 단조 비감소로 준다(역행은 `TimeRegression`; 스캔 카운터 본문의 구간도 포함). 서명 연산마다 새 32바이트 시드를 `Signer::new(key, seed)`로 준다.
5. 표가 오류로 끝나거나 값이 사라지면 `OpenBox::quarantine_in_flight`로 격리를 기록하고 투표지를 격리 봉투로 보낸다.
6. 다음 표 전에 `batch_due`를 확인해 배치를 닫고, `scan_count_due`면 스캔 카운터 본문을 만들어 참관인 서명을 받는다. 마감 전에 열린 배치를 닫는다.
7. 각인기가 인쇄를 마치면 `imprinted(open_box, sink, time_bucket)`를 부르고, `Done`이 돌아온 뒤에만 투표지를 함으로 떨어뜨린다. 오류면 떨어뜨리지 않고 `quarantine_in_flight`로 격리해 격리 봉투로 보낸다.
8. 재개 후 돌아온 `WaitingAction`대로 대기 구역의 투표지를 처리하고(낙하 / 격리 봉투), `PaperMissing`·`QuarantineUnmatched`는 사건 이벤트로 기록한다.
9. 투표양식 목록은 ID 바이트 오름차순으로 넘긴다(최대 4,096개). 구성은 그 슬라이스를 빌리기만 하므로 목록은 호스트 메모리에 있다(항목당 64비트 24바이트, 32비트 12바이트; 4,096개면 thumbv7em에서 48 KB).
10. 마감은 `prepare_close`(본문·장치 서명·저널 항목, 판정 반환) 뒤 같은 투표함의 토큰으로 `into_closed`를 부른다. 판정이 비어 있지 않으면 `HOLD_REVIEW`다.
11. `is_faulted()`가 참이면 장치를 교체한다.

버퍼 크기: 작업 영역 `BallotWork` 하나(약 35 KB), 빌드 scratch `scratch_len(신뢰기관 수)`(신뢰기관당 3,542바이트), share 패키지 ≤ 269,088, 기록 본문 ≤ 21,570, 기록 ≤ 22,582(증명 인코딩의 임시 공간을 겸한다), 배치 작업 `BATCH_WORK_LEN`(76,922: 모듈 서명 7개와 장치 서명 1개의 자리, 그 뒤 `BatchAttest` ≤ 39,394), 마감 작업 `CLOSE_WORK_LEN`(5,715), 검증 공개 ≤ 7,805, 슬립 ≤ 5,387, 재개 패키지 버퍼 ≥ 투표함의 가장 큰 share 패키지.

## 검증

```bash
cargo test --locked -p ityv-cunit                 # V1: 흐름·회계·재개·링크·규칙·속성 테스트, 문서 테스트(컴파일 실패 포함)
cargo kani -p ityv-cunit                          # V2: 순수 규칙 하네스
cargo mutants -p ityv-cunit --timeout 300         # V1: 변이 테스트
cargo build --locked -p ityv-cunit --target thumbv7em-none-eabihf   # no_std 빌드
```

시험은 결정적 모의 모듈(SHA3 패드 스트림, 일회성 MAC 태그, 모듈별 기록·배치 키, 오동작 스위치)과 메모리 저널로 관내·관외 흐름 전체를 돌린다.

| 파일 | 내용 |
|---|---|
| `tests/flow.rs` | 공개 검증기의 검사(추적코드, 장치·모듈 기록 서명, OR 증명), 신뢰기관의 검사(패드·KEM 복호, 전송 태그, 정족수로 모든 비밀 복원과 검증 공개값의 일치, 정당 챔버 하나나 J가 빠진 집합의 실패; 정당 2·3·4, 최대 구성인 모듈 7개·챔버 8개 포함), 모듈 태그 `tag_{c,i}`의 신뢰기관 측 검증(VC-022), KEM 연관 데이터 변조 시 복호 실패, 청크 수가 다른 투표양식의 패드 구간 분리, 포트 순서 오류, 다른 키의 기록 서명, 종료·실패 경로의 작업 영역 소거 |
| `tests/boxes.rs` | 저널 사슬, 카운터 되감기·재사용·건너뛰기, 배치 범위·거부·연쇄 없음·서명 검증, 전제 검사 순서, 고장 고정, 스캔 카운터, 격리 회계(기록된 표·각인 실패·저널 실패), 마감 불변식 하나씩, 방문 수의 양쪽 상한, 관외 봉투·스티커 수와 프로필, 다른 투표함의 토큰 |
| `tests/resume.rs` | 항목 종류마다 재개한 투표함과 원래 투표함의 동일성과 이어서 쓰기, 대기 구역 판정의 네 경우와 두 번째 전원 상실, 사라진 투표지 사건의 저널 재계산, 각인 항목 쓰기 실패, 손상·불일치 저널 거부(검사마다 하나씩) |
| `tests/styles.rs` | 4,096개 투표양식 구성에서 처음·가운데·마지막 투표양식 조회와 투표, 모르는 투표양식, 정렬 안 됨·중복·초과 거부, 구성 크기 |
| `tests/link.rs` | 링크 객체 배치와 디코더(`VisitEnd`, 저널 종류 1–8, 최대 길이), 구성 규칙(정당 챔버 모듈 필수·위임 금지, n 밖의 정당 챔버, 모듈 8개 거부), 계수 규칙 예, 속성 테스트 |
| `tests/surface.rs` | 표시 문자열, 비밀을 담은 값의 `Debug`, 접근자, 경계값 |

Kani 하네스(9개): 선택지 범위, 카운터 판정, 네 번의 발급에 걸친 카운터 최고값(되돌아가지 않고 같은 카운터를 두 번 받지 않음), 패드 소비·인덱스 산술, 모듈 배치 서명 규칙, 배치·스캔 카운터 시점, VC-038 판정 전체(투표지 사건, 방문·봉투·스티커 수 포함)를 128비트 산술로 독립 기술한 명제와 대조하고, 재개의 대기 구역 판정을 독립적으로 적은 3×5 표와 대조한다.

### 변이 테스트 결과

정당 챔버(ADR-0019)와 방문 수·봉투·스티커 마감 검사(ADR-0021) 반영 후(2026-11-01), 바뀐 파일만 두 번에 나눠 돌렸다(`-f`, `--timeout 300`). `config.rs`·`link.rs`·`rules.rs`·`error.rs`·`ballot.rs`: 변이 411개 중 잡힘 287, 빌드 불가 124, 놓침 0(17분). `boxstate.rs`: 변이 149개 중 잡힘 114, 빌드 불가 35, 놓침 0(6분). 바뀌지 않은 `port.rs`·`rng.rs`는 직전 전체 실행(변이 569개, 놓침 0)의 결과가 그대로다. 빌드 불가는 대부분 비공개 타입의 값을 기본값으로 바꾸는 변이다. 알려진 동치 변이는 없다.

### `Drop` 소거의 시험

`.cargo/mutants.toml`은 `impl Drop` 본문을 변이에서 뺀다(값이 사라진 뒤에는 관찰할 수 없다). 그래서 소거하는 `Drop`은 모두 한 줄로 시험된 메서드를 부른다.

| `Drop` | 부르는 메서드 | 직접 시험 |
|---|---|---|
| `BallotWork` | `zeroize` | `ballot::tests::zeroize_clears_every_field`, `is_clear_sees_every_field_on_its_own`; 통합 테스트가 종료·실패 경로마다 `is_clear()`를 확인 |
| 작업 영역 보호자(`WorkGuard`, 비공개) | `BallotWork::zeroize` | `ballot::tests::guard_wipes_on_take_and_on_drop`이 보호자를 실제로 drop한 뒤 작업 영역을 읽는다 |
| `ImprintCommand` | `zeroize` | `ballot::tests::imprint_command_zeroizes_and_redacts` |
| `DeviceRng` | `wipe` | `ballot::tests::durable_keeps_only_the_imprint_secrets` 등(소거된 생성기는 0 키의 스트림을 낸다) |
| `ModuleIssue` | `wipe` | `link::tests::wipe_clears_the_private_part` |

## 테스트·하네스 코드의 lint 완화

| 파일 | 완화 | 사유 |
|---|---|---|
| `tests/flow.rs`, `tests/boxes.rs`, `tests/link.rs`, `tests/resume.rs` | `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `too_many_lines`, `missing_panics_doc`, `many_single_char_names` | 테스트는 "반드시 성립한다"를 unwrap·panic·인덱싱으로 표현하고 작은 시험 크기에 산술·캐스팅을 쓰며, 흐름 하나를 한 함수에서 끝까지 검사한다 |
| `tests/surface.rs` | 위 집합에서 `cast_possible_truncation` 제외 | 같은 사유 |
| `tests/styles.rs` | `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `missing_panics_doc` | 같은 사유 |
| `tests/common/mod.rs` | `dead_code`, `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `missing_panics_doc`, `missing_errors_doc`, `too_many_lines`, `struct_excessive_bools` | 모든 테스트 바이너리에 컴파일되지만 각 바이너리는 일부만 쓴다; 모의 모듈의 오동작 스위치는 서로 독립인 불리언이다 |
| `kani/proofs.rs` | `clippy::indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_lossless`, `missing_panics_doc` | 하네스는 유계 기호 입력의 기대값을 인덱싱·`as`·무검사 산술로 적고, 패닉·오버플로는 Kani가 직접 보고한다 |
| `src/` | 없음 | 단위 테스트(`#[cfg(test)]`)의 unwrap·expect·panic·인덱싱은 워크스페이스 `clippy.toml`이 테스트 함수 안에서만 허용한다 |
