# ityv-cunit

> English summary: The trusted core of the casting scanner's commitment unit (ADR-0017 with its amendments, ADR-0019, ADR-0021). A `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate that turns one voter's visit (one to eight interpreted ballots) into every object the scanner emits. Per ballot: the generalized Pedersen commitments and their 1-of-(m+2) OR proof, the share package for the trustees (each secret split over the per-party access structure, sealed per member through the chamber module's one-time pad or the hybrid KEM), the device and module record signatures (verified against genesis keys) and the tracking code. Per visit: each position's bound entry (journal kind 9: its record hash and the counters it consumed) made durable before the next ballot, so a resume always knows every consumed counter; the cast-or-check decision, which exists only once every position carries its device and module record signatures (VC-068); the positions' decision entries and the decision entry with one fsync, before any paper moves (VC-054); per position in order the imprint command and imprint entry, the imprint-failure quarantine, or the signed opening of a checked ballot; out of district one label sticker with every envelope label of the visit; one slip listing the visit's cast tracking codes under one signature. A position's finished record and share package go to a host staging port as soon as it is bound; the unit keeps their hashes and re-checks the staged bytes before journaling or publishing them, so a full eight-ballot visit adds about 26 KB to the 30 KB ballot work area. The crate also keeps the box state: counter high-water marks, the sealed journal chain, batch attestations, scan-count bodies, a fault latch on a journal mismatch, the box close with the VC-038 verdict, and resume from the journal after a power loss with the four-case rule of PROTOCOL §7.3, asking each module with the dry-run batch check whether the ballot in flight consumed a counter before its bound entry, so the close's counter equation holds after any resume. Between visits it answers observers' field attestation challenges (ADR-0023): it checks the observer's signature against the station's token list, asks every chamber module for its signed statement, and signs the attestation and its QR summary with the device's attestation key, without touching any ballot or box state. Ordering rules are types and compile-fail doctests.

## 무엇인가

커밋먼트 유닛은 투함 스캐너의 검증 부품이다(PROTOCOL.md §7.1, CONSTITUTION §4). 이 크레이트는 그 TCB 핵심이며 명세는 `docs/spec/PROTOCOL.md` §7–§10, `docs/spec/ENCODING.md` §8.6–§8.19, `docs/adr/ADR-0017-cunit-crate.md`(개정 포함), ADR-0019, ADR-0021이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

| 모듈 | 내용 | 명세 |
|---|---|---|
| `config` | genesis에서 호스트가 만드는 선거 구성: 투표양식(최대 4,096개, ID 오름차순, 이진 탐색), 모듈(챔버당 하나, 최대 7개; 정당 챔버 P1…Pn(2 ≤ n ≤ 4)은 자체 모듈만 쓰고 위임하지 않으며 n 밖의 정당 챔버는 모듈도 구성원도 없음, J·A·C는 자체 또는 중립 위임, N은 없음)과 모듈 공개키(Ed25519 기록 키, 하이브리드 배치 키), 신뢰기관 명부, 접근구조, `VOTER_CODE`. 투표함 단위 패드 소비 `b`를 검증 시 고정한다 | ADR-0017 §2, §12, 개정 1·10·16·17, ADR-0019 |
| `link` | 해석 유닛 링크 `Interpretation`(0x0101)과 방문 끝 알림 `VisitEnd`(0x0104), 현장 증명 도전값 `AttestChallenge`(0x0105), 모듈 링크 `ModuleIssue`(0x0103), 봉인 저널 `JournalEntry`(0x0014, 종류 1–9), 방문 결정 다이제스트 `visit_digest` | ENCODING.md §8.19, ADR-0021 |
| `port` | 호스트 trait `ModulePort`(발급 `issue(k)`, 패드 봉인, 기록 서명, 배치 구간 확인 `check_batch`, 배치 서명, 현장 증명 진술 `attest`)·`JournalSink`(내구 추가와 미뤄 쓰기)·`JournalSource`(재개 시 읽기)·`StagingPort`(방문의 기록·share 패키지 보관), 모듈의 서명 규칙 `module_may_sign_batch`(VC-021)·`module_may_sign_record`(카운터당 본문 하나, VC-068) | ADR-0017 §3, §7–§8, 개정 6·11·18 |
| `rng` | SHA3-512 카운터 모드 생성기 `DeviceRng`(표 생성기: 장치 시드와 모든 모듈의 비공개 기여로 시드, 작업 영역 안에서 재시드; 서명 생성기: 장치 시드) | ADR-0017 §12 |
| `ballot` | 표 작업 영역 `BallotWork`, 위치별 typestate `Interpreted → Issued → Committed → Built → bind`, share 패키지·투함 기록 | PROTOCOL.md §7.3 1–5단계, §9, 개정 3–5·18 |
| `visit` | 방문 작업 영역 `VisitWork`, 방문 typestate `ReadyVisit → DecidedVisit → ProcessedVisit`, 결정과 저널, 각인 명령, 확인 공개, 라벨 스티커, 슬립, 방문 포기 | PROTOCOL.md §7.3 6–11단계, §7.7, §8, ADR-0021, 개정 18 |
| `boxstate` | `OpenBox`: 카운터 최고값, 저널 사슬, 배치 마감(`BatchAttest`), 스캔 카운터 본문, 고장 고정, 마감(`BoxCloseBody` + 장치 서명 + VC-038 판정 + 투표함에 묶인 토큰), `ClosedBox` | PROTOCOL.md §7.2.1, §7.8, §10.2, 개정 5–9·19·22 |
| `resume` | 저널에서 투표함과 마지막 방문의 상태를 복원하고, 모듈에 묶이기 전 발급이 있었는지 묻고, 재개 판정대로 항목을 덧붙임 | PROTOCOL.md §7.3 재개, §7.8, VC-069, 개정 20·23 |
| `attest` | 현장 증명 `Attestor`: 참관인 도전값 확인(토큰 목록, 서명, 열린 방문 없음, 30초 간격), 모듈 진술 확인, 증명 본문·`DeviceAttestation`·`AttestationSummary` 작성과 서명 | PROTOCOL.md §7.9, ENCODING.md §8.19·§8.28–§8.30, ADR-0023, VC-088, 개정 24 |
| `rules` | 순수 규칙(Kani 대상): 선택지 범위, 카운터 최고값, 패드 소비·인덱스, 배치·스캔 카운터 시점, 마감 불변식, 재개 판정 `resume_plan` | §7.2, §7.3, VC-021, VC-034, VC-038, VC-052, VC-069 |

보장하는 것:
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음. 워크스페이스 lint 집합을 그대로 쓰며 `src/`에는 `#[allow]`·`#[expect]`가 하나도 없다(CONSTITUTION §1.1).
- 해석 유닛에서는 `Interpretation`과 `VisitEnd` 객체만 받는다. 다른 선거, 모르는 투표양식, `t > m+1`, 장수 0이나 9 이상은 거부한다(ITYV-BEH-013).
- 방문은 한 번에 하나, 방문 안의 위치도 한 번에 하나만 처리한다. 첫 해석이 방문을 열고, 배치에 방문 하나(8건)를 더할 자리가 없으면 거부한다(`BatchFull`). 위치는 8개까지다(`VisitFull`). 배치 마감, 스캔 카운터 본문, 마감은 방문과 방문 사이에서만 나오므로(`VisitOpen`) 배치가 증명하는 모든 카운터는 이미 저널에 있는 위치의 것이고 스캔 카운터의 수량과 head는 뒤로 가지 않는다(VC-052).
- 묶음 항목(ADR-0021 결정 10, 개정 23): `Ballot::bind`는 기록과 share 패키지를 보관 포트에 넘긴 뒤 묶음 항목(9, 기록 해시와 그 표가 소비한 카운터, 패키지 없음)을 내구화하고 나서야 위치를 센다. 카운터는 이 항목이 소비하고 뒤의 위치 항목·격리·각인 항목은 같은 카운터를 되풀이한다.
- 결정 전 결속(VC-068): 넣기·확인 결정은 `ReadyVisit`에만 있고, `ReadyVisit`은 `VisitEnd`의 장수가 묶인 위치 수와 같고 진행 중인 위치가 없을 때만 `OpenBox::end_visit`이 만든다. 묶인 위치는 장치와 모든 모듈의 기록 서명을 마친 것이다. 모듈은 한 카운터에 본문 해시 하나만 서명하므로(`module_may_sign_record`) 결정 뒤 기록을 바꿀 수 없다. 컴파일 실패 문서 테스트가 "묶이지 않은 표에 결정 없음", "결정 전 각인 없음", "처리 전 스티커·슬립 없음", "`ReadyVisit`을 만들 수 없음"을 고정한다.
- 저널 순서(VC-069, VC-054): 결정은 위치 항목(넣는 표 1, 확인하는 표 2, 묶음 항목과 같은 기록 해시·카운터)을 위치 순으로 미뤄 쓰고(`append_deferred`), 방문 결정 항목(7, 다이제스트 `SHA3-512("ityv:visit:v1" ‖ 0x00 ‖ n ‖ (kind ‖ record_hash)…)`, 카운터 없음)을 써서 한 번에 내구화한 뒤에만 `DecidedVisit`을 만든다. 넣는 표의 share 패키지는 보관 포트에서 다시 읽어 묶을 때의 해시와 대조한 뒤에만 기록 항목과 함께 쓴다(`StagedMismatch`). 각인 명령·각인 완료(6)·각인 실패 격리(3)·확인 공개는 `DecidedVisit`에서 위치 순서로만 나오고(`WrongPosition`), 각인 완료 항목이 내구화된 뒤에만 종이가 움직인다.
- 관외·재외 방문은 넣은 표(각인 완료, 격리되지 않음)가 있으면 스티커 하나에 그 `env_label` 목록을 싣고(`LabelCommand`), 인쇄 뒤 라벨 출력 항목(8, 결정 다이제스트, 카운터 없음)을 쓴다. 스티커를 뽑지 못하면 그 방문의 넣은 기록을 모두 격리한다. 스티커가 남아 있는 동안 슬립과 방문 종료는 없다(`LabelPending`).
- 슬립은 방문당 하나이고 넣은 표의 추적코드를 위치 순으로 담아 하이브리드 서명 한 번으로 서명한다(VC-070). 넣은 표가 없으면 없다(`NothingCast`).
- 모듈 카운터는 모듈별 최고값 + 1일 때만 받는다. 최고값 이하는 `CounterRegression`, 건너뛰기는 `CounterGap`이며 둘 다 최고값을 바꾸지 않는다(개정 2). 패드 인덱스는 `카운터 × b`여야 하고(VC-034) `b`는 투표함에 하나다(개정 1).
- 모듈의 기록 서명과 배치 서명은 설정의 genesis 공개키로 검증한 뒤에만 객체에 넣는다(`RecordSignature`, `BatchSignature`).
- 배치 마감은 모든 전제(투표함 상태, 열린 방문, 호스트가 저장 매체에서 다시 읽은 head, 빈 배치, 포트 수, 시간 구간, 작업 버퍼)를 먼저 검사한다. 그다음 모든 모듈에 구간 확인을 묻고, 거부 목록을 넣은 최종 본문에 동의한 모듈마다 한 번씩 서명을 받는다(개정 6).
- 저널 head가 다르면 투표함은 고장 상태로 고정되어 새 표, 배치, 스캔 카운터, 마감 서명을 모두 거부한다(VC-056, 개정 7).
- 마감은 프로필과 봉투 수를 대조하고(관외·재외는 봉투·스티커 수와 회송용 봉투 교부·빈 봉투 회수 수가 필수, 관내는 없음; `EnvelopeCountProfile`) VC-038 전체를 판정한다: 관내 `paper_count == record_count + no_record_count`, 관외·재외 `paper_count == 0`·`sticker_count == visit_count`·`envelope_count == 교부 − 빈 봉투 회수`, 모든 함에서 `visit_count ≤ record_count ≤ 8·visit_count`. `visit_count`는 넣은 표가 하나 이상 남은 방문 수다. 마감 본문은 사람이 센 폐기·격리 봉투 수(`spoil_envelope_count`)도 실어 장부 쪽에서 `== challenge_count + quarantine_count`를 확인할 수 있게 한다(ADR-0025 공백 5). 마감 토큰은 서명한 `BoxCloseBody`의 해시를 담아 그 투표함만 닫는다.
- 방문 포기(`OpenBox::abandon_visit`): 결정 전이면(결정이 위치 항목 일부를 쓴 뒤 실패한 경우 포함) 묶인 위치마다 그 기록 해시로 격리(3, 묶음 항목의 카운터)하고, 이어서 묶이기 전의 진행 중인 표가 카운터를 소비했으면 기록 없는 격리(3, 해시 0, 소비 카운터)를 쓴다. 결정 후면 각인 안 된 넣는 표와(관외에서 스티커 항목이 없으면) 넣은 표 전부를 기록 해시로 격리한다. 카운터를 하나도 소비하지 않은 표는 유권자에게 돌려준다.
- 현장 증명(VC-088): `Attestor::attest`는 모듈에 묻기 전에 도전값의 선거, 열린 방문 없음, 직전 증명 뒤 30초(호스트의 단조 초 값, 믿지 않으며 간격 제한에만 쓰고 어디에도 쓰지 않음), 참관인이 투표소 토큰 목록에 있음, 참관인 서명(`attest-challenge`, `election_id ‖ station_id ‖ observer_id ‖ nonce`)을 확인한다. 하나라도 어긋나면 아무 모듈도 묻지 않고 간격 시계도 그대로다. 모듈 진술은 genesis의 모듈 증명 키로 확인한 뒤에만 싣는다(`ModuleStatement`). 투표함은 읽기만 하며 증명에는 투표에 관한 값이 없다.
- 증명·비밀분산의 난수는 장치 시드와 모든 모듈 기여로 시드된 생성기에서만 나오므로 장치 혼자도, 모듈 하나도 그 난수를 정하지 못한다. 증명 생성은 `ityv-crypto`의 상수 시간 `prove_into`다(참 선택지로 분기하지 않음).

## 작업 영역 계약

비밀은 두 곳에만 있다(개정 3·4·18). 크기는 64비트 기준이며 `visit::memory` 단위 테스트가 잰다.

- `BallotWork`(30,264바이트, 생성자 `const`): 표 하나를 만드는 동안의 모든 비밀과 증명. 위치마다 `OpenBox::interpret(link, &mut work)`로 빌려주며, 방문의 위치들이 차례로 다시 쓴다. 선택 인덱스, 모듈 기여(카운터, `r_{c,j}`, `cid_c`, `lab_c`, 태그), 투함 ID, 봉투 라벨, 합산 난수, 표 생성기, 공유 비밀 값, 구성원 share와 `MemberShare` 평문, 증명.
- `VisitWork`(24,304바이트): 묶인 위치마다 결정과 확인 공개에 필요한 것만(선택, 투함 ID, 봉투 라벨, 합산 난수, 모듈별 난수와 `cid_c`; 위치당 약 2.3 KB)과 확인 공개 작성 공간. 첫 위치를 묶을 때 비우고 받으며, 그 뒤의 위치는 같은 방문의 것이어야 한다(`StaleVisit`).
- 상자 안 방문 장부(2,256바이트): 위치마다 투표양식, 소비 카운터, 추적코드, 보관한 기록·share 패키지의 해시, 결정, 처리 상태. 8장 방문이 한 장 처리 공간에 더하는 것은 합쳐 26,584바이트다(목표 64 KiB).
- 기록(≤ 22,582바이트)과 share 패키지(≤ 269,088바이트)는 묶는 즉시 `StagingPort`로 넘어간다. 유닛은 결정 때 패키지를, 공개 때 기록을 보관 포트에서 다시 읽어 해시를 대조한다.
- 소거 시점: 표가 작업 영역을 빌릴 때, share 봉인을 마쳤을 때, 표를 묶을 때(작은 비밀을 방문 작업 영역으로 옮긴 뒤), 전이가 실패할 때, 표 값이 버려질 때, 방문 상태 값(`ReadyVisit`·`DecidedVisit`·`ProcessedVisit`)이 버려지거나 방문이 끝날 때, 확인 공개를 쓴 뒤(작성 공간), 작업 영역 자체가 drop될 때. `BallotWork::is_clear()`와 `VisitWork::is_clear()`로 확인한다.
- 증명은 영지식이고 공개되므로 비밀이 아니다. 상태가 증명을 들고 다니지 않도록 표 작업 영역에 두며, 기록 본문을 쓰는 동안 인코딩은 호스트의 기록 버퍼에 잠시 둔다.
- `ityv-encoding`의 비밀 담는 값(`Scalars`, `MemberShare`, `ModuleOpening`, `ChallengeOpeningBody`)은 drop 때 스스로 지워진다(개정 15).

## 재개

전원 상실 뒤 `OpenBox::resume(config, source, sink, modules, inputs, package_buf)`는 `JournalSource`가 처음부터 읽어 주는 저널로 투표함을 다시 만들고, 모듈 포트에 한 번씩 묻고, `(OpenBox, ResumePlan)`을 돌려준다(개정 20·23).

- 항목마다 검사한다: 0에서 시작하는 head 사슬, 디코딩, 시간 구간의 단조성, 기록 항목 바로 뒤에만 share 패키지가 있고 그 해시가 맞는지, 소비한 카운터가 모듈마다 최고값 + 1인지, 방문 순서(VC-069): 묶음 항목(최대 8, 기록 해시 0 아님, 같은 기록 두 번 없음, 카운터 소비) → 묶인 위치마다 순서대로 같은 기록 해시와 카운터의 위치 항목(1·2) → 그 위치 항목들의 다이제스트를 담은 방문 결정 항목 → 넣는 위치마다 위치 순서의 각인 완료(6) 또는 그 기록을 지목하는 격리(3, 같은 카운터) → 관외면 결정 다이제스트를 되풀이하는 라벨 출력(8). 방문 항목(7·8)에는 카운터가 없다. 결정되지 않은 위치 뒤에는 묶음 항목(위치 항목 전), 위치 항목, 결정, 그 위치를 지목하는 격리만 올 수 있고, 격리가 시작되면 남은 위치를 모두 지목할 때까지 다른 항목이 오지 않는다. 배치 마감의 root와 카운터, 투표함 마감 뒤 항목 없음. 하나라도 어긋나면 `JournalCorrupt`, 마감으로 끝나면 `BoxClosed`다.
- 복원하는 것: head, 카운터 최고값, 열린 배치, 증명된 카운터, 배치 번호, 누적 수량(방문 수 포함), 투표지 사건 수, 마지막 방문의 상태. 결정된 방문이 무언가를 남긴 채(넣는 위치 미처리, 관외 스티커 항목 없음) 다른 방문이나 배치가 뒤따르면 이전 재개에서 투표지가 사라진 것이므로 사건 하나로 센다.
- 모듈에 묻기: 모듈마다 `check_batch`(서명·상태 변화 없음)로 증명되지 않은 카운터가 `최고값 + 1`까지인지 묻는다. 그렇다면 묶음 항목을 쓰기 전에 멈춘 표(진행 중인 표는 하나뿐이다)가 그 카운터를 받은 것이다. 앞선 배치를 거부해 어느 쪽으로도 답할 수 없는 모듈은 발급하지 않았다고 본다.
- 재개 판정(`rules::resume_plan`, PROTOCOL §7.3의 네 경우): 입력은 마지막 방문의 상태, 사무원 2인과 참관인 2인이 확인한 대기 구역(`WaitingArea`: 남은 장수, 맨 앞의 각인 여부, 스티커 출력 여부), 모듈의 답.
  1. 결정 전 멈춤: 아직 격리되지 않은 묶인 위치는 기록 해시로 격리하고 그 종이는 격리 봉투로 보낸다. 묶인 위치 뒤의 첫 종이는, 모듈이 발급했다고 답하면 그 카운터를 실은 기록 없는 격리로 남기고 격리 봉투로 보낸다(종이가 없으면 항목은 쓰고 사건). 나머지 종이는 카운터를 소비하지 않았으므로 유권자에게 돌려준다(`PaperAction::Return`). 맨 앞에 각인이 있거나 스티커가 나왔으면 묶이지 않은 종이도 모두 기록 없이 격리하고 사건으로 센다. 묶인 위치보다 종이가 적어도 사건이다. 마지막 방문이 끝났는데 종이가 남았으면 새 방문의 묶이지 않은 종이다.
  2. 결정 후 멈춤: 남은 종이는 마지막 위치들이다. 확인한 종이는 폐기 슈트로, 맨 앞 넣는 종이에 각인이 있으면 각인 항목을 (없을 때만) 덧붙이고 투입, 그 밖의 넣는 종이는 기록 해시로 격리한다.
  3. 관외에서 스티커 항목이 없으면 라벨을 다시 뽑을 수 없으므로 그 방문의 넣은 기록을 모두 격리하고 반환 트레이도 격리 봉투로 보낸다.
  4. 종이가 저널과 맞지 않으면(넣는 종이가 사라짐, 처리된 종이가 맨 앞 뒤에 남음, 각인 여부가 항목과 맞지 않음, 종이가 남았는데 스티커가 나옴) 사건으로 세고 아무것도 쓰지 않으며 종이는 보류한다.
  덧붙이는 항목은 `inputs.time_bucket`을 쓴다. Kani 하네스가 8위치까지 모든 입력과 모듈의 두 답에 대해 판정이 전부 정의되고, 경우 1은 격리되지 않은 묶인 위치를 모두 격리하며 모듈이 발급했으면 그 카운터를 반드시 저널에 싣고 카운터를 소비하지 않은 묶이지 않은 종이만 돌려주며, 경우 2·3을 적용하면 넣는 위치가 모두 처리되고 관외에서 스티커 없이 넣은 채 남는 기록이 없음을 증명한다.
- 그래서 재개 뒤에도 모듈마다 `최고값 == 기록 + 검증 + 격리`다(마감 불변식의 카운터 등식).
- 재개 직후에는 스캔 카운터가 바로 기한이 된다.

## 남은 명세 편차와 한계

- 소거의 연역 증명(V3, VC-020)은 미해결이다. 컴파일러가 이동 때 남기는 스택 사본은 Rust에서 보장해 지울 수 없다.
- **답할 수 없는 모듈.** 앞선 배치를 거부해 증명되지 않은 카운터가 남은 모듈은 재개 때 구간 확인으로 묶이기 전 발급 여부를 답할 수 없다. 유닛은 발급하지 않았다고 보며, 실제로 발급했으면 그 모듈의 다음 발급이 `CounterGap`으로 거부되어 장치를 교체한다. 경우 4(맞지 않는 종이)에서도 아무것도 쓰지 않으므로 같은 일이 생길 수 있다.
- 결정 후 멈춘 방문에서 남은 확인 위치는 투함 ID가 영속되지 않으므로 검증 공개를 만들 수 없다. 기록 상태는 `CHALLENGED_SPOILED`로 남고 공개만 빠지며, 호스트가 사건 이벤트로 남기고 유권자는 새 투표지로 다시 확인할 수 있다(FAILURE_CASES T3c, 받아들임).
- 경우 4의 사건과, 새 방문의 종이 가운데 각인된 것이 있는 사건은 저널에 남지 않는다. 앞의 것은 그 방문 뒤에 다른 항목이 오면 다음 재개가 다시 세지만, 뒤의 것은 그 재개의 메모리에만 있다. 호스트가 사건 이벤트로 기록해야 한다.
- 마지막 방문이 끝났는데(넣는 위치가 모두 처리됨) 관내에서 종이가 남았을 때, 그 종이가 마지막 확인 위치들인지 새 방문의 종이인지는 저널로 가를 수 없다(확인 위치는 처리 항목이 없다). 남은 장수가 끝의 확인 위치 수 이하면 확인 위치로 본다. 틀리면 폐기 봉투 수가 어긋나 `HOLD_REVIEW`가 된다(FAILURE_CASES T4c, 받아들임).
- 투표함 마감의 `record_set_root`는 호스트가 저널에서 계산해 넘기고 유닛은 그 값에 서명한다(개정 9). 공개 검증기가 공표된 기록과 배치 root로 대조한다(VC-027).
- 마지막 배치 뒤 검증 폐기·격리로만 소비된 카운터는 `BatchAttest`에 들어가지 않는다. `BoxClose`의 `module_counters`와 해당 항목이 그 구간을 덮는다(PROTOCOL.md §7.2.1).
- 증명 생성의 사전 계산(P6, `ityv_crypto::ProofPrecomputation`)은 이 유닛에서 쓰지 않는다(ADR-0020 결정 11). 증명 난수는 모듈 기여로 시드되므로(개정 4, §12) 모듈 발급 전에는 뽑을 수 없고, 지연보다 보안을 택했다. 모듈이 다음 표의 기여를 미리 발급하는 방식은 M8에서 하드웨어 실측 뒤에 평가한다.
- 현장 증명의 부팅 측정값(부팅 횟수, 이미지 목록)과 장치 증명 키는 호스트(부트 ROM)가 넘기는 대로 믿는다. 유닛이 확인하는 것은 목록의 형식(1–16개, 식별자 순)뿐이며, 측정의 정직성은 부트 ROM과 기기 고유 비밀에 달려 있다(PROTOCOL §7.9 7항, M8).
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
| `JournalEntry`(0x0014) | `prev_head: Hash512` ‖ `kind: u8`(1–9) ‖ `record_hash: Hash512` ‖ `share_package_hash: Hash512`(기록이 아니면 0) ‖ `module_counters: Array<{module_id, counter}, 7>` ‖ `time_bucket: u64` (최대 753바이트) |

`JournalEntry`의 `record_hash`와 `module_counters`는 종류마다 뜻이 다르다(ENCODING.md §8.19 개정): 9 묶음은 그 표의 기록 해시와 소비한 카운터, 1 기록·2 검증 폐기는 같은 기록 해시와 묶음 항목의 카운터, 3 격리는 묶인 표면 그 기록 해시와 그 카운터, 묶이기 전이면 0과 소비한 카운터(소비가 없으면 빈 목록), 4 배치 마감은 배치의 `records_root`와 모든 모듈의 최고값, 5 투표함 마감은 `record_set_root`와 모든 모듈의 최고값, 6 각인 완료는 그 기록 해시와 그 카운터, 7 방문 결정과 8 라벨 출력은 방문 결정 다이제스트와 빈 목록(ADR-0021). 카운터를 소비하는 것은 9와 기록 없는 3뿐이고, 1·2, 기록을 지목하는 3, 6은 묶음 항목의 카운터를 되풀이한다. 한 방문의 항목은 묶음(9) n개, 위치 항목(1·2) n개, 방문 결정(7), 처리 항목(6·3), 관외면 라벨 출력(8) 순이다.

나머지 객체(`CastRecordBody`, `CastRecord`, `SharePackage`, `MemberShare`, `ChallengeOpening`, `BatchAttest`, `ScanCountAttestBody`, `BoxCloseBody`, `Slip`)는 `ityv-encoding`이 구현한다(ENCODING.md §8.6–§8.18).

## 호스트 계약

1. 모듈마다 `ModulePort`를 구현하고 구성의 모듈 순서(모듈 ID 오름차순)로 포트를 넘긴다. `issue(k, out)`은 그 표의 청크 수만큼 `rand`를 돌려준다. `seal_member`는 위 패드 구간 배치를 따르고, 패드가 소진되면 버퍼를 바꾸지 않고 `Exhausted`를 돌려준다. `sign_record`는 카운터당 본문 해시 하나만 서명한다(`module_may_sign_record`). `check_batch`는 서명도 상태 변화도 없는 확인이고, `sign_batch`는 서명하면서 그 구간을 증명된 것으로 표시한다.
2. `JournalSink::append`는 그 항목과 앞서 미뤄 쓴 항목 모두가 안정 저장소에 쓰인(fsync) 뒤에만 `Ok`을 돌려준다. 묶음 항목도 이것으로 쓰므로 방문은 위치마다 한 번, 결정에 한 번 fsync한다. `append_deferred`는 기다리지 않고 쓴다(기본 구현은 `append`). `JournalSource::next_item`은 스트림 틀(`u32_be 길이 ‖ 객체`)을 벗겨 항목과 패키지를 넘긴다.
3. `StagingPort`는 방문이 끝날 때까지 위치마다 `CastRecord`와 `SharePackage`를 보관하고 요청하면 되돌려준다. 유닛은 돌려받은 바이트를 해시와 대조한다.
4. 방문: 표마다 `interpret → issue → commit → build → bind(…, sink, staging, visit, 시간 구간)`(묶음 항목이 내구화된 뒤에만 다음 해석을 넘긴다), 해석 유닛의 `VisitEnd`로 `end_visit`, 유권자의 선택으로 `decide`(그 뒤에만 종이가 움직인다), `current()`가 가리키는 위치마다 넣는 표는 `imprint_command` → 인쇄 → `imprinted`(각인 실패면 `imprint_failed`, 종이는 격리 봉투), 확인하는 표는 `open_challenge`(종이는 폐기 슈트), 그다음 `finish_positions`, 관외면 `label_command` → 인쇄 → `label_printed`(실패면 `label_failed`, 반환 트레이를 격리 봉투로), `slip`, `finish`. 공개할 기록은 `record(...)`로 대조된 바이트를 받는다.
5. 방문을 끝낼 수 없으면(유권자가 결정하지 않고 떠남, `VisitCountMismatch`, 위치 실패, 결정 실패, 방문 상태 값을 잃음) 사무원 2인과 참관인 2인이 확인한 뒤 `OpenBox::abandon_visit`을 부르고 남은 종이를 격리 봉투로 보낸다(확인 위치의 종이는 폐기 슈트).
6. 배치 마감의 `host_head`는 저장 매체에서 다시 읽은 값이어야 한다. `OpenBox::journal_head`를 그대로 넘기면 VC-056 검사가 무의미해진다.
7. 시간 구간은 단조 비감소로 준다(역행은 `TimeRegression`). 서명 연산마다 새 32바이트 시드를 `Signer::new(key, seed)`로 준다.
8. 다음 방문 전에 `batch_due`를 확인해 배치를 닫고, `scan_count_due`면 스캔 카운터 본문을 만들어 참관인 서명을 받는다. 마감 전에 열린 배치를 닫는다.
9. 현장 증명은 방문과 방문 사이에 `Attestor::attest`로 한다. 도전값 객체(확인 카드는 해석 유닛이, 토큰은 호스트가 같은 네 값으로 만든다)와 경로, 부트 ROM의 측정값, 단조 초 값, 시간 구간, 구성 순서의 모듈 포트, 장치 증명 키의 `Signer`, `ATTEST_WORK_LEN` 작업 버퍼를 넘긴다. 돌아온 `DeviceAttestation`은 다음 송신 슬롯에 공개 이벤트로, `AttestationSummary`는 슬립 프린터로 QR 인쇄한다.
10. 재개(`OpenBox::resume`)에는 구성 순서의 모듈 포트를 넘긴다(구간 확인만 하고 상태를 바꾸지 않는다). 돌아온 `ResumePlan`대로 종이를 옮기고(함·반환 트레이, 폐기 슈트, 격리 봉투, 유권자에게 돌려줌, 보류), `incident`면 사건 이벤트로 기록한다. 확인 위치가 공개 없이 폐기 슈트로 가면 그것도 사건 이벤트로 남긴다.
11. 투표양식 목록은 ID 바이트 오름차순으로 넘긴다(최대 4,096개, 슬라이스를 빌림).
12. 마감은 `prepare_close` 뒤 같은 투표함의 토큰으로 `into_closed`를 부른다. 판정이 비어 있지 않으면 `HOLD_REVIEW`다.
13. `is_faulted()`가 참이면 장치를 교체한다.

버퍼 크기: 표 작업 영역 `BallotWork` 하나(30,264바이트), 방문 작업 영역 `VisitWork` 하나(24,304바이트), 빌드 scratch `scratch_len(신뢰기관 수)`(신뢰기관당 3,542바이트), share 패키지 ≤ 269,088(빌드 버퍼, 결정 때 패키지를 다시 읽는 버퍼, 재개 패키지 버퍼), 기록 본문 ≤ 21,570, 기록 ≤ 22,582, 배치 작업 `BATCH_WORK_LEN`(76,922), 마감 작업 `CLOSE_WORK_LEN`(5,715), 검증 공개 ≤ 7,805, 슬립 ≤ 5,387, 보관 공간 ≤ 위치 8 × (기록 + 패키지), 현장 증명 작업 `ATTEST_WORK_LEN`(119,856: 모듈 서명 7개, 본문, 증명 객체, 요약).

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
| `tests/flow.rs` | 방문 흐름(세 위치의 결정 전 결속과 모듈 서명, 위치마다 내구화되는 묶음 항목, 위치 순서 처리, 저널 순서와 결정의 fsync 한 번, 방문 슬립, 보관 포트에서의 기록 공개; 관외 스티커와 라벨 목록, 스티커 실패; 결정 뒤 같은 카운터의 다른 본문 거부), 공개 검증기의 검사(추적코드, 장치·모듈 기록 서명, OR 증명), 신뢰기관의 검사(패드·KEM 복호, 전송 태그, 정족수로 모든 비밀 복원과 검증 공개값의 일치, 정당 챔버 하나나 J가 빠진 집합의 실패; 정당 2·3·4, 최대 구성인 모듈 7개·챔버 8개 포함), 모듈 태그 `tag_{c,i}`의 신뢰기관 측 검증(VC-022), KEM 연관 데이터 변조 시 복호 실패, 청크 수가 다른 투표양식의 패드 구간 분리, 포트 순서 오류, 다른 키의 기록 서명, 두 작업 영역의 종료·실패 경로 소거 |
| `tests/boxes.rs` | 저널 사슬, 카운터 되감기·재사용·건너뛰기, 배치 범위·거부·연쇄 없음·서명 검증, 방문 자리를 남기는 배치 시점, 전제 검사 순서, 고장 고정, 스캔 카운터, 격리 회계(배치 중간 기록의 각인 실패, 저널 실패, 버려진 결정 방문, 결정 중 저널 실패), 바뀐 보관 객체 거부, `VisitEnd` 장수·8위치·잘못된 결정, 방문 상태의 방문 결속, 마감 불변식 하나씩, 방문 수의 양쪽 상한, 관외 봉투·스티커 수와 프로필, 다른 투표함의 토큰 |
| `tests/resume.rs` | 방문 종류마다 재개한 투표함과 원래 투표함의 동일성과 이어서 쓰기(실제 모듈에 묻기), 네 경우(결정 전: 묶인 위치의 기록 해시 격리와 카운터 등식·다음 발급 수락, 묶이기 전 발급을 모듈에 물어 찾기와 답할 수 없는 모듈, fsync 전 유실된 결정 항목, 결정 없는 위치 항목; 결정 후: 폐기 슈트·각인 덧붙임·이미 각인; 관외 스티커 없음; 맞지 않는 종이와 사건 재계산·마감 보고), 스티커 항목 없이 다음 방문으로 넘어간 관외 방문의 사건(스티커가 있거나 넣은 표가 없으면 사건 아님), 재개 항목 쓰기 실패, 손상·불일치 저널 거부(묶음 항목의 카운터·순서·패키지, 위치 항목의 순서와 되풀이한 카운터, 결정 다이제스트, 위치 수, 각인 순서, 격리 대상과 포기한 방문의 순서, 스티커 항목, 배치, 마감) |
| `tests/styles.rs` | 4,096개 투표양식 구성에서 처음·가운데·마지막 투표양식 조회와 투표, 모르는 투표양식, 정렬 안 됨·중복·초과 거부, 구성 크기 |
| `tests/link.rs` | 링크 객체 배치와 디코더(`VisitEnd`, 저널 종류 1–9, 최대 길이), 구성 규칙(정당 챔버 모듈 필수·위임 금지, n 밖의 정당 챔버, 모듈 8개 거부), 계수 규칙과 모듈 서명 규칙 예, 재개 판정의 경우별 표, 속성 테스트 |
| `tests/surface.rs` | 표시 문자열, 비밀을 담은 값의 `Debug`, 접근자, 경계값 |
| `tests/attest.rs` | 현장 증명: 확인 카드·토큰 경로, 본문의 모든 필드와 구성 해시 재계산, 챔버 코드 순 모듈 진술과 그 서명, 증명 키 서명과 요약의 Ed25519 절반 서명, 투표함·저널·카운터 불변, 추적코드·저널 head 없음; 30초 간격(경계, 시계 역행, 시계 끝); 모듈에 묻기 전의 거부(목록 밖 참관인, 다른 키·바뀐 바이트의 서명, 다른 선거, 깨진 객체, 열린 방문); 틀린 모듈 진술·모듈 거부·잘못된 측정 목록·작은 버퍼·포트 수; 설정 검사(관찰자 순서·중복·개수, 모듈 키 수, 장치 ID 길이); 도전값 링크 객체 |

Kani 하네스(10개): 현장 증명의 30초 간격 규칙(128비트로 독립 기술한 식과 대조), 선택지 범위, 카운터 판정, 네 번의 발급에 걸친 카운터 최고값(되돌아가지 않고 같은 카운터를 두 번 받지 않음), 패드 소비·인덱스 산술, 모듈 배치 서명 규칙, 배치·스캔 카운터 시점, VC-038 판정 전체(투표지 사건, 방문·봉투·스티커 수 포함)를 128비트 산술로 독립 기술한 명제와 대조하고, 재개 판정이 위치 8개까지의 모든 입력과 모듈의 두 답에 대해 정의되며 경우마다 약속을 지킴(경우 4는 아무것도 쓰지 않고 보류, 경우 1은 격리되지 않은 묶인 위치와 그 종이를 모두 격리하고 모듈이 발급했으면 그 카운터를 싣고 소비 없는 묶이지 않은 종이만 돌려줌, 경우 2·3을 적용하면 넣는 위치가 모두 처리되고 관외에서 스티커 없이 넣은 기록이 남지 않음, 각인 덧붙임은 관내 맨 앞 각인 종이만)을 증명한다.

### 변이 테스트 결과

묶음 항목(ADR-0021 결정 10) 반영 후(2026-11-01), 바뀐 `visit.rs`·`resume.rs`·`rules.rs`·`ballot.rs`·`boxstate.rs`·`link.rs`를 한 번에 돌렸다(`-f`, `--timeout 300`): 변이 770개 중 잡힘 603, 빌드 불가 162, 놓침 5(31분). 둘은 시험이 엉뚱한 이유(시간 구간 역행)로 실패하던 손상 저널 시험을 고쳐 잡았고(위치 항목 뒤·격리 뒤의 묶음 항목, 묶인 위치 너머의 빈 위치 항목), 셋은 동치 변이라 코드에서 없앴다: 모듈에 묻기 전의 `first <= mark` 검사(구간 확인 하나로 충분), 이상 종이일 때 모든 종이를 격리로 바꾸는 중복 호출, 진행 중인 표 항목 수의 중복 조건. 해당 함수만 다시 돌린 결과 변이 43개 중 잡힘 36, 빌드 불가 7, 놓침 0. 현장 증명(개정 24) 반영 후 `attest.rs`·`link.rs`·`error.rs`와 `boxstate.rs`의 서명 도우미를 돌렸다: 변이 235개 중 잡힘 122, 빌드 불가 70, 놓침 43이었고 놓친 것은 모두 `attest.rs`의 버퍼 길이 상수 식이었다(버퍼가 커지거나 작아져도 시험 입력에서는 결과가 같다). 길이마다 가장 긴 필드 묶음의 인코딩 길이와 정확한 값을 단위 테스트로 고정한 뒤 `attest.rs`를 다시 돌려 변이 103개 중 잡힘 79, 빌드 불가 24, 놓침 0. 방문 단위 투입 때(같은 날) `error.rs`·`config.rs`와 그 밖의 파일도 놓침 0이었고, 바뀌지 않은 `port.rs`·`rng.rs`는 그 결과가 그대로다. 빌드 불가는 대부분 비공개 타입의 값을 기본값으로 바꾸는 변이다. 알려진 동치 변이는 없다.

### `Drop` 소거의 시험

`.cargo/mutants.toml`은 `impl Drop` 본문을 변이에서 뺀다(값이 사라진 뒤에는 관찰할 수 없다). 그래서 소거하는 `Drop`은 모두 한 줄로 시험된 메서드를 부른다.

| `Drop` | 부르는 메서드 | 직접 시험 |
|---|---|---|
| `BallotWork` | `zeroize` | `ballot::tests::zeroize_clears_every_field`, `is_clear_sees_every_field_on_its_own`; 통합 테스트가 종료·실패 경로마다 `is_clear()`를 확인 |
| 작업 영역 보호자(`WorkGuard`, 비공개) | `BallotWork::zeroize` | `ballot::tests::guard_wipes_on_take_and_on_drop`이 보호자를 실제로 drop한 뒤 작업 영역을 읽는다 |
| `VisitWork` | `zeroize` | `visit::tests::is_clear_sees_every_field_and_zeroize_clears_it`; 통합 테스트가 방문 종료·실패 경로마다 `is_clear()`를 확인 |
| 방문 보호자(`VisitGuard`, 비공개) | `VisitWork::zeroize` | `visit::tests::the_guard_and_the_first_slot_wipe_the_work_area` |
| `ImprintCommand`, `LabelCommand` | `zeroize` | `visit::tests::commands_redact_and_zeroize` |
| `DeviceRng` | `wipe` | `ballot::tests::binding_moves_the_small_secrets_and_wipes_the_rest` 등(소거된 생성기는 0 키의 스트림을 낸다) |
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
