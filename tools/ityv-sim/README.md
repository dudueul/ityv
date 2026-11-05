# ityv-sim

> English summary: The synthetic-election generator (ROADMAP M6, first part; ADR-0038). Outside the TCB: it depends on the TCB crates and nothing depends on it; besides workspace crates it uses only the P-256 signer and SHA-2 that `ityv-tsa` already depends on, for two simulated timestamp authorities. From a fixed seed it builds whole signed elections — genesis with every set, real hybrid keys and signatures for every device, person, module, trustee and witness, OR-proved cast records, full voting days slot by slot with arrival peaks, spoiled and returned sheets, the three progress alarms with their on-site checks and an emergency-insertion hour, closes, station counts, participation sets, receipt resolutions, the voter roll (extracts, freeze, custody receipts), every station gateway's frame logs and sessions over every device's fixed-schedule uplink frames (ADR-0041), the tally and the comparison audit (freezes, the commit, the binding checkpoint, the seed, opening references, comparisons, escalation, full comparison with a finding, hand counts), every checkpoint stamped by a government and a non-government timestamp authority — and named scenarios over them: the status ladder from `UNVERIFIED` to `PAPER_AUDITED`, two larger fictional elections, and 46 attacks and faults. The beacon round's published output, the dice record and the beacon designation are fixture data, carried in the bundle and handed to the verifier as the caller's observation. Each scenario carries its expected verifier outcome; the tests compare it with what `ityv-verify` reports, directly and through `ityv-wasm`. Output is byte-identical across runs. Each scenario is written as a development bundle, a small documented container that is not part of `ENCODING.md` and lasts until the mirror format of ADR-0018 exists. All names are fictional.

## 무엇인가

`cargo run --release -p ityv-sim -- [--quick] <outdir>`는 시나리오마다 번들 `<이름>.ityvb`과 목록 `index.json`을 쓴다. 검증 콘솔(`apps/ityv-console`)이 이 둘을 읽는다. `--quick`은 작은 선거 하나(와 그 변형 셋) 위의 55개(CI와 테스트용), 기본은 그것에 큰 선거 셋을 더한 58개다. `index.json`은 시나리오마다 번들 파일의 크기와 SHA3-512(`sha3`)를 적는다. 콘솔은 번들 바이트의 해시가 그 값과 같을 때만 그 시나리오의 설명을 붙인다.

TCB 밖이다(CONSTITUTION.md §0). 여기서 무엇이 틀려도 증거가 바뀌지 않는다. 시뮬레이터가 만든 장부는 검증기가 그대로 검증하고, 시나리오의 기대와 검증기의 판정이 다르면 테스트와 콘솔이 불일치로 보인다. 의존성은 워크스페이스 크레이트와, 가상의 시점확인 기관 둘(`tsa`, 정부 운영과 정부 밖)을 위한 P-256 서명과 SHA-2(`ityv-tsa`가 이미 쓰는 같은 판)뿐이다. ECDSA 서명은 RFC 6979로 결정적이고 키는 다른 키처럼 이름표와 고정 씨앗으로 정한다. 서명의 hedged 난수와 커밋먼트·증명의 난수는 `ityv-cunit`의 SHA3 카운터 생성기(`DeviceRng::for_signing`)에 입력에서 유도한 씨앗을 넣어 얻는다. 키는 이름표와 고정 씨앗(`util::SEED`)의 SHA3-512로 정한다. 그래서 두 번 돌리면 같은 바이트가 나온다(`tests/scenarios.rs`의 `bundles_are_byte_identical_across_runs`).

| 모듈 | 내용 |
|---|---|
| `spec` | 선거를 이루는 것: 정당 챔버, 투표양식과 후보, 보고 단위, 투표소와 투표함, 하루의 사건 |
| `catalog` | 빠른 시연 선거, 지방선거 모양, 국회의원선거 모양 |
| `day` | 투표소 하루를 10분 슬롯마다: 도착 곡선(아침·저녁 정점), 교부·투입·훼손·반납, 경보를 일으키는 사건과 현장 확인, 비상 투입 |
| `election` | genesis와 모든 집합, 키, 이벤트 생성기(검증기 테스트 세계에서 옮겨 일반화) |
| `plan` | 한 선거의 장부 계획: genesis, 법적 승인, 열쇠 절차와 모듈 발급, 선거인명부(투표구 추출과 스냅숏, 동결, 보관 기관 셋의 영수증), 투표일(개시, 기록, 배치, 진행 기록, 현장 확인, 두 시간마다 체크포인트), 마감과 투표소 수량, 참여 집합, 수령 대조, 집계 |
| `audit` | 집계 뒤의 감사(PROTOCOL §12, ADR-0036): 투표양식마다 동결, 감사 약정, 약정 직후의 고정 체크포인트, 비콘 공표 뒤의 시드, 검증기와 같은 표본, 감사가 부르는 순서의 열기 흔적과 대조(`ityv_state::audit_phase`로 라운드를 따름), 코드 1·2 장치의 전수 대조와 발견, 모든 라운드를 넘으면 단위별 수검표 |
| `ledger` | 계획의 단계를 프레임과 증인 체크포인트로 깔기, 체크포인트마다 두 기관의 시점확인 기록 |
| `tsa` | 가상의 시점확인 기관 둘: 키, 자체 서명 인증서(필수 EKU timeStamping), `ityv-tsa`가 받는 RFC 3161 토큰 |
| `uplink` | 연결 감사(ADR-0041): genesis가 고정하는 연결 목록, 장치 링크의 프레임(슬롯마다 연결 목록의 수, 데이터 덩어리 잎과 탑재부 root, 프레임 키 서명), 게이트웨이의 프레임 기록과 세션(여섯 슬롯 창, 사슬 head, 마지막은 `final`과 참관인 캡처 서명), 세션에 붙이는 장애 |
| `scenarios` | 이름 붙은 시나리오와 기대 결과 |
| `bundle`, `meta` | 번들 인코더와 `index.json` |

## 선거

모든 장소·정당·후보 이름은 가상이며 "가상"을 붙여 실제와 헷갈리지 않게 했다(예: "가상시 한빛구", "가상미래당", 후보 "김가상"). 실제 선거 결과는 쓰지 않는다.

| 선거 | 모양 | 규모 |
|---|---|---|
| `SIM-QUICK` | 두 구, 선거일 투표소 하나와 관외 투표함이 있는 사전투표소 하나, 한 시간 투표 | 방문 17, 프레임 113 |
| `SIM-LOCAL` | 지방선거 모양: 가상시의 세 구·군, 투표소 여덟(사전투표소 둘, 관외 투표함 둘), 06:00–18:00. 바닥·음수·과다 경보가 한 번씩 나고 현장 확인으로 해소되며, 한 투표소는 한 시간 동안 비상 투입구를 쓴다 | 방문 1,520, 프레임 3,048 |
| `SIM-NATIONAL` | 국회의원선거 모양: 두 지역구, 투표소 다섯(사전투표소 하나, 관외 투표함 하나), 06:00–18:00, 과다·바닥 경보와 현장 확인 | 방문 840, 프레임 1,800 |

현재 genesis와 검증기의 한계로 줄인 것:
- 한 방문에 여러 종류의 투표지(지방선거 7종, 국회의원선거 지역구+비례)를 넣을 수 없다. `GenesisBox`는 투표양식 하나만 갖고(ENCODING.md §8.43), 투표소 등식은 확인 한 건에 투표지 한 장을 센다(`ityv-state` issuance: `checkin = issued − voter_spoiled − challenged`). 그래서 유권자마다 투표지 한 장이며, 지방선거 모양은 구·군의 장만, 국회의원선거 모양은 지역구만 시연한다. 여러 장 방문의 화면 흐름(위치 1…N)은 콘솔의 스캐너 화면 시제품에서 본다.
- 관외 투표함은 사전투표소마다 하나다. 한 투표소에 관외 투표함이 둘이면 봉투 수 대조(`EnvelopeMismatch`)가 투표소 교부 수 전체와 비교되기 때문이다.
- 정당 챔버는 둘(P1, P2)이다. 검증 공개(검증 폐기)와 격리는 만들지 않았다.
- 모든 선거의 명부에 감사인 둘(AUDIT-A, AUDIT-B)이 있고 법적 승인은 `RLA`와 `OBSERVER_ACCESS`를 준다. 감사 이벤트가 없는 장부에서는 아무것도 바꾸지 않는다.
- `SIM-QUICK`의 변형 `quick_faint_election`: 선거일 투표소 스캐너가 후보 표시 세 장 가운데 하나를 판독 불가로 읽는다(`DayEvent::Faint`, 종이는 유효표). 감사에서 코드 3으로 나온다.

## 연결 감사

모든 투표소에 게이트웨이(하이브리드 키·증명 키)가, 모든 스캐너와 카운터·가명 유닛에 프레임 키가 genesis에 있다. 연결 목록은 기준값(스캐너 16, 유닛 4, 따라잡기 64)을 쓰고 한 방향 규칙을 지킨다. 장치는 투표소 개시 슬롯부터 마감 구간 다음 슬롯까지 슬롯마다 그 수의 일반 프레임을 보내고, 앞 세션 뒤에 만든 객체(배치 증명과 그 기록을 기록 해시 순서로, 진행 기록, 참관인 확인 수, 참여 집합)를 창의 마지막 슬롯 첫 프레임들에 싣는다. 배치에 들지 않은 기록은 보내지 않는다. 게이트웨이는 개시부터 여섯 슬롯마다 프레임 기록과 세션을, 참여 집합 뒤에 남은 창과 `final` 세션을 싣고, 투표소의 두 참관인이 `final` 세션에 캡처 서명을 한다(캡처 해시는 고정 자료다. 시뮬레이터는 캡처 파일을 만들지 않는다). 세션은 계획의 단계(`Step::Uplink`)라 장부를 깔 때 그때까지 깐 장치 이벤트로 만들어지고, 장부를 바꾼 공격도 바뀐 장부를 그대로 나른다. 그래서 기존 시나리오의 기대 결과는 그대로다(`attack-record-after-close`의 마감 뒤 기록은 색인이 무효로 하므로 포함을 따로 묻지 않는다).

- `attack-manifest-two-way`: 연결 목록이 스캐너 업링크 포트를 양방향으로 적었다. 장부 전체 `ConnectivityManifest`(79).
- `attack-uplink-hidden-frame`: 게이트웨이가 한 프레임을 기록과 사슬에서 빼고 빠진 슬롯으로 적지 않았다. `UplinkSessionRefused`(80).
- `attack-uplink-injected-frame`, `fault-uplink-padding`, `fault-uplink-extra-frame`, `fault-uplink-after-close`: 게이트웨이가 서명한 프레임, 데이터 뒤 0이 아닌 채움, 슬롯당 수를 넘는 번호, 마감 뒤 슬롯의 일반 프레임. `UplinkFrameInvalid`(81).
- `attack-uplink-batch-order`: 마감 배치의 기록을 해시 내림차순으로 보냈다. `UplinkObjectInvalid`(82).
- `fault-uplink-lost-frame`, `attack-hidden-path-record`: 회선에서 사라진 데이터 프레임(정직하게 빠진 슬롯으로 적음)의 진행 기록, 업링크로 오지 않은 기록. `UplinkObjectOutside`(83).
- `fault-roll-line-incident`, `fault-capture-mismatch`: 위원회와 참관인이 실은 명부 회선 사건(투표소 전체), 사무원과 참관인이 실은 캡처 불일치 사건(투표함, 커밋먼트 유닛 연루, 전수 대조 대상). `ConnectivityIncident`(84).
- `attack-incident-forged`: 한 참관인의 서명을 다른 참관인의 키로 만든 사건. 장부 전체 `ConnectivityIncidentRefused`(85).

캡처와 통신사 기록의 대조(`ityv-verify`의 `compare_capture`, `compare_carrier`)는 장부 밖 입력의 도구라 시나리오의 상태에 들어가지 않는다. 그 결과가 사건으로 실린 장부가 위의 사건 시나리오다.

## 시점확인과 명부 보관

체크포인트마다 두 가상 기관(정부 운영 `TSA-GOV-SIM`, 정부 밖 `TSA-FREE-SIM`)이 그 구간의 1분째에 찍은 토큰이 바로 뒤 프레임에 실린다(ADR-0039). 감사의 고정 체크포인트도 그렇게 찍혀 시드보다 앞에 있으므로 감사 시나리오는 공표 전 토큰 규칙을 지킨다. 집계 범위는 그 앞 프레임의 토큰으로 앵커된 체크포인트의 증인 시각을 쓴다(ADR-0039 개정 6항). 기관의 키와 인증서는 시뮬레이터의 공개 씨앗에서 나오는 가상의 것이다.

- `attack-checkpoint-backdated`: 정부 밖 기관의 토큰 하나가 마지막 체크포인트가 증인이 적은 구간보다 두 구간 앞서 있었다고 말한다. 사슬이 거기서 끝난다(`TimestampMismatch`, VC-116).
- `fault-anchor-missed`: 마지막 체크포인트에 토큰이 없고 지금 시각이 앵커 창을 넘었다. 보류가 아니라 `UNVERIFIED`다(`quick-anchor-pending`은 창 안에서 한 기관만 찍은 경우).
- `attack-tsa-unpinned`: 고정되지 않은 기관(`TSA-ROGUE-SIM`)의 토큰을 정부 운영 기관의 이름으로 실었다(`TimestampInvalid`).
- `attack-roll-extract-after-freeze`: 동결과 영수증 뒤에 같은 투표구의 추출을 다른 내용으로 하나 더 실었다(`RollEventRefused`, ADR-0040).
- `quick-roll-amended`, `fault-roll-amendment-short`: 동결 뒤 이의신청 결정으로 한 명을 더한 변경 1. 보관 기관 셋이 영수증을 내면 효력이 있고, 둘뿐이면(정족수 3) 효력이 없어 14절 6단계가 끝나지 않는다(보류 아님).

## 감사와 고정 자료

감사 시나리오의 타임라인(시간 구간, 15분): 집계가 준비된 구간 `ready`에서 동결 `ready + 8`, 약정 `+9`, 약정 직후의 고정 체크포인트 `+9`, 비콘 공표 `P = +16`(규칙은 `binding ≤ P − 3`, 나머지 4구간은 운영 여유), 시드 `P + 1`, 발견 `P + 2`, 수검표 `P + 3`, 마지막 체크포인트 `P + 4`. 대조는 시뮬레이터가 아는 하루대로다(`audit::truthful`: 판독 불가로 읽힌 유효표는 코드 3, 나머지는 일치). 시나리오가 주입하는 것만 다르다.

시드의 입력 가운데 주사위 기록 해시, 비콘 지정 문서 해시, 비콘 회차 4242의 공표 출력은 시뮬레이터가 만든 고정 자료다. 번들에 비콘 관찰(회차, 출력, 공표 구간)을 넣고, 콘솔은 그것을 검증기에 호출자의 관찰로 넘기며 고정 자료라고 표시한다. 표본에 모양이 필요한 시나리오(첫 라운드에 판독 불가 유효표가 나와야 하는 `audit-escalation`, `audit-hand-count`)는 그 모양이 나오는 첫 고정 출력(`... output k`)을 쓴다. 실제 선거에서는 약정이 비콘 값 말고 모든 입력을 공표 전에 고정하므로 아무도 고를 수 없다(ADR-0036 4항). 제한 등급의 표본 열기(`SampleOpeningBody`)는 시나리오 옆에 두어 열람 권한 있는 검증 시험에만 쓰고, 장부에도 번들에도 넣지 않는다.

## 시나리오

기대 결과는 시나리오 정의의 일부다. "주입한 것"과 "검증기가 보여야 할 것"은 `index.json`에 한국어로 있고 콘솔이 그대로 보인다.

| 이름 | 묶음 | 기대 상태 | 기대 보류 사유 |
|---|---|---|---|
| `quick-clean` | 정상 | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `quick-voting` | 정상 | `LOG_CONSISTENT` | 없음 |
| `quick-closed` | 정상 | `SOURCE_COMPLETENESS_CHECKED` | 없음 |
| `quick-anchor-pending` | 정상 | `UNVERIFIED` | 없음 |
| `quick-roll-amended` | 정상 | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `audit-clean` | 정상 | `PAPER_AUDITED` | 없음 |
| `audit-escalation` | 정상 | `PAPER_AUDITED` | 없음 |
| `audit-hand-count` | 정상 | `PAPER_AUDITED` | 없음 |
| `audit-one-style` | 정상 | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `local-clean` | 정상(큰) | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `local-voting` | 정상(큰) | `LOG_CONSISTENT` | 없음 |
| `national-clean` | 정상(큰) | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `attack-tampered-record` | 공격 | `HOLD_REVIEW` | IssuanceMismatch, RecordRejected, BatchInvalid, RecordSetMismatch, TallyScopeMismatch, AggregateMismatch |
| `attack-checkpoint-fork` | 공격 | `HOLD_REVIEW` | StepFailed, CheckpointInvalid |
| `attack-replayed-record` | 공격 | `HOLD_REVIEW` | EventReplayed |
| `attack-conflicting-scope` | 공격 | `HOLD_REVIEW` | TallyScopeRefused |
| `attack-record-after-close` | 공격 | `HOLD_REVIEW` | RecordAfterClose |
| `attack-mirror-tampered` | 공격 | `HOLD_REVIEW` | ObservedCountMismatch, IssuanceMismatch, StepFailed, LedgerUnchecked, BatchInvalid, RecordSetMismatch, TallyScopeMismatch, AggregateMismatch |
| `attack-unknown-event` | 공격 | `HOLD_REVIEW` | StepFailed, LedgerUnchecked |
| `fault-missing-coverage` | 장애 | `UNVERIFIED` | 없음 |
| `attack-paper-mismatch` | 공격 | `HOLD_REVIEW` | PaperCountMismatch |
| `attack-aggregate-mismatch` | 공격 | `HOLD_REVIEW` | AggregateMismatch |
| `attack-receipt-unresolved` | 공격 | `HOLD_REVIEW` | TallyScopeRefused, AggregateRefused |
| `attack-wrong-role` | 공격 | `HOLD_REVIEW` | ProgressStream, StationCountRefused |
| `fault-missing-amendment` | 장애 | `HOLD_REVIEW` | StepFailed, AmendmentMissing |
| `fault-progress-unresolved` | 장애 | `HOLD_REVIEW` | ProgressUnresolved |
| `attack-late-close-after-scope` | 공격 | `HOLD_REVIEW` | LateCloseAfterScope |
| `fault-manual-close` | 장애 | `HOLD_REVIEW` | ManualClose |
| `attack-duplicate-pseudonym` | 공격 | `HOLD_REVIEW` | DuplicatePseudonym |
| `fault-open-dispute` | 장애 | `HOLD_REVIEW` | OpenDispute |
| `fault-seal-mismatch` | 장애 | `HOLD_REVIEW` | SealMismatch |
| `fault-board-late` | 장애 | `HOLD_REVIEW` | PublicationLate |
| `attack-no-authorization` | 공격 | `HOLD_REVIEW` | ProgressStream, BoxEventRefused, AuthorizationMissing, TallyScopeRefused, AggregateRefused, ReceiptResolutionRefused |
| `attack-overflow-progress` | 공격 | `HOLD_REVIEW` | ProgressStream, ProgressUnresolved |
| `attack-checkpoint-backdated` | 공격 | `HOLD_REVIEW` | StepFailed, TimestampMismatch |
| `fault-anchor-missed` | 장애 | `UNVERIFIED` | 없음 |
| `attack-tsa-unpinned` | 공격 | `HOLD_REVIEW` | TimestampInvalid |
| `attack-roll-extract-after-freeze` | 공격 | `HOLD_REVIEW` | RollEventRefused |
| `fault-roll-amendment-short` | 장애 | `SOURCE_COMPLETENESS_CHECKED` | 없음 |
| `fault-swapped-readings` | 장애 | `PAPER_AUDITED` | 없음 |
| `fault-audit-ballot-missing` | 장애 | `HOLD_REVIEW` | AuditCustody |
| `attack-seed-grinding` | 공격 | `HOLD_REVIEW` | AuditSeedRefused, SampleOpeningRefused, SampleComparisonRefused |
| `attack-binding-backdated` | 공격 | `HOLD_REVIEW` | AuditSeedRefused, SampleOpeningRefused, SampleComparisonRefused |
| `attack-binding-unstamped` | 공격 | `HOLD_REVIEW` | AuditSeedRefused, SampleOpeningRefused, SampleComparisonRefused |
| `fault-commit-missing` | 장애 | `HOLD_REVIEW` | AuditSeedRefused, SampleOpeningRefused, SampleComparisonRefused |
| `attack-commit-conflict` | 공격 | `HOLD_REVIEW` | AuditCommitRefused |
| `attack-manifest-two-way` | 공격 | `HOLD_REVIEW` | ConnectivityManifest |
| `attack-uplink-hidden-frame` | 공격 | `HOLD_REVIEW` | UplinkSessionRefused |
| `attack-uplink-injected-frame` | 공격 | `HOLD_REVIEW` | UplinkFrameInvalid |
| `fault-uplink-padding` | 장애 | `HOLD_REVIEW` | UplinkFrameInvalid |
| `fault-uplink-extra-frame` | 장애 | `HOLD_REVIEW` | UplinkFrameInvalid |
| `fault-uplink-after-close` | 장애 | `HOLD_REVIEW` | UplinkFrameInvalid |
| `attack-uplink-batch-order` | 공격 | `HOLD_REVIEW` | UplinkObjectInvalid |
| `fault-uplink-lost-frame` | 장애 | `HOLD_REVIEW` | UplinkObjectOutside |
| `attack-hidden-path-record` | 공격 | `HOLD_REVIEW` | UplinkObjectOutside |
| `fault-roll-line-incident` | 장애 | `HOLD_REVIEW` | ConnectivityIncident |
| `fault-capture-mismatch` | 장애 | `HOLD_REVIEW` | ConnectivityIncident |
| `attack-incident-forged` | 공격 | `HOLD_REVIEW` | ConnectivityIncidentRefused |

감사 시나리오:
- `audit-clean`: 두 투표양식 모두 첫 라운드에서 끝난다(한빛구청장 4장·상한 1, 누리구청장 3장·상한 0). 고정 체크포인트가 공표보다 7구간 앞선다. 비콘 관찰 없이 검증하면 `CRYPTO_TALLY_VERIFIED`, 제한 열기를 함께 넘기면 모든 열기가 재구성된다.
- `audit-escalation`: 희미한 표시의 선거. 한빛구청장 첫 라운드(3장·상한 0)에 코드 3이 나와 둘째 라운드(8장·상한 3)로 늘고 거기서 끝난다.
- `audit-hand-count`: 같은 선거, 한 라운드(3장·상한 0)뿐인 규칙. 상한을 넘어 보고 단위의 수검표가 실리고 끝난다.
- `audit-one-style`: 동결·약정·시드는 둘 다, 대조는 한빛구청장만. 장부는 집계 상태에 머물고 한빛구 단위만 `PAPER_AUDITED`다.
- `fault-swapped-readings`: 스캐너가 서로 다른 후보의 투표지 두 장의 판독을 바꿨다(후보별 합은 같아 종이 계수와 맞는다). 표본의 코드 1이 그 장치의 전수 대조를 불러 다른 한 장도 찾고, 발견이 실려 끝난다.
- `fault-audit-ballot-missing`: 표본 첫 기록의 투표지가 없다(코드 5). 그 투표함과 투표양식이 `AuditCustody`. 누리구 단위는 `PAPER_AUDITED`로 읽힌다.
- `attack-seed-grinding`: 약정 뒤 체크포인트 없이 기다리다 공표 뒤에 `P − 2`로 적은 체크포인트를 받았다. 시드 `Late`, 그 뒤 열기와 대조는 `Premature`. 정직한 두 시점확인 기관은 그 체크포인트를 만든 때(`P + 1`)에 찍으므로 공표 전 토큰 규칙(`Unstamped`)으로도 걸리지만, 검증기는 먼저 걸린 `Late`를 보인다.
- `attack-binding-backdated`: 약정이 자기를 덮는 체크포인트보다 한 구간 늦은 시각을 적었다. 시드 `Backdated`.
- `attack-binding-unstamped`: 고정 체크포인트에 정부 운영 기관의 토큰만 있다(증인 시각 규칙은 지킴). 시드 `Unstamped`(ADR-0039 8항).
- `fault-commit-missing`: 약정 없이 시드. 시드 `Premature`.
- `attack-commit-conflict`: 다른 주사위 기록의 둘째 약정. 둘째 약정 `Conflict`, 감사는 첫 약정으로 끝나지만 보류.

`attack-overflow-progress`는 한 투표함의 장치가 투입 누계를 2^64 − 1장으로 서명한 하루다. 같은 투표소의 다른 투표함과 더하면 64비트를 넘으므로 `ityv-wasm`의 진행 수열은 그 칸을 `null`과 `overflow`로 쓰고, 콘솔은 '넘침'으로 보인다(트랩하지 않는다). 그 하루의 경보는 시뮬레이터가 의도한 하루와 다르므로 경보 일치 시험에서 뺀다.

여러 사유가 함께 나오는 시나리오는 주입 하나가 뒤 단계에 퍼진 결과다(예: 바꿔치기한 기록이 거부되면 배치, 마감 기록 집합, 교부 등식, 집계 범위가 함께 어긋난다). 기대는 그 퍼짐까지 적는다. 테스트는 사유 집합이 정확히 같은지 본다. 또 큰 선거와 경보 시나리오는 검증기가 낸 경보(투표소·슬롯·종류)가 시뮬레이터가 그 하루에 일으키려 한 경보와 같은지, 비상 투입 투표소의 경보가 멈췄는지 본다.

### 보류 사유와 시나리오

| 코드 | 이름 | 시나리오 |
|---|---|---|
| 7 | `ObservedCountMismatch` | `attack-mirror-tampered` |
| 8 | `ManualClose` | `fault-manual-close` |
| 10 | `SealMismatch` | `fault-seal-mismatch` |
| 20 | `IssuanceMismatch` | `attack-tampered-record`, `attack-mirror-tampered` |
| 23 | `StepFailed` | `attack-checkpoint-fork`, `attack-mirror-tampered`, `attack-unknown-event`, `fault-missing-amendment`, `attack-checkpoint-backdated` |
| 24 | `OpenDispute` | `fault-open-dispute` |
| 26 | `PublicationLate` | `fault-board-late` |
| 30 | `ProgressUnresolved` | `fault-progress-unresolved`, `attack-overflow-progress` |
| 32 | `ProgressStream` | `attack-wrong-role`, `attack-no-authorization`, `attack-overflow-progress` |
| 33 | `EventReplayed` | `attack-replayed-record` |
| 34 | `RecordAfterClose` | `attack-record-after-close` |
| 35 | `LedgerUnchecked` | `attack-mirror-tampered`, `attack-unknown-event` |
| 36 | `CheckpointInvalid` | `attack-checkpoint-fork` |
| 38 | `BoxEventRefused` | `attack-no-authorization` |
| 39 | `AuthorizationMissing` | `attack-no-authorization` |
| 41 | `AmendmentMissing` | `fault-missing-amendment` |
| 42 | `RecordRejected` | `attack-tampered-record` |
| 43 | `BatchInvalid` | `attack-tampered-record`, `attack-mirror-tampered` |
| 44 | `RecordSetMismatch` | `attack-tampered-record`, `attack-mirror-tampered` |
| 49 | `DuplicatePseudonym` | `attack-duplicate-pseudonym` |
| 51 | `StationCountRefused` | `attack-wrong-role` |
| 52 | `TallyScopeRefused` | `attack-conflicting-scope`, `attack-receipt-unresolved`, `attack-no-authorization` |
| 53 | `TallyScopeMismatch` | `attack-tampered-record`, `attack-mirror-tampered` |
| 54 | `AggregateRefused` | `attack-receipt-unresolved`, `attack-no-authorization` |
| 55 | `AggregateMismatch` | `attack-tampered-record`, `attack-mirror-tampered`, `attack-aggregate-mismatch` |
| 57 | `PaperCountMismatch` | `attack-paper-mismatch` |
| 59 | `ReceiptResolutionRefused` | `attack-no-authorization` |
| 60 | `LateCloseAfterScope` | `attack-late-close-after-scope` |
| 63 | `AuditSeedRefused` | `attack-seed-grinding`, `attack-binding-backdated`, `attack-binding-unstamped`, `fault-commit-missing` |
| 64 | `SampleOpeningRefused` | `attack-seed-grinding`, `attack-binding-backdated`, `attack-binding-unstamped`, `fault-commit-missing` |
| 66 | `SampleComparisonRefused` | `attack-seed-grinding`, `attack-binding-backdated`, `attack-binding-unstamped`, `fault-commit-missing` |
| 67 | `AuditCustody` | `fault-audit-ballot-missing` |
| 70 | `AuditCommitRefused` | `attack-commit-conflict` |
| 72 | `TimestampInvalid` | `attack-tsa-unpinned` |
| 73 | `TimestampMismatch` | `attack-checkpoint-backdated` |
| 74 | `RollEventRefused` | `attack-roll-extract-after-freeze` |
| 79 | `ConnectivityManifest` | `attack-manifest-two-way` |
| 80 | `UplinkSessionRefused` | `attack-uplink-hidden-frame` |
| 81 | `UplinkFrameInvalid` | `attack-uplink-injected-frame`, `fault-uplink-padding`, `fault-uplink-extra-frame`, `fault-uplink-after-close` |
| 82 | `UplinkObjectInvalid` | `attack-uplink-batch-order` |
| 83 | `UplinkObjectOutside` | `fault-uplink-lost-frame`, `attack-hidden-path-record` |
| 84 | `ConnectivityIncident` | `fault-roll-line-incident`, `fault-capture-mismatch` |
| 85 | `ConnectivityIncidentRefused` | `attack-incident-forged` |

아직 시나리오가 닿지 않은 사유(86개 중 43개): 0 `PaperRecordMismatch`, 1 `AttestedMismatch`, 2 `SpoilEnvelopeMismatch`, 3 `ModuleCounterGap`, 4 `OpenBatches`, 5 `VisitBounds`, 6 `FallbackUndeclared`, 9 `LateCloseDiffers`, 11 `OpeningNonZero`, 12 `AbsenteePaperNonZero`, 13 `StickerVisitMismatch`, 14 `EnvelopeMismatch`, 15 `IssuanceMissing`, 16 `CustodyCountMismatch`, 17 `CustodySealUnexplained`, 18 `CustodyIncomplete`, 19 `ImprintAudit`, 21 `ParticipationMismatch`, 22 `LegalDecisionPending`, 25 `SplitView`, 27 `BoxUnderReview`, 28 `SealBroken`, 29 `IssuanceStockMismatch`, 31 `CarryOut`, 37 `CloseMissing`(완전성 미달이며 장부 상태의 보류가 아니다), 40 `AuthorizationInvalid`, 45 `DisputeRefused`, 46 `ChallengeRejected`, 47 `OpeningMismatch`, 48 `ParticipationSetInvalid`, 50 `KeyProvisioningInvalid`, 56 `PaperCountRefused`, 58 `TallyEffectRefused`, 61 `AuditFreezeRefused`, 62 `AuditFrameMismatch`, 65 `SampleOpeningMismatch`(열람 권한 있는 검증기에만 나온다), 68 `AuditFindingRefused`, 69 `HandCountRefused`, 71 `AuditSampleFailed`(일어나지 않을 일), 75 `RollCustodyMismatch`, 76 `ContestedCheckinInvalid`, 77 `ContestedLabelReused`(둘 다 열람 권한 있는 검증기에만 나온다), 78 `RollIncomplete`. 마감 수량·인계·각인·검증 공개·법적 결정과 감사 이벤트의 변조 생성기를 더하면 닿는다(M6 다음 단계). `SplitView`(25)는 검증기의 분기 감시 단계(§14 10항)가 아직 없어 만들 수 없다.

## 번들 형식

개발용 형식이다. ADR-0018의 미러 형식이 생기면 그것으로 바꾼다. `ENCODING.md`의 일부가 아니고 TCB 크레이트는 읽지 않는다. 읽는 쪽은 `apps/ityv-wasm/src/bundle.rs`다. 모든 정수는 big-endian이다.

```text
bundle  = magic "ITYVSIMB" (8 바이트) ‖ version u16 (= 4) ‖ count u16 ‖ section × count
section = tag u16 ‖ length u32 ‖ payload (length 바이트)
blob    = len u32 ‖ bytes
list    = n u32 ‖ blob × n
hashes  = n u32 ‖ 64 바이트 × n
sets    = list(boxes) ‖ list(stations) ‖ list(progress_policies) ‖ list(reporting_units)
          ‖ list(routes) ‖ list(roster) ‖ list(modules) ‖ hashes(appointments)
```

| tag | 이름 | payload | 필수 |
|---|---|---|---|
| 0x0001 | NAME | 시나리오 이름(UTF-8) | 예 |
| 0x0002 | PIN | 호출자가 믿는 genesis 핀(본문 객체 해시, 64바이트) | 예 |
| 0x0003 | GENESIS | blob(`SignedGenesis` 객체) ‖ blob(`ConnectivityManifest` 객체) ‖ sets ‖ list(ballot_styles) ‖ list(trustees) ‖ list(witnesses) ‖ list(timestamp_authorities) ‖ list(roll_authorities): 각 항목은 `ENCODING.md`의 항목 객체. 연결 목록(genesis 본문이 해시로 고정, ADR-0041)은 버전 4에서, 마지막 둘(genesis 집합 12·13)은 버전 3에서 더했다 | 예 |
| 0x0004 | AMENDMENTS | n u32 ‖ (blob(`SignedGenesis` 변경 객체) ‖ sets) × n | 아니오 |
| 0x0005 | FRAMES | 장부 프레임 스트림(`u32_be 길이 ‖ 프레임 객체` 반복, PROTOCOL §5.1) | 예 |
| 0x0006 | EVENTS | list(프레임 옆에 공표한 이벤트 객체, 프레임 순서) | 예 |
| 0x0007 | PUBLICATIONS | checkpoint u64 ‖ n u32 ‖ receipt u64 × n ‖ close u64 ‖ published_flag u8 ‖ published u64 ‖ now u64: `ityv_ledger::check_board`의 입력과 호출자의 지금(시간 구간). 앵커 기한은 검증기가 장부의 시점확인 토큰으로 정하므로(ADR-0039) checkpoint와 receipt는 읽지 않는다 | 예 |
| 0x0008 | BEACON | round u64 ‖ published u64 ‖ blob(output): 호출자가 본 비콘 공표(`ityv_verify::BeaconObservation`). 시뮬레이터의 고정 자료 | 아니오(감사한 장부에만) |

버전 4는 GENESIS에 연결 목록을 더했다(ADR-0041, ADR-0038 개정 3). 버전 3은 BEACON 섹션(감사, 0x0008)과 GENESIS의 집합 12·13(시점확인 기관과 명부 기관, ADR-0039·ADR-0040)을 함께 담는다. 두 갈래에서 따로 버전 2로 올렸던 둘을 합친 것이다. 버전 1–3 번들은 읽지 않는다(번들은 저장소에 넣지 않고 빌드가 다시 만든다).
규칙: 섹션은 tag 오름차순으로 한 번씩, 모르는 tag는 거부, 길이가 남은 바이트를 넘거나 바이트가 남으면 거부. PIN은 번들 안에 있지만 번들과 같은 출처에서 온 것이다. 실제 검증에서는 관보 등 다른 출처의 핀을 써야 하며, 콘솔은 그 값을 넣게 한다(PROTOCOL §14, VC-005).

## 크기와 시간

이 컨테이너(release 빌드)에서 잰 값:

| 묶음 | 시나리오 | 크기 합계 | 생성 시간 |
|---|---|---|---|
| `--quick` | 55 | 98.7 MB (번들 하나 1.2–2.4 MB) | 19.3초 |
| 전체 | 58 | 136.7 MB (`local-clean` 15.9 MB, `local-voting` 11.9 MB, `national-clean` 10.0 MB) | 29.0초 |

번들이 큰 까닭은 하이브리드 서명(ML-DSA-87, 4,627바이트)이다. 진행 기록 한 건, 모듈 발급 기록, 증인 체크포인트마다 붙는다. 번들은 저장소에 넣지 않는다(`bun run dev`/`build`가 만든다). WASM 검증 시간은 연결 단계를 더한 뒤 빠른 번들 0.26–0.63초, `local-clean` 약 9.2초, `local-voting` 약 6.8초, `national-clean` 약 5.6초다(node 22에서 `verify_bundle`만 잰 값, 4코어 컨테이너, 2026-11-05).

## 검증

- `cargo test -p ityv-sim`: 빠른 시나리오 55개마다 기대 상태와 보류 사유가 `ityv-verify`의 판정과 같고, `ityv-wasm`이 같은 번들에서 같은 상태와 사유를 보고하며, 검증기가 낸 경보가 시뮬레이터의 하루와 같다. 번들은 실행마다 같은 바이트이고 새로 만든 선거도 같은 장부를 깐다. WASM 읽기는 번들이 아닌 바이트, 잘린 번들, 다른 핀을 거부하고, 보고서의 기록마다 포함 증명이 성립한다.
- `tests/robustness.rs`(`ityv-wasm`의 견고성): 모든 보고서가 올바른 JSON이다. 빠른 번들의 비트를 뒤집고(56번) 자르고 바이트를 덧붙여도 패닉하지 않는다. 적대적인 시나리오 이름(HTML, 따옴표, 제어 문자, U+2028/2029)이 한 문자열로 이스케이프된다. 두 투표함이 같은 칸에 2^63을, 한 투표함이 u64::MAX를 적어 합이 넘쳐도 트랩 없이 `overflow`로 보고되고 상태는 `ityv-verify`와 같다. 보고 단위가 장부보다 높게 읽히는 것은 장부의 보류가 모두 다른 단위의 투표함·집계·투표양식 감사 탓일 때뿐이고, 단위가 `PAPER_AUDITED`로 읽히는 것은 그 투표양식의 감사가 끝났을 때뿐이다. 시나리오에서 나오는 모든 집계·감사 거부가 검증기가 공개한 표(`TallyEvent::hold`, `AuditEvent::hold`)의 보류로 장부에 남는다. 콘솔의 보류 이름 표(`apps/ityv-console/src/vocab.ts`)가 `ityv-state`의 이름과 같다.
- `tests/audit.rs`: 감사 시나리오마다 검증기의 감사 단계가 시나리오가 말한 것(라운드, 확대, 전수 대조와 발견, 수검표, 보관 보류, 공격마다의 거부 `Late`·`Backdated`·`Premature`·`Conflict`·`Unstamped`, 고정 체크포인트와 공표의 간격)을 보인다. 비콘 관찰 없이는 집계 상태, 제한 열기를 넘기면 모두 재구성. 콘솔 보고서에 제한 열기의 바이트·cast id·난수가 없다.
- `tests/uplink.rs`: 깨끗한 장부마다 모든 게이트웨이의 세션을 받고(`final` 세션에 참관인 캡처 서명 둘, 슬롯마다 기준값의 프레임, 모든 장치 이벤트 포함), 투표 중에는 포함을 묻지 않으며, 연결 시나리오마다 검증기가 주입한 것(목록의 어긴 규칙, 세션 발견, 프레임·객체 발견, 링크 밖 이벤트, 사건과 전수 대조 대상, 받지 않은 사건)을 보인다.
- 큰 시나리오: `cargo test -p ityv-sim --release -- --ignored`(약 1분).

## 하지 않는 것

- 검증기가 옳다는 것을 증명하지 않는다. 시나리오가 기대한 대로 검증기가 말하는지만 본다.
- 장치 동작은 모델이다. 커밋먼트 유닛의 typestate나 펌웨어를 거치지 않고 같은 형식의 객체를 직접 만든다.
- 소프트웨어 증명(DeviceAttestation) 이벤트는 만들지 않는다. 검증기에 그 단계가 아직 없다. 연결 감사의 프레임은 실제 1 MiB 탑재부를 만들지 않고 데이터 덩어리의 잎과 root만 계산하며(0 덩어리는 0 부분 트리로), 따라잡기·마감 재전송·입회 재전송은 만들지 않는다(정직한 게이트웨이가 모두 받는다). 참관인 캡처 파일과 통신사 기록은 만들지 않는다.
- 비콘을 관찰하지 않는다. 비콘 공표는 고정 자료다. 표본 크기를 위험 한도 공식에서 계산하지 않는다(라운드는 손으로 정한 정수다, ADR-0036 9항). 큰 선거에는 감사를 싣지 않았다.
