# ityv-sim

> English summary: The synthetic-election generator (ROADMAP M6, first part; ADR-0038). Outside the TCB: it depends on the TCB crates and nothing depends on it, and only workspace crates are used (no external dependency). From a fixed seed it builds whole signed elections — genesis with every set, real hybrid keys and signatures for every device, person, module, trustee and witness, OR-proved cast records, full voting days slot by slot with arrival peaks, spoiled and returned sheets, the three progress alarms with their on-site checks and an emergency-insertion hour, closes, station counts, participation sets, receipt resolutions and the tally — and named scenarios over them: the status ladder from `UNVERIFIED` to `CRYPTO_TALLY_VERIFIED`, two larger fictional elections, and 21 attacks and faults. Each scenario carries its expected verifier outcome; the tests compare it with what `ityv-verify` reports, directly and through `ityv-wasm`. Output is byte-identical across runs. Each scenario is written as a development bundle, a small documented container that is not part of `ENCODING.md` and lasts until the mirror format of ADR-0018 exists. All names are fictional.

## 무엇인가

`cargo run --release -p ityv-sim -- [--quick] <outdir>`는 시나리오마다 번들 `<이름>.ityvb`과 목록 `index.json`을 쓴다. 검증 콘솔(`apps/ityv-console`)이 이 둘을 읽는다. `--quick`은 작은 선거 하나 위의 25개(CI와 테스트용), 기본은 그것에 큰 선거 셋을 더한 28개다.

TCB 밖이다(CONSTITUTION.md §0). 여기서 무엇이 틀려도 증거가 바뀌지 않는다. 시뮬레이터가 만든 장부는 검증기가 그대로 검증하고, 시나리오의 기대와 검증기의 판정이 다르면 테스트와 콘솔이 불일치로 보인다. 의존성은 워크스페이스 크레이트뿐이다. 서명의 hedged 난수와 커밋먼트·증명의 난수는 `ityv-cunit`의 SHA3 카운터 생성기(`DeviceRng::for_signing`)에 입력에서 유도한 씨앗을 넣어 얻는다. 키는 이름표와 고정 씨앗(`util::SEED`)의 SHA3-512로 정한다. 그래서 두 번 돌리면 같은 바이트가 나온다(`tests/scenarios.rs`의 `bundles_are_byte_identical_across_runs`).

| 모듈 | 내용 |
|---|---|
| `spec` | 선거를 이루는 것: 정당 챔버, 투표양식과 후보, 보고 단위, 투표소와 투표함, 하루의 사건 |
| `catalog` | 빠른 시연 선거, 지방선거 모양, 국회의원선거 모양 |
| `day` | 투표소 하루를 10분 슬롯마다: 도착 곡선(아침·저녁 정점), 교부·투입·훼손·반납, 경보를 일으키는 사건과 현장 확인, 비상 투입 |
| `election` | genesis와 모든 집합, 키, 이벤트 생성기(검증기 테스트 세계에서 옮겨 일반화) |
| `plan` | 한 선거의 장부 계획: genesis, 법적 승인, 열쇠 절차와 모듈 발급, 투표일(개시, 기록, 배치, 진행 기록, 현장 확인, 두 시간마다 체크포인트), 마감과 투표소 수량, 참여 집합, 수령 대조, 집계 |
| `ledger` | 계획의 단계를 프레임과 증인 체크포인트로 깔기 |
| `scenarios` | 이름 붙은 시나리오와 기대 결과 |
| `bundle`, `meta` | 번들 인코더와 `index.json` |

## 선거

모든 장소·정당·후보 이름은 가상이며 "가상"을 붙여 실제와 헷갈리지 않게 했다(예: "가상시 한빛구", "가상미래당", 후보 "김가상"). 실제 선거 결과는 쓰지 않는다.

| 선거 | 모양 | 규모 |
|---|---|---|
| `SIM-QUICK` | 두 구, 선거일 투표소 하나와 관외 투표함이 있는 사전투표소 하나, 한 시간 투표 | 방문 17, 프레임 97 |
| `SIM-LOCAL` | 지방선거 모양: 가상시의 세 구·군, 투표소 여덟(사전투표소 둘, 관외 투표함 둘), 06:00–18:00. 바닥·음수·과다 경보가 한 번씩 나고 현장 확인으로 해소되며, 한 투표소는 한 시간 동안 비상 투입구를 쓴다 | 방문 1,520, 프레임 3,003 |
| `SIM-NATIONAL` | 국회의원선거 모양: 두 지역구, 투표소 다섯(사전투표소 하나, 관외 투표함 하나), 06:00–18:00, 과다·바닥 경보와 현장 확인 | 방문 840, 프레임 1,757 |

현재 genesis와 검증기의 한계로 줄인 것:
- 한 방문에 여러 종류의 투표지(지방선거 7종, 국회의원선거 지역구+비례)를 넣을 수 없다. `GenesisBox`는 투표양식 하나만 갖고(ENCODING.md §8.43), 투표소 등식은 확인 한 건에 투표지 한 장을 센다(`ityv-state` issuance: `checkin = issued − voter_spoiled − challenged`). 그래서 유권자마다 투표지 한 장이며, 지방선거 모양은 구·군의 장만, 국회의원선거 모양은 지역구만 시연한다. 여러 장 방문의 화면 흐름(위치 1…N)은 콘솔의 스캐너 화면 시제품에서 본다.
- 관외 투표함은 사전투표소마다 하나다. 한 투표소에 관외 투표함이 둘이면 봉투 수 대조(`EnvelopeMismatch`)가 투표소 교부 수 전체와 비교되기 때문이다.
- 정당 챔버는 둘(P1, P2)이다. 검증 공개(검증 폐기)와 격리는 만들지 않았다.

## 시나리오

기대 결과는 시나리오 정의의 일부다. "주입한 것"과 "검증기가 보여야 할 것"은 `index.json`에 한국어로 있고 콘솔이 그대로 보인다.

| 이름 | 묶음 | 기대 상태 | 기대 보류 사유 |
|---|---|---|---|
| `quick-clean` | 정상 | `CRYPTO_TALLY_VERIFIED` | 없음 |
| `quick-voting` | 정상 | `LOG_CONSISTENT` | 없음 |
| `quick-closed` | 정상 | `SOURCE_COMPLETENESS_CHECKED` | 없음 |
| `quick-anchor-pending` | 정상 | `UNVERIFIED` | 없음 |
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

여러 사유가 함께 나오는 시나리오는 주입 하나가 뒤 단계에 퍼진 결과다(예: 바꿔치기한 기록이 거부되면 배치, 마감 기록 집합, 교부 등식, 집계 범위가 함께 어긋난다). 기대는 그 퍼짐까지 적는다. 테스트는 사유 집합이 정확히 같은지 본다. 또 큰 선거와 경보 시나리오는 검증기가 낸 경보(투표소·슬롯·종류)가 시뮬레이터가 그 하루에 일으키려 한 경보와 같은지, 비상 투입 투표소의 경보가 멈췄는지 본다.

### 보류 사유와 시나리오

| 코드 | 이름 | 시나리오 |
|---|---|---|
| 7 | `ObservedCountMismatch` | `attack-mirror-tampered` |
| 8 | `ManualClose` | `fault-manual-close` |
| 10 | `SealMismatch` | `fault-seal-mismatch` |
| 20 | `IssuanceMismatch` | `attack-tampered-record`, `attack-mirror-tampered` |
| 23 | `StepFailed` | `attack-checkpoint-fork`, `attack-mirror-tampered`, `attack-unknown-event`, `fault-missing-amendment` |
| 24 | `OpenDispute` | `fault-open-dispute` |
| 26 | `PublicationLate` | `fault-board-late` |
| 30 | `ProgressUnresolved` | `fault-progress-unresolved` |
| 32 | `ProgressStream` | `attack-wrong-role`, `attack-no-authorization` |
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

아직 시나리오가 닿지 않은 사유(61개 중 33개): 0 `PaperRecordMismatch`, 1 `AttestedMismatch`, 2 `SpoilEnvelopeMismatch`, 3 `ModuleCounterGap`, 4 `OpenBatches`, 5 `VisitBounds`, 6 `FallbackUndeclared`, 9 `LateCloseDiffers`, 11 `OpeningNonZero`, 12 `AbsenteePaperNonZero`, 13 `StickerVisitMismatch`, 14 `EnvelopeMismatch`, 15 `IssuanceMissing`, 16 `CustodyCountMismatch`, 17 `CustodySealUnexplained`, 18 `CustodyIncomplete`, 19 `ImprintAudit`, 21 `ParticipationMismatch`, 22 `LegalDecisionPending`, 25 `SplitView`, 27 `BoxUnderReview`, 28 `SealBroken`, 29 `IssuanceStockMismatch`, 31 `CarryOut`, 37 `CloseMissing`(완전성 미달이며 장부 상태의 보류가 아니다), 40 `AuthorizationInvalid`, 45 `DisputeRefused`, 46 `ChallengeRejected`, 47 `OpeningMismatch`, 48 `ParticipationSetInvalid`, 50 `KeyProvisioningInvalid`, 56 `PaperCountRefused`, 58 `TallyEffectRefused`. 마감 수량·인계·각인·검증 공개·법적 결정의 생성기를 더하면 닿는다(M6 다음 단계). `SplitView`(25)는 검증기의 분기 감시 단계(§14 10항)가 아직 없어 만들 수 없다.

## 번들 형식

개발용 형식이다. ADR-0018의 미러 형식이 생기면 그것으로 바꾼다. `ENCODING.md`의 일부가 아니고 TCB 크레이트는 읽지 않는다. 읽는 쪽은 `apps/ityv-wasm/src/bundle.rs`다. 모든 정수는 big-endian이다.

```text
bundle  = magic "ITYVSIMB" (8 바이트) ‖ version u16 (= 1) ‖ count u16 ‖ section × count
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
| 0x0003 | GENESIS | blob(`SignedGenesis` 객체) ‖ sets ‖ list(ballot_styles) ‖ list(trustees) ‖ list(witnesses): 각 항목은 `ENCODING.md`의 항목 객체 | 예 |
| 0x0004 | AMENDMENTS | n u32 ‖ (blob(`SignedGenesis` 변경 객체) ‖ sets) × n | 아니오 |
| 0x0005 | FRAMES | 장부 프레임 스트림(`u32_be 길이 ‖ 프레임 객체` 반복, PROTOCOL §5.1) | 예 |
| 0x0006 | EVENTS | list(프레임 옆에 공표한 이벤트 객체, 프레임 순서) | 예 |
| 0x0007 | PUBLICATIONS | checkpoint u64 ‖ n u32 ‖ receipt u64 × n ‖ close u64 ‖ published_flag u8 ‖ published u64 ‖ now u64: `ityv_ledger::check_anchor`·`check_board`의 입력(시간 구간) | 예 |

규칙: 섹션은 tag 오름차순으로 한 번씩, 모르는 tag는 거부, 길이가 남은 바이트를 넘거나 바이트가 남으면 거부. PIN은 번들 안에 있지만 번들과 같은 출처에서 온 것이다. 실제 검증에서는 관보 등 다른 출처의 핀을 써야 하며, 콘솔은 그 값을 넣게 한다(PROTOCOL §14, VC-005).

## 크기와 시간

이 컨테이너(release 빌드)에서 잰 값:

| 묶음 | 시나리오 | 크기 합계 | 생성 시간 |
|---|---|---|---|
| `--quick` | 25 | 36.9 MB (번들 하나 1.1–1.7 MB) | 6.1초 |
| 전체 | 28 | 66.8 MB (`local-clean` 12.5 MB, `local-voting` 9.4 MB, `national-clean` 7.9 MB) | 13.7초 |

번들이 큰 까닭은 하이브리드 서명(ML-DSA-87, 4,627바이트)이다. 진행 기록 한 건, 모듈 발급 기록, 증인 체크포인트마다 붙는다. 번들은 저장소에 넣지 않는다(`bun run dev`/`build`가 만든다). 브라우저 WASM 검증 시간은 빠른 번들 약 0.3–0.4초, `local-clean` 약 6초, `national-clean` 약 3.5초(node 22, 같은 컨테이너)다.

## 검증

- `cargo test -p ityv-sim`: 빠른 시나리오 25개마다 기대 상태와 보류 사유가 `ityv-verify`의 판정과 같고, `ityv-wasm`이 같은 번들에서 같은 상태와 사유를 보고하며, 검증기가 낸 경보가 시뮬레이터의 하루와 같다. 번들은 실행마다 같은 바이트이고 새로 만든 선거도 같은 장부를 깐다. WASM 읽기는 번들이 아닌 바이트, 잘린 번들, 다른 핀을 거부한다.
- 큰 시나리오: `cargo test -p ityv-sim --release -- --ignored`(약 1분).

## 하지 않는 것

- 검증기가 옳다는 것을 증명하지 않는다. 시나리오가 기대한 대로 검증기가 말하는지만 본다.
- 장치 동작은 모델이다. 커밋먼트 유닛의 typestate나 펌웨어를 거치지 않고 같은 형식의 객체를 직접 만든다.
- 연결 감사(UplinkSession), 소프트웨어 증명(DeviceAttestation), 감사(SampleOpening) 이벤트는 만들지 않는다. 검증기에 그 단계가 아직 없다.
