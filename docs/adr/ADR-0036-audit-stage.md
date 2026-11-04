# ADR-0036: 감사 단계 — 동결, 시드, 표본, 표본 열기, 대조, 확대, 전수 대조, 수검표

> English summary: Step M5 2g adds the verifier's audit stage (PROTOCOL §12, §14 item 8; VC-045..047, VC-059, VC-074) and its ledger objects, and the status ladder reaches `PAPER_AUDITED` only when the verifier itself computed that every ballot style's audit concluded. The encoding gets `AuditManifestFreezeBody` (0x0048, one per style: the sample frame's count and root and the sampling rule as declared integer rounds of cumulative sample size and tolerated discrepancies, the designated beacon round), `AuditSeedBody` (0x000D), the restricted `SampleOpeningBody` (0x0049, never on the public ledger) and its public reference `SampleOpeningRefBody` (0x004A, in `QuorumSigned`), `SampleComparisonBody` (0x004B), `AuditFindingBody` (0x004C) and `HandCountReportBody` (0x004D); accepting them takes `WitnessedEvent` to version 3, `RosterSigner` to 3 (the auditor role) and `QuorumSigned` to 2. The seed must name the last valid checkpoint before it, covering every freeze, and the beacon round every freeze designated; the verifier recomputes it and compares the beacon value with the one the caller observed (no value: the audit cannot conclude; another value: the seed is refused). The sample is a partial Fisher–Yates shuffle of the sorted frame driven by a per-style SHA3-512 counter stream with rejection sampling (SHAKE256 is not reachable from the crypto crate's dependencies, and the counter construction is already in the TCB). Trustees may open only what the audit calls for; a caller with access supplies the restricted bodies, which are reconstructed against the commitments. Every nonzero code counts toward the escalation rule; codes 1 and 2 call for a full comparison of the device and a finding, 5 and 6 hold the box; past the last round each unit's hand count, the legal result, concludes the style. The sample-size formula itself is not checked.

- 상태: 채택
- 날짜: 2026-11-04
- 관련: ADR-0011(감사, 공개 난수), ADR-0020(사유 코드), ADR-0017 §12(SHA3-512 카운터 생성기), ADR-0028(버전 번호), ADR-0032(분쟁 단계의 키 규칙), ADR-0035(집계 단계); `docs/spec/PROTOCOL.md` §5.2, §12, §14 8항, 부록 A·B·C; `docs/spec/ENCODING.md` §6, §8.33, §8.42, §8.43, §8.63, §8.66–§8.72; `docs/ROADMAP.md` M5 2g

## 맥락

M5 2f까지 검증기는 §14의 1–7항과 9항을 돌리고 `CRYPTO_TALLY_VERIFIED`까지 상태를 냈다. 8항(감사)에는 장부 객체도 검증 단계도 없었고, `ityv-state`의 상태 규칙은 "감사가 규칙상 종료됨"을 호출자가 넘기는 깃발로 받았다. 명세(§12)는 동결·시드·표본·열기·대조·확대의 내용을 말하지만, 인코딩, 시드가 쓰는 체크포인트, 비콘 값의 출처, 표본의 바이트 절차, 제한 등급 열기를 공개 검증자가 어떻게 확인하는지, 표본 크기 공식을 누가 계산하는지, 수검표를 어떻게 싣는지, "종료"가 무엇인지를 정하지 않았다. `AuditSeed`(0x000D)는 등록만 되어 있었다.

## 결정

1. **인코딩(ENCODING §8.66–§8.72).** 모든 본문은 버전 1이다.
   - `AuditManifestFreezeBody`(0x0048): 투표양식 하나의 표본 프레임(포함 기록 수와 정렬 집합 root)과 추출 규칙(규칙 문서 해시, 위험 한도 ppm, 비콘 지정 문서 해시와 회차, 라운드 목록). 라운드는 1–8개이고 라운드마다 누적 표본 크기(1 이상, 엄격히 커짐)와 그 라운드에서 감사를 끝내는 불일치 수의 상한(줄지 않음)이다.
   - `AuditSeedBody`(0x000D, 등록부의 `AuditSeed`): 주사위 기록 해시, 비콘 회차와 값, 체크포인트 해시, 시드.
   - `SampleOpeningBody`(0x0049, 제한 등급): 표본 기록 하나의 `(option_index, cast_id, r_0..r_{k−1})`. 비밀이므로 복사되지 않고 `Debug`에 선택이 나오지 않으며 해제 때 지운다. 공개 장부에 실리지 않는다.
   - `SampleOpeningRefBody`(0x004A): 공개 장부가 싣는 열기의 흔적. 투표양식, 기록 해시, 제한 본문의 객체 해시. 정족수가 `QuorumSigned`로 서명한다(purpose `sample-opening`, 서명 메시지는 다른 정족수 본문처럼 본문 해시와 참여 구성원 목록).
   - `SampleComparisonBody`(0x004B): 기록 해시, 대조한 열기의 객체 해시, 장치(투표함), 사유 코드 0–6, `transfer_mark`.
   - `AuditFindingBody`(0x004C): 투표양식, 장치, 발견 문서 해시, 시각.
   - `HandCountReportBody`(0x004D): `PaperCountReportBody`와 같은 필드와 규칙. 법적 결과인 수검표는 첫 종이 개표와 다른 질문의 답이므로 스키마를 따로 둔다.
   - 기록 하나에 관한 객체(열기 흔적, 대조)에는 시각이 없다(VC-001). 열기 흔적의 열람 권한은 시드의 날로 확인한다(6항).

2. **서명자와 버전.** 동결과 시드는 위원회 1과 서로 다른 조직 참관인 2 이상(부록 A "위원회, 참관인"), 대조와 발견은 서로 다른 조직의 감사인 2 이상과 서로 다른 조직의 참관인 2 이상(§12.3 "감사인 2 조직 서명과 열람한 정당 참관인 서명"), 수검표는 종이 보고처럼 그 단위 선관위 위원장 1과 참관인 2 조직이다. 감사인은 명부 역할 6, 이벤트 역할 10으로 둔다. 역할과 본문이 늘어 `WitnessedEvent`의 버전 2 거부 벡터(`role 10`)와 `RosterSigner`의 버전 2 거부 벡터(`role 6`), `QuorumSigned`의 버전 1이 거부하던 본문이 정상 입력이 되므로 세 스키마를 각각 버전 3, 3, 2로 올렸다(ADR-0028, ADR-0035 3항과 같은 이유). 서명 키는 다른 단계와 같다: 위원회는 genesis 본문의 키, 그 밖의 서명자는 그 프레임에 시행 중인 상태 또는 그 앞 상태의 명부 항목 가운데 서명이 맞는 것(새 상태부터), 역할과 조직은 시행 중인 상태의 명부가 정한다.

3. **표본 프레임과 동결.** 투표양식의 프레임은 genesis 마지막 상태에서 그 투표양식인 모든 보고 단위의 포함 기록(집계 단계의 재계산)을 합쳐 정렬한 것이다. 투표양식마다 동결 하나를 받으며, 그 투표양식의 모든 단위의 `TallyScope`가 앞 프레임에 받아들여진 뒤에만 받는다(`RLA`, 그 날). 동결의 수와 root가 재계산과 다르면 받되 그 투표양식을 보류하고(`AuditFrameMismatch`) 표본을 뽑지 않는다. 시드가 모든 동결을 기다리므로(4항) 시드 뒤의 동결은 언제나 같은 투표양식의 두 번째 동결이다(반복 또는 충돌).

4. **시드.** 선거마다 하나. 받는 조건(VC-045): 모든 투표양식의 동결이 앞 프레임에 있다; 모든 동결이 같은 비콘 지정 문서와 시드의 비콘 회차를 적었다; `checkpoint_hash`가 시드보다 앞 프레임의 유효 체크포인트 가운데 마지막 것의 본문 객체 해시이고, 그 체크포인트의 `tree_size`가 모든 동결 프레임을 덮는다; `seed = SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice ‖ beacon ‖ checkpoint)`. "마지막"으로 고정하는 것은 시드를 만드는 쪽이 여러 체크포인트 가운데 고를 수 없게 하기 위해서이고, 동결을 덮게 하는 것은 프레임과 규칙이 증인 서명으로 고정된 뒤에만 시드가 생기게 하기 위해서다. 검증기는 비콘을 가져올 수 없다. 호출자가 그 회차의 공표 값을 넘기고(`AuditInput::beacon`, genesis 핀처럼 검증 대상 밖에서 온 값), 다르면 시드를 거부하고 보류하며, 넘기지 않으면 시드는 받지만 감사는 종료되지 않는다. 다른 회차의 값은 이 회차의 관찰이 아니다.

5. **표본(VC-046).** 표본 흐름은 SHA3-512 카운터 모드다: 투표양식마다 열쇠 `SHA3-512("ityv:sample:v1" ‖ 0x00 ‖ seed ‖ u32_be(len(style)) ‖ style)`, 블록 `i`는 `SHA3-512(열쇠 ‖ u64_be(i))`, 흐름은 블록을 이어 붙인 것이고 8바이트씩 big-endian `u64`로 읽는다. `below(n)`은 낱말 `x`를 `x ≤ 2^64 − 1 − (2^64 mod n)`일 때 받아 `x mod n`을 내고, 아니면 버리고 다음 낱말을 읽는다(최대 64번, 넘으면 표본 실패). 표본은 정렬된 프레임 `0..N`에 대한 부분 Fisher–Yates다: `i = 0, 1, …`마다 `j = i + below(N − i)`, 위치 `i`와 `j`를 바꾸고 위치 `i`의 값을 뽑는다. 그래서 한 기록은 한 번만 뽑히고(비복원), 라운드 `r`의 표본은 처음 `min(크기_r, N)`개이며 확대된 표본은 앞의 표본으로 시작한다. 명세가 말한 SHAKE256 대신 SHA3-512 카운터를 쓴 것은 `ityv-crypto`의 의존성에서 SHAKE256에 닿을 수 없고(sha3 0.12는 SHAKE를 다른 크레이트로 옮겼다) 의존성 추가는 검증 의무이기 때문이며(CONSTITUTION §1.10), 같은 구성이 이미 커밋먼트 유닛 생성기로 TCB에 있다(ADR-0017 §12). 가정은 같다(Keccak 해시를 무작위 오라클로 봄). 시험 벡터는 Python `hashlib`로 명세에서 따로 계산했다(`ityv-crypto` `sample`, `ityv-verify` `audit` 단위 시험).

6. **표본 열기와 제한 본문(VC-047, VC-059).** 공개 장부에는 정족수가 서명한 열기 흔적(제한 본문의 해시를 담은 `SampleOpeningRefBody`, 1항)만 실리고 제한 본문은 실리지 않는다. 0x0049 프레임은 검증기가 모르는 장부 이벤트라 장부를 보류한다(`OPAQUE_SCHEMAS`에 넣지 않는다). 흔적은 시드 뒤, 시드의 날에 `OBSERVER_ACCESS`가 있을 때(열람은 그 범위로 한다, §12.3), 접근구조의 자격 정족수가, 기록마다 한 번, 감사가 부르는 기록에만 받는다: 지금 대조 중인 라운드의 표본, 또는 전수 대조 중인 장치의 기록. 그 밖의 열기는 선택을 열람자에게 드러내므로 받지 않고 보류한다(`NotCalled`). 열람 권한이 있는 호출자는 제한 본문을 `AuditInput::openings`로 넘기고, 검증기는 흔적이 가리키는 해시의 본문마다 선거·투표양식·기록이 맞는지, 정확히 `k`개의 canonical 스칼라와 선택지·`cast_id`가 기록의 모든 커밋먼트를 여는지 확인한다(`Reconstructed`/`Mismatch`, 불일치는 `SampleOpeningMismatch` 보류). 공개 검증자에게는 `NotSupplied`이며 그래도 `PAPER_AUDITED`에 이를 수 있다: §14 8항은 공개 검증자에게 존재와 서명을, 열람 권한이 있는 검증기에게 재구성을 맡긴다. 검증기의 출력에는 열린 값이 없다.

7. **대조와 사유 코드.** 대조는 그 기록의 흔적이 앞 프레임에 있고 그 흔적의 열기 해시를 적었을 때, 장치가 기록의 투표함일 때만 받는다. 0이 아닌 모든 코드가 확대 규칙에 들어간다(§12.4). 코드 1·2는 그 장치를 전수 대조에 두고(VC-074), 전수 대조는 그 투표함의 프레임 기록이 모두 대조되고 첫 코드 1·2 뒤 프레임에 그 장치의 `AuditFinding`이 있을 때 끝난다. 코드 3·4는 장치별로 센다(모델은 genesis에 없어 모델별 합은 내지 않는다). 코드 5·6은 그 투표함과 투표양식을 보류한다(`AuditCustody`). `transfer_mark`는 장치와 투표소별로 센다. 전수 대조 기록 가운데 표본이 아닌 것은 확대 규칙의 수에 들어가지 않는다(규칙의 수는 무작위 표본의 것이다).

8. **확대와 수검표.** 라운드의 수는 누적이다: 라운드 `r`의 대조 수와 불일치 수는 그 라운드 표본(처음 `min(크기_r, N)`개) 안에서 센다. 라운드를 차례로 보아 불일치가 상한을 넘으면 다음 라운드로(표본 전부가 대조되기 전이라도 곧바로), 마지막 라운드를 넘으면 그 투표양식 전체를 수검표한다. 넘지 않은 첫 라운드는 표본이 모두 대조되면 종료다(`ityv_state::audit_phase`, Kani로 정확성 확인). 수검표는 보고 단위마다 `HandCountReportBody` 하나이고, 그 투표양식의 표본이 마지막 라운드를 넘은 대조보다 뒤 프레임에서만 받는다. 수검표가 법적 결과이며 검증기는 그것을 보일 뿐 기계 합계와 비교하지 않는다(다를 수 있어서 수검표를 한 것이다).

9. **표본 크기 공식.** 명세는 `policy_hash` 문서가 공식을 고정한다고 말한다. 검증기는 부동소수점을 쓰지 않고 임의의 문서를 계산할 수 없으므로, 동결이 정수 라운드(누적 크기와 상한)를 선언하고 `rule_hash`로 그 공식 문서를 가리킨다. 검증기는 선언된 규칙대로 표본을 다시 뽑고 확대가 그 규칙을 따랐는지를 확인한다. 선언된 크기와 상한이 공식과 표차·위험 한도에서 나온 값인지는 검증 범위 밖이다(사람이 문서로 확인한다). 위험 한도는 기록만 한다.

10. **종료와 상태.** 투표양식의 감사는 다음을 모두 만족할 때 종료다: 동결이 재계산과 같고, 시드가 받아들여졌고 호출자가 같은 비콘 값을 보았으며, 한 라운드가 상한 안에서 종료되었거나 수검표 단계에서 모든 단위의 수검표가 있고, 코드 1·2가 나온 장치마다 전수 대조와 발견이 있으며, 그 투표양식에 보류가 없다. 감사 단계는 모든 투표양식이 종료되고 거부된 이벤트가 없을 때 통과한다. 보고서는 그때만 8단계를 통과로 두며, `ityv-state`의 상태 규칙에서 호출자가 넣던 "감사 종료" 깃발을 없앴다. 그래서 `PAPER_AUDITED`는 1–7단계 통과, 보류 없음, 그리고 검증기가 장부에서 계산한 감사 종료가 있을 때만 나온다. 한 투표양식이라도 미완성이면 보류 없이 `CRYPTO_TALLY_VERIFIED`에 머문다.

11. **거부와 보류.** 받지 못한 이벤트는 모두 목록에 남고 보류한다: 동결 `AuditFreezeRefused`(61), 시드 `AuditSeedRefused`(63), 열기 `SampleOpeningRefused`(64), 대조 `SampleComparisonRefused`(66), 발견 `AuditFindingRefused`(68), 수검표 `HandCountRefused`(69). 불일치는 `AuditFrameMismatch`(62), `SampleOpeningMismatch`(65), `AuditCustody`(67). 같은 대상의 둘째 이벤트는 본문이 같으면 반복, 다르면 충돌이다(대상: 투표양식의 동결, 선거의 시드, 기록의 열기와 대조, 장치·문서의 발견, 단위의 수검표). 보류 사유가 64개를 넘어 `HoldSet`을 128비트로 넓혔다(코드는 빈틈없이 이어진다).

12. **색인.** 대조와 발견은 그 장치(투표함)의 이벤트로, 동결·시드·수검표·열기 흔적은 선거의 이벤트로 색인한다.

## 결과

- 공개 장부와 호출자가 본 비콘 값만으로 누구나 시드와 표본을 다시 계산하고, 열기 흔적과 대조가 표본과 전수 대조가 부르는 기록에 대해 있고 서명되었는지, 확대와 수검표가 선언된 규칙을 따랐는지 확인한다.
- 열람 권한이 있는 검증기는 같은 단계로 열린 값이 기록의 커밋먼트를 여는지 확인한다. 열린 값은 어떤 출력에도 나오지 않는다.
- 감사가 없거나 일부만 된 장부, 비콘 값이 없는 검증은 `PAPER_AUDITED`에 이르지 못한다.

## 한계

- 표본 크기 공식, 위험 한도와 선언된 라운드의 관계는 확인하지 않는다(9항).
- 주사위 기록의 내용과 비콘 값은 검증 대상 밖에서 온다(비콘은 호출자가 보증한다).
- 시드가 체크포인트를 고르는 규칙은 운영자가 시드를 싣는 시점을 정하는 것까지 막지 못한다. 그 시점은 동결이 증인 체크포인트에 고정된 뒤이고, 비콘 회차는 동결에 고정되어 있다.
- §12.5의 다른 전수 대조 사유(`ScannerQuarantine`, §9.5·§11.3의 장치, `AttestationIncident`)와 §11.5·§10.6 7항의 "표본을 늘림"은 아직 장부 사건이 없어 다루지 않는다(그런 경우는 이미 보류다).
- 모델별 비율(코드 3·4)은 genesis에 장치 모델이 없어 내지 않는다.
- 열람자가 누구였는지는 장부에 없다. 대조에 서명한 참관인이 열람을 증언한다.
- 기록 하나에 관한 이벤트에 시각이 없으므로 열기 흔적의 열람 권한은 시드의 날로만 확인하고, 대조는 서명자만 확인한다. 승인 기간이 끝난 뒤의 열기와 대조는 가려내지 못한다.
- `SampleOpening` 원본의 파기(§15, VC-059)는 검증하지 않는다.
- 명세의 SHAKE256과 다른 흐름이다(5항). SHAKE256으로 바꾸려면 새 라벨로 정의를 바꾸고 벡터를 다시 만든다.

## 기각한 대안

- **동결 하나에 모든 투표양식.** `WitnessedEvent` 본문 상한(2,048바이트)을 넘고, 규칙은 투표양식마다 다르다. 기각.
- **제한 본문을 불투명 프레임으로 싣고 서명을 따로 공개.** 프레임이 둘이 되지만 흔적이 이미 본문 해시를 서명으로 고정하므로 결속이 늘지 않는다. 기각.
- **복원 추출(같은 기록을 여러 번).** 기록마다 대조 하나라는 규칙과 반복·충돌 판정이 복잡해진다. 기각.
- **검증기가 공식을 계산.** 부동소수점 금지와 임의 문서 해석 불가. 기각.
- **"감사 종료"를 호출자가 계속 넣기.** 장부와 무관한 주장으로 `PAPER_AUDITED`가 나온다. 기각.
- **시드 뒤의 동결을 따로 거부(`AfterSeed`).** 시드가 모든 동결을 기다리므로 그런 동결은 언제나 두 번째 동결이다. 도달할 수 없는 규칙은 두지 않았다.

## 연결되는 검증

- `ityv-encoding` `tests/m5_audit.rs`, `tests/vectors.rs` `audit`(새 벡터 7개, 다시 만든 `witnessed_event.txt`·`roster_signer.txt`·`quorum_signed.txt`), Kani `event_codes_are_exact`(역할 10, 명부 역할 6, 사유 코드 0–6), `audit_round_rules_are_exact`.
- `ityv-crypto` `sample` 단위 시험(독립 계산 벡터), `tests/proptests.rs` `the_sample_limit_leaves_whole_runs`(받는 낱말이 `bound`의 온전한 런들인지, 128비트로), Kani `sample_accept_limit_is_tight`(모든 `bound`에서 한계가 있고 그 위의 낱말이 `bound`개보다 적음). 한계가 런의 배수라는 나머지 항등식은 Kani의 SAT 백엔드가 10분 안에 끝내지 못해(전 범위, `2^26` 이하, 128비트 몫 증인을 시도) 속성 테스트로 확인한다.
- `ityv-state` `audit` 단위 시험, Kani `audit_phase_is_exact`, `hold_set_is_sticky`(128비트), `status_is_exact`.
- `ityv-verify` `tests/audit.rs`(17개, 실제 OR 증명·커밋먼트·하이브리드 서명), `audit` 단위 시험(표본 벡터).
