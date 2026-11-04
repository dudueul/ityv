# ADR-0036: 감사 단계 — 동결, 시드, 표본, 표본 열기, 대조, 확대, 전수 대조, 수검표

> English summary: Step M5 2g adds the verifier's audit stage (PROTOCOL §12, §14 item 8; VC-045..047, VC-059, VC-074) and its ledger objects, and the status ladder reaches `PAPER_AUDITED` only when the verifier itself computed that every ballot style's audit concluded. The encoding gets `AuditManifestFreezeBody` (0x0048, one per style: the sample frame's count and root and the sampling rule as declared integer rounds of cumulative sample size and tolerated discrepancies, each threshold below its size, the designated beacon round), `AuditCommitBody` (0x004E: the dice record, the beacon and the freezes fixed before the beacon is published), `AuditSeedBody` (0x000D), the restricted `SampleOpeningBody` (0x0049, never on the public ledger) and its public reference `SampleOpeningRefBody` (0x004A, in `QuorumSigned`), `SampleComparisonBody` (0x004B), `AuditFindingBody` (0x004C) and `HandCountReportBody` (0x004D); accepting them takes `WitnessedEvent` to version 3, `RosterSigner` to 3 (the auditor role) and `QuorumSigned` to 2. No input of the seed is left to choose once the beacon value can be known: the commit fixes the dice record and the freezes, the seed must name the binding checkpoint (the first valid checkpoint that covers the commit), the binding checkpoint and the commit must be timed strictly before the beacon publication the caller observed, and the beacon's raw output is mapped to 64 bytes by a labelled hash. The verifier recomputes the seed; without the observation the audit cannot conclude. The sample is a partial Fisher–Yates shuffle of the sorted frame driven by a per-style SHA3-512 counter stream with rejection sampling (one hash primitive throughout, specified with independent vectors). Trustees may open only what the audit calls for; a caller with access supplies the restricted bodies, which are reconstructed against the commitments. Every nonzero code counts toward the escalation rule; codes 1 and 2 call for a full comparison of the device and a finding, 5 and 6 hold the box; past the last round each unit's hand count, the legal result, concludes the style. The sample-size formula itself is not checked. An independent review (H1, grinding the seed) led to the commit; see the amendment at the end.

- 상태: 채택
- 날짜: 2026-11-04
- 관련: ADR-0011(감사, 공개 난수), ADR-0020(사유 코드), ADR-0028(버전 번호), ADR-0032(분쟁 단계의 키 규칙), ADR-0034(외부 시점확인), ADR-0035(집계 단계); `ityv-cunit` `rng`(SHA3-512 카운터 생성기); `docs/spec/PROTOCOL.md` §5.2, §12, §14 8항, 부록 A·B·C; `docs/spec/ENCODING.md` §6, §8.33, §8.42, §8.43, §8.63, §8.66–§8.73; `docs/ROADMAP.md` M5 2g

## 맥락

M5 2f까지 검증기는 §14의 1–7항과 9항을 돌리고 `CRYPTO_TALLY_VERIFIED`까지 상태를 냈다. 8항(감사)에는 장부 객체도 검증 단계도 없었고, `ityv-state`의 상태 규칙은 "감사가 규칙상 종료됨"을 호출자가 넘기는 깃발로 받았다. 명세(§12)는 동결·시드·표본·열기·대조·확대의 내용을 말하지만, 인코딩, 시드가 쓰는 체크포인트, 비콘 값의 출처, 표본의 바이트 절차, 제한 등급 열기를 공개 검증자가 어떻게 확인하는지, 표본 크기 공식을 누가 계산하는지, 수검표를 어떻게 싣는지, "종료"가 무엇인지를 정하지 않았다. `AuditSeed`(0x000D)는 등록만 되어 있었다.

## 결정

1. **인코딩(ENCODING §8.66–§8.73).** 모든 본문은 버전 1이다.
   - `AuditManifestFreezeBody`(0x0048): 투표양식 하나의 표본 프레임(포함 기록 수와 정렬 집합 root)과 추출 규칙(규칙 문서 해시, 위험 한도 ppm, 비콘 지정 문서 해시와 회차, 라운드 목록). 라운드는 1–8개이고 라운드마다 누적 표본 크기(1 이상, 엄격히 커짐)와 그 라운드에서 감사를 끝내는 불일치 수의 상한(그 라운드 크기보다 작고, 줄지 않음)이다.
   - `AuditSeedBody`(0x000D, 등록부의 `AuditSeed`): 주사위 기록 해시, 비콘 회차와 값, 체크포인트 해시, 시드.
   - `AuditCommitBody`(0x004E, 감사 약정): 주사위 기록 해시, 비콘 지정 문서 해시와 회차, 모든 동결 본문 객체 해시의 정렬 집합 root, 시각. 시드의 입력 가운데 비콘 값만 빼고 모두를 비콘 공표 전에 고정한다(4항).
   - `SampleOpeningBody`(0x0049, 제한 등급): 표본 기록 하나의 `(option_index, cast_id, r_0..r_{k−1})`. 비밀이므로 복사되지 않고 `Debug`에 선택이 나오지 않으며 해제 때 지운다. 공개 장부에 실리지 않는다.
   - `SampleOpeningRefBody`(0x004A): 공개 장부가 싣는 열기의 흔적. 투표양식, 기록 해시, 제한 본문의 객체 해시. 정족수가 `QuorumSigned`로 서명한다(purpose `sample-opening`, 서명 메시지는 다른 정족수 본문처럼 본문 해시와 참여 구성원 목록).
   - `SampleComparisonBody`(0x004B): 기록 해시, 대조한 열기의 객체 해시, 장치(투표함), 사유 코드 0–6, `transfer_mark`.
   - `AuditFindingBody`(0x004C): 투표양식, 장치, 발견 문서 해시, 시각.
   - `HandCountReportBody`(0x004D): `PaperCountReportBody`와 같은 필드와 규칙. 법적 결과인 수검표는 첫 종이 개표와 다른 질문의 답이므로 스키마를 따로 둔다.
   - 기록 하나에 관한 객체(열기 흔적, 대조)에는 시각이 없다(VC-001). 열기 흔적의 열람 권한은 시드의 날로 확인한다(6항).

2. **서명자와 버전.** 동결, 약정, 시드는 위원회 1과 서로 다른 조직 참관인 2 이상(부록 A "위원회, 참관인"), 대조와 발견은 서로 다른 조직의 감사인 2 이상과 서로 다른 조직의 참관인 2 이상(§12.3 "감사인 2 조직 서명과 열람한 정당 참관인 서명"), 수검표는 종이 보고처럼 그 단위 선관위 위원장 1과 참관인 2 조직이다. 감사인은 명부 역할 6, 이벤트 역할 10으로 둔다. 역할과 본문이 늘어 `WitnessedEvent`의 버전 2 거부 벡터(`role 10`)와 `RosterSigner`의 버전 2 거부 벡터(`role 6`), `QuorumSigned`의 버전 1이 거부하던 본문이 정상 입력이 되므로 세 스키마를 각각 버전 3, 3, 2로 올렸다(ADR-0028, ADR-0035 3항과 같은 이유). 서명 키는 다른 단계와 같다: 위원회는 genesis 본문의 키, 그 밖의 서명자는 그 프레임에 시행 중인 상태 또는 그 앞 상태의 명부 항목 가운데 서명이 맞는 것(새 상태부터), 역할과 조직은 시행 중인 상태의 명부가 정한다.

3. **표본 프레임과 동결.** 투표양식의 프레임은 genesis 마지막 상태에서 그 투표양식인 모든 보고 단위의 포함 기록(집계 단계의 재계산)을 합쳐 정렬한 것이다. 투표양식마다 동결 하나를 받으며, 그 투표양식의 모든 단위의 `TallyScope`가 앞 프레임에 받아들여진 뒤에만 받는다(`RLA`, 그 날). 동결의 수와 root가 재계산과 다르면 받되 그 투표양식을 보류하고(`AuditFrameMismatch`) 표본을 뽑지 않는다. 약정이 모든 동결을 기다리므로(4항) 약정 뒤의 동결은 언제나 같은 투표양식의 두 번째 동결이다(반복 또는 충돌).

4. **약정, 고정 체크포인트, 시드(VC-045).** 비콘 값을 알 수 있게 된 뒤에는 시드의 어떤 입력도 고를 수 없어야 한다. 비콘 값은 시드 앞에 공개되고, 운영자는 체크포인트를 언제 자를지 정하며, 주사위 기록 해시는 그 전 어디에도 고정되어 있지 않았으므로, "시드 앞 마지막 체크포인트"를 쓰던 처음 규칙은 비콘 값을 본 운영자가 체크포인트를 더 자르거나 다른 주사위 기록을 시도해 특정 기록을 피하는 표본을 고르게 했다(k번 시도하면 위험 한도 1 %가 대략 1 − 0.99^k가 된다). 그 규칙은 시드에 서명하는 동안 체크포인트가 하나 더 수록되면 정직한 시드도 거부해 보류를 영구히 남겼다. 그래서:
   - **약정.** 선거마다 `AuditCommit` 하나. 모든 투표양식의 동결이 앞 프레임에 있을 때만, 비콘 지정 문서와 회차가 모든 동결의 것과 같고 `freezes_root`가 받아들인 동결 본문 객체 해시들의 정렬 집합 root일 때만 받는다. 서명은 시드와 같다(위원회 1, 서로 다른 조직 참관인 2 이상, `RLA`). 둘째 약정은 반복 또는 충돌이며 보류다(`AuditCommitRefused`).
   - **고정 체크포인트.** 약정을 덮는(`tree_size`가 약정의 프레임 이상인) 첫 유효 체크포인트. 검증기가 체크포인트 사슬에서 결정적으로 정하고 시드는 그 본문 해시를 적는다. 나중의 체크포인트는 아무 영향이 없다. 시드는 약정과 고정 체크포인트가 앞 프레임에 있을 때만, 주사위 기록 해시와 비콘 회차가 약정의 것일 때만 받는다.
   - **시각.** 체크포인트의 `time_bucket`은 증인 정족수가 증언하는 시각이다: 증인은 자기 시계의 구간 `now`에 대해 `now − 1 ≤ time_bucket ≤ now`(`WITNESS_TIME_TOLERANCE` = 1)이고 직전 서명 이상일 때만 서명하고, 체크포인트 사슬의 `time_bucket`은 줄지 않는다(PROTOCOL §5.4, VC-012, 개정 2). 고정 체크포인트의 시각은 약정의 시각 이상이어야 하고(`Backdated`) 공표 구간보다 `WITNESS_TIME_TOLERANCE + CLOCK_ERROR_BUCKETS + 1` 이상 앞서야 한다(`binding ≤ published − 3`). 논증: 정직한 증인은 시계가 `B + 1` 이하를 읽을 때만 구간 `B`에 서명한다(`now − 1 ≤ B`). `B ≤ P − 3`이면 그 시계는 `P − 2` 이하를 읽고, 시계 오차가 1분 이하이므로 실제 시각은 구간 `P − 2`의 끝에 1분을 더한 것 이하, 곧 구간 `P`의 시작 전, 따라서 공표 순간 `T_pub` 전이다. 어떤 정족수에도 정직한 증인이 있으므로(`q > f`) 받아들여진 고정 체크포인트는 `T_pub` 전에 서명되었다. 허용을 1구간만 두면(`binding + 1 < published`) 1분 이내로 늦은 정직한 증인이 공표 직후에도 `P − 1`을 읽고 `P − 2`에 서명하므로 모자랐다(셋째 리뷰, 개정 3). 호출자는 관찰한 비콘 공표를 `(회차, 출력, 공표 time bucket)`으로 넘긴다(`AuditInput::beacon`, genesis 핀처럼 검증 대상 밖의 값). 약정의 시각 구간은 공표 구간보다 엄격히 앞서야 하며, 아니면 그 약정이나 시드를 거부하고 보류한다(`Late`). 공표 구간은 그 회차의 값을 알 수 있게 된 가장 이른 순간(예정 공표 시각, 실제 공표가 더 이르면 그 시각)을 UTC로 잡아 `election_epoch_day` 00:00 UTC부터의 15분 구간 번호로 내림한 것이다. 빈 출력은 관찰이 아니다(`Beacon`). 관찰이 없으면 감사는 종료되지 않고 아무것도 보류하지 않는다. 외부 시점확인(ADR-0034)이 연결되면 이 비교에서 체크포인트의 시각 구간은 그 시점확인 시각으로 바뀐다(ROADMAP).
   - **비콘 값.** 공표 출력의 폭은 비콘마다 다르므로 `beacon_value = SHA3-512("ityv:beacon:v1" ‖ 0x00 ‖ u32_be(len(source)) ‖ source ‖ u64_be(round) ‖ output)`로 64바이트를 만든다(`source`는 비콘 지정 문서 해시 64바이트). 출처와 회차를 묶으므로 다른 비콘이나 회차의 출력은 같은 값이 되지 않는다. 검증기가 호출자의 출력에서 이 값을 계산해 시드의 값과 대조한다. 독립 계산 벡터는 `ityv-crypto` `sample`에 있다.
   - **시드.** `seed = SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice ‖ beacon_value ‖ binding_checkpoint_hash)`, 검증기가 다시 계산한다. 다른 회차의 관찰은 이 회차의 관찰이 아니다.

5. **표본(VC-046).** 표본 흐름은 SHA3-512 카운터 모드다: 투표양식마다 열쇠 `SHA3-512("ityv:sample:v1" ‖ 0x00 ‖ seed ‖ u32_be(len(style)) ‖ style)`, 블록 `i`는 `SHA3-512(열쇠 ‖ u64_be(i))`, 흐름은 블록을 이어 붙인 것이고 8바이트씩 big-endian `u64`로 읽는다. `below(n)`은 낱말 `x`를 `x ≤ 2^64 − 1 − (2^64 mod n)`일 때 받아 `x mod n`을 내고, 아니면 버리고 다음 낱말을 읽는다(최대 64번, 넘으면 표본 실패). 표본은 정렬된 프레임 `0..N`에 대한 부분 Fisher–Yates다: `i = 0, 1, …`마다 `j = i + below(N − i)`, 위치 `i`와 `j`를 바꾸고 위치 `i`의 값을 뽑는다. 그래서 한 기록은 한 번만 뽑히고(비복원), 라운드 `r`의 표본은 처음 `min(크기_r, N)`개이며 확대된 표본은 앞의 표본으로 시작한다. 명세가 말한 SHAKE256 대신 SHA3-512 카운터를 쓴 것은 해시 기본 연산을 하나로 두기 위해서다. `shake` 0.1.0은 ML-DSA·ML-KEM을 거쳐 이미 `Cargo.lock`에 있지만 `ityv-crypto`의 직접 의존성이 아니고, 직접 의존성 추가는 검증 의무다(CONSTITUTION §1.10). SHA3-512 카운터 구성은 이미 TCB에 있고(커밋먼트 유닛 생성기, `ityv-cunit` `rng`) 이 명세에 독립 계산 벡터와 함께 정해져 있다. 독립 리뷰가 이 흐름이 건전하고 편향이 없으며 따로 다시 구현할 수 있음을 확인했다. 가정은 같다(Keccak 해시를 무작위 오라클로 봄). 시험 벡터는 Python `hashlib`로 명세에서 따로 계산했다(`ityv-crypto` `sample`, `ityv-verify` `audit` 단위 시험).

6. **표본 열기와 제한 본문(VC-047, VC-059).** 공개 장부에는 정족수가 서명한 열기 흔적(제한 본문의 해시를 담은 `SampleOpeningRefBody`, 1항)만 실리고 제한 본문은 실리지 않는다. 0x0049 프레임은 검증기가 모르는 장부 이벤트라 장부를 보류한다(`OPAQUE_SCHEMAS`에 넣지 않는다). 흔적은 시드 뒤, 시드의 날에 `OBSERVER_ACCESS`가 있을 때(열람은 그 범위로 한다, §12.3), 접근구조의 자격 정족수가, 기록마다 한 번, 감사가 부르는 기록에만 받는다: 지금 대조 중인 라운드의 표본, 또는 전수 대조 중인 장치의 기록. 그 밖의 열기는 선택을 열람자에게 드러내므로 받지 않고 보류한다(`NotCalled`). 그래서 운영 절차는 한 라운드의 열기 흔적을 모두 그 라운드의 대조보다 먼저 싣는 것이다. 대조로 단계가 넘어간 뒤에는 감사가 더는 부르지 않는 기록의 흔적을 받지 않으며 보류가 남는다(규칙은 그대로 둔다: 늦은 열기도 선택을 드러낸다). 열람 권한이 있는 검증기는 `StyleAudit::reconstructions`와 `AuditStage::all_reconstructed`로 제한 본문을 일부만 받았는지 모두 받았는지 구분한다. 열람 권한이 있는 호출자는 제한 본문을 `AuditInput::openings`로 넘기고, 검증기는 흔적이 가리키는 해시의 본문마다 선거·투표양식·기록이 맞는지, 정확히 `k`개의 canonical 스칼라와 선택지·`cast_id`가 기록의 모든 커밋먼트를 여는지 확인한다(`Reconstructed`/`Mismatch`, 불일치는 `SampleOpeningMismatch` 보류). 공개 검증자에게는 `NotSupplied`이며 그래도 `PAPER_AUDITED`에 이를 수 있다: §14 8항은 공개 검증자에게 존재와 서명을, 열람 권한이 있는 검증기에게 재구성을 맡긴다. 검증기의 출력에는 열린 값이 없다.

7. **대조와 사유 코드.** 대조는 그 기록의 흔적이 앞 프레임에 있고 그 흔적의 열기 해시를 적었을 때, 장치가 기록의 투표함일 때만 받는다. 0이 아닌 모든 코드가 확대 규칙에 들어간다(§12.4). 코드 1·2는 그 장치를 전수 대조에 두고(VC-074), 전수 대조는 그 투표함의 프레임 기록이 모두 대조되고 첫 코드 1·2 뒤 프레임에 그 장치의 `AuditFinding`이 있을 때 끝난다. 코드 3·4는 장치별로 센다(모델은 genesis에 없어 모델별 합은 내지 않는다). 코드 5·6은 그 투표함과 투표양식을 보류한다(`AuditCustody`). `transfer_mark`는 장치와 투표소별로 센다. 전수 대조 기록 가운데 표본이 아닌 것은 확대 규칙의 수에 들어가지 않는다(규칙의 수는 무작위 표본의 것이다).

8. **확대와 수검표.** 라운드의 수는 누적이다: 라운드 `r`의 대조 수와 불일치 수는 그 라운드 표본(처음 `min(크기_r, N)`개) 안에서 센다. 라운드를 차례로 보아 불일치가 상한을 넘으면 다음 라운드로(표본 전부가 대조되기 전이라도 곧바로), 마지막 라운드를 넘으면 그 투표양식 전체를 수검표한다. 넘지 않은 첫 라운드는 표본이 모두 대조되면 종료다(`ityv_state::audit_phase`, Kani로 정확성 확인). 수검표는 보고 단위마다 `HandCountReportBody` 하나이고, 그 투표양식의 표본이 마지막 라운드를 넘은 대조보다 뒤 프레임에서만 받는다. 수검표가 법적 결과이며 검증기는 그것을 보일 뿐 기계 합계와 비교하지 않는다(다를 수 있어서 수검표를 한 것이다).

9. **표본 크기 공식.** 명세는 `policy_hash` 문서가 공식을 고정한다고 말한다. 검증기는 부동소수점을 쓰지 않고 임의의 문서를 계산할 수 없으므로, 동결이 정수 라운드(누적 크기와 상한)를 선언하고 `rule_hash`로 그 공식 문서를 가리킨다. 검증기는 선언된 규칙대로 표본을 다시 뽑고 확대가 그 규칙을 따랐는지를 확인한다. 선언된 크기와 상한이 공식과 표차·위험 한도에서 나온 값인지는 검증 범위 밖이다(사람이 문서로 확인한다). 규칙 문서 해시, 위험 한도, 비콘 지정은 `StyleAudit::rule`로 보인다. 상한이 라운드 크기 이상이면 모든 표본이 통과하므로 디코더가 거부한다. 사유 코드에는 가중치가 없으므로 선언하는 상한은 가장 나쁜 불일치 유형(표차를 가장 많이 줄이는 코드 1·2)을 가정해 공식에서 정해야 한다.

10. **종료와 상태.** 투표양식의 감사는 다음을 모두 만족할 때 종료다: 동결이 재계산과 같고, 시드가 받아들여졌고 호출자가 같은 비콘 값을 보았으며, 한 라운드가 상한 안에서 종료되었거나 수검표 단계에서 모든 단위의 수검표가 있고, 코드 1·2가 나온 장치마다 전수 대조와 발견이 있으며, 그 투표양식에 보류가 없다. 감사 단계는 모든 투표양식이 종료되고 거부된 이벤트가 없을 때 통과한다. 보고서는 그때만 8단계를 통과로 두며, `ityv-state`의 상태 규칙에서 호출자가 넣던 "감사 종료" 깃발을 없앴다. 그래서 `PAPER_AUDITED`는 1–7단계 통과, 보류 없음, 그리고 검증기가 장부에서 계산한 감사 종료가 있을 때만 나온다. 한 투표양식이라도 미완성이면 보류 없이 `CRYPTO_TALLY_VERIFIED`에 머문다.

11. **거부와 보류.** 받지 못한 이벤트는 모두 목록에 남고 보류한다: 동결 `AuditFreezeRefused`(61), 약정 `AuditCommitRefused`(70), 시드 `AuditSeedRefused`(63), 열기 `SampleOpeningRefused`(64), 대조 `SampleComparisonRefused`(66), 발견 `AuditFindingRefused`(68), 수검표 `HandCountRefused`(69). 불일치는 `AuditFrameMismatch`(62), `SampleOpeningMismatch`(65), `AuditCustody`(67). 시드에서 표본을 뽑지 못하면(거부가 64번 이어지거나 뽑힌 위치가 프레임 밖) `AuditSampleFailed`(71)로 그 투표양식을 보류한다(일어나지 않는 일이지만 조용히 미완으로 두지 않는다). 같은 대상의 둘째 이벤트는 본문이 같으면 반복, 다르면 충돌이다(대상: 투표양식의 동결, 선거의 약정과 시드, 기록의 열기와 대조, 장치·문서의 발견, 단위의 수검표). 보류 사유가 64개를 넘어 `HoldSet`을 128비트로 넓혔다(코드는 빈틈없이 이어진다).

12. **색인.** 대조와 발견은 그 장치(투표함)의 이벤트로, 동결·약정·시드·수검표·열기 흔적은 선거의 이벤트로 색인한다.

## 결과

- 공개 장부와 호출자가 본 비콘 값만으로 누구나 시드와 표본을 다시 계산하고, 열기 흔적과 대조가 표본과 전수 대조가 부르는 기록에 대해 있고 서명되었는지, 확대와 수검표가 선언된 규칙을 따랐는지 확인한다.
- 열람 권한이 있는 검증기는 같은 단계로 열린 값이 기록의 커밋먼트를 여는지 확인한다. 열린 값은 어떤 출력에도 나오지 않는다.
- 감사가 없거나 일부만 된 장부, 비콘 값이 없는 검증은 `PAPER_AUDITED`에 이르지 못한다.

## 한계

- 표본 크기 공식, 위험 한도와 선언된 라운드의 관계는 확인하지 않는다(9항).
- 주사위 기록의 내용과 비콘 값은 검증 대상 밖에서 온다(비콘은 호출자가 보증한다).
- 약정과 고정 체크포인트가 비콘 공표보다 앞서는지는 체크포인트 본문의 시각 구간(증인이 서명한 값)과 호출자가 넘긴 공표 구간으로만 확인한다. 증인이 시각을 속이면 막지 못한다. 외부 시점확인(ADR-0034)이 연결되면 그 시각으로 바꾼다.
- §12.5의 다른 전수 대조 사유(`ScannerQuarantine`, §9.5·§11.3의 장치, `AttestationIncident`)와 §11.5·§10.6 7항의 "표본을 늘림"은 아직 장부 사건이 없어 다루지 않는다(그런 경우는 이미 보류다).
- 모델별 비율(코드 3·4)은 genesis에 장치 모델이 없어 내지 않는다.
- 열람자가 누구였는지는 장부에 없다. 대조에 서명한 참관인이 열람을 증언한다.
- 기록 하나에 관한 이벤트에 시각이 없으므로 열기 흔적의 열람 권한은 시드의 날로만 확인하고, 대조는 서명자만 확인한다. 승인 기간이 끝난 뒤의 열기와 대조는 가려내지 못한다.
- `SampleOpening` 원본의 파기(§15, VC-059)는 검증하지 않는다.
- 명세의 처음 초안이 말한 SHAKE256과 다른 흐름이다(5항). 명세는 이제 SHA3-512 카운터를 정의한다.

## 기각한 대안

- **동결 하나에 모든 투표양식.** `WitnessedEvent` 본문 상한(2,048바이트)을 넘고, 규칙은 투표양식마다 다르다. 기각.
- **제한 본문을 불투명 프레임으로 싣고 서명을 따로 공개.** 프레임이 둘이 되지만 흔적이 이미 본문 해시를 서명으로 고정하므로 결속이 늘지 않는다. 기각.
- **복원 추출(같은 기록을 여러 번).** 기록마다 대조 하나라는 규칙과 반복·충돌 판정이 복잡해진다. 기각.
- **검증기가 공식을 계산.** 부동소수점 금지와 임의 문서 해석 불가. 기각.
- **"감사 종료"를 호출자가 계속 넣기.** 장부와 무관한 주장으로 `PAPER_AUDITED`가 나온다. 기각.
- **시드 뒤의 동결을 따로 거부(`AfterSeed`).** 약정이 모든 동결을 기다리므로 그런 동결은 언제나 두 번째 동결이다. 도달할 수 없는 규칙은 두지 않았다.
- **시드 앞 마지막 체크포인트(처음 규칙).** 비콘 값을 본 운영자가 체크포인트를 더 잘라 표본을 고를 수 있고, 서명 중의 체크포인트 하나가 정직한 시드를 영구히 보류시킨다. 기각(4항, 개정).
- **주사위 기록을 동결에 넣기.** 투표양식마다 동결이 따로 서명되므로 기록 하나를 모두에 반복하고 일치를 따로 확인해야 하며, 동결은 집계 범위 직후라 추첨보다 이를 수 있다. 약정 하나로 모았다.
- **비콘 출력을 그대로 64바이트로 받기.** 비콘마다 출력 폭이 다르고, 출처·회차와 묶이지 않는다. 라벨 붙은 해시로 바꾼다(4항).

## 연결되는 검증

- `ityv-encoding` `tests/m5_audit.rs`, `tests/vectors.rs` `audit`(새 벡터 8개, 약정 포함, 다시 만든 `witnessed_event.txt`·`roster_signer.txt`·`quorum_signed.txt`), Kani `event_codes_are_exact`(역할 10, 명부 역할 6, 사유 코드 0–6), `audit_round_rules_are_exact`(상한이 크기보다 작음 포함).
- `ityv-crypto` `sample` 단위 시험(시드·표본 흐름·비콘 값의 독립 계산 벡터), `tests/proptests.rs` `the_sample_limit_leaves_whole_runs`(받는 낱말이 `bound`의 온전한 런들인지, 128비트로), Kani `sample_accept_limit_is_tight`(모든 `bound`에서 한계가 있고 그 위의 낱말이 `bound`개보다 적음). 한계가 런의 배수라는 나머지 항등식은 Kani의 SAT 백엔드가 10분 안에 끝내지 못해(전 범위, `2^26` 이하, 128비트 몫 증인을 시도) 속성 테스트로 확인한다.
- `ityv-state` `audit` 단위 시험, Kani `audit_phase_is_exact`, `hold_set_is_sticky`(128비트), `status_is_exact`.
- `ityv-verify` `tests/audit.rs`(25개, 실제 OR 증명·커밋먼트·하이브리드 서명: 체크포인트를 더 잘라 시드를 고르는 시도와 다른 주사위 기록이 거부되고 서명 중의 체크포인트는 정직한 시드를 깨지 않음 `the_operator_cannot_grind_the_seed`, 약정의 규칙과 비콘 공표 뒤의 약정·고정 체크포인트 `the_commit_fixes_the_dice_and_the_freezes_before_the_beacon`, 두 보고 단위의 한 투표양식과 단위마다의 수검표, 여러 장치의 전수 대조, 장부에 실린 제한 본문, 디버그 출력, 공급 요약, 큰 프레임), `audit` 단위 시험(표본 벡터).

## 개정 (2026-11-04, 독립 리뷰 반영)

독립 리뷰가 찾은 것과 바꾼 것. 이 ADR의 결정은 위에 고쳐 적었다.

1. **시드 고르기(H1).** 처음 규칙은 시드가 "시드 앞 마지막 유효 체크포인트"를 적게 했다. 비콘 값은 시드 앞에 공개되고 운영자가 체크포인트 시점을 정하며 주사위 기록 해시는 어디에도 먼저 고정되지 않았으므로, 운영자가 비콘 값을 본 뒤 체크포인트를 더 자르거나 주사위 기록을 바꿔 표본을 고를 수 있었다(리뷰의 시험이 확인). 같은 규칙은 서명 중의 체크포인트 하나로 정직한 시드를 영구 보류시켰다. `AuditCommit`(0x004E), 고정 체크포인트, 비콘 공표 시각과의 비교, 비콘 값의 라벨 붙은 사상을 더했다(4항). 디코더와 서명 규칙에 0x004E를 더한 `WitnessedEvent`는 아직 공개 장부에 쓰인 적 없는 버전 3 그대로다.
2. **디버그 출력(M1).** 호출자 입력 `AuditInput`과 `SampleOpeningParts`의 `Debug`가 제한 본문의 바이트와 선택·`cast_id`를 보였다. 둘 다 손으로 쓴 `Debug`로 개수만 보이고, `SampleOpeningParts`는 `Clone`·`Copy`가 아니다.
3. **규모(M2).** 서명 확인마다 모든 genesis 상태의 명부를 다시 만들던 것을 단계마다 한 번으로, 기록과 장치를 선형 탐색하던 것을 색인으로, 프레임 기록마다 해독한 `CastRecord`를 들고 있던 것을 열린 기록만 해독하도록 바꿨다.
4. **빈 규칙(M3).** 상한이 라운드 크기 이상인 라운드를 디코더가 거부하고, 규칙 문서·위험 한도·비콘 지정을 `StyleAudit::rule`로 보이며, 상한은 가장 나쁜 불일치 유형을 가정해야 함을 적었다(9항).
5. **그 밖(L1–L5, INFO).** 열기 흔적의 운영 절차(6항), 공급 요약, 여러 단위·여러 장치·장부의 제한 본문 시험, 문서의 SHAKE256 흔적과 잘못된 ADR-0017 인용, 시범 선거구 추출의 고유 라벨과 영역(PROTOCOL §12.1), SHAKE256을 쓰지 않는 이유의 정정(5항), 비콘 값의 폭(4항), 발견의 선거 확인, 표본을 뽑지 못할 때의 보류(11항).

## 개정 2 (2026-11-04, 둘째 독립 리뷰 반영)

1. **H1이 닫히지 않았다.** 첫 개정은 고정 체크포인트의 `time_bucket`을 증인 시각으로 썼지만, 증인 도구(`WitnessMemory::may_sign`)도 사슬 규칙(`validate_successor`)도 그 값을 확인하지 않았다. 운영자는 비콘 값을 본 뒤 공표 구간보다 작은 아무 구간, 약정을 덮는 아무 크기로 다음 체크포인트 후보를 오프라인에서 만들어 원하는 표본이 나오는 것 하나만 서명받을 수 있었다(VC-013 위반 없음). 그래서 시각을 증인의 의무로 만들었다: 증인은 자기 시계의 허용 범위(1구간) 안이고 직전 서명 이상인 `time_bucket`에만 서명하며(`ityv-ledger` `witness_time_ok`, `WitnessMemory` 버전 2가 마지막 시각을 기억), 사슬은 `time_bucket`이 줄지 않기를 요구한다(줄면 `CheckpointInvalid`, 사슬이 거기서 끝나고 보류). 감사는 고정 체크포인트가 약정 이후이고 공표보다 앞서기를 요구한다(4항; 그 여유는 개정 3에서 3구간으로 고쳤다). 정직한 증인의 시계는 국가표준시를 NTS로 받고 독립된 둘째 원천과 대조한다(PROTOCOL §5.4).
2. **위협의 경계.** H1은 이제 증인 정족수의 시각 증언에 기댄다. 공모한 증인 정족수는 시각을 거슬러 서명할 수 있지만, 그런 정족수는 이미 장부를 분기할 수 있고 그것은 허용하는 공모 집합 밖이다(ADR-0018, VC-013). 외부 시점확인(ADR-0034)이 연결되면 고정 체크포인트는 `latest()`가 공표보다 앞서는 TSA 토큰도 지녀야 하고, 그때부터 이 조건은 증인에게 기대지 않는다(ROADMAP).
3. **살아 있음.** 고정 체크포인트가 늦거나, 지정 회차가 이미 또는 일찍 공표되었거나, 약정 뒤에 범위가 늦게 수록되면 감사는 사유와 함께 `HOLD_REVIEW`로 남는다. 약정을 다시 내는 장치는 두지 않는다(비콘을 본 뒤 고를 입력을 다시 만든다). 운영 절차(약정 직후 체크포인트, 예상 고정 체크포인트보다 3구간과 여유 뒤에 공표되는 회차 지정)와 구제(전수 수검표, 분쟁·법적 결정 절차)를 PROTOCOL §12.1과 GOVERNANCE에 적었다. 비콘이 공표되지 않으면 감사는 종료되지 않는다.
4. **프레임으로 자른 상한.** 디코더는 선언 크기로 상한을 보지만 검증기의 라운드 크기는 `min(크기, 프레임)`이다. `[(10, 5)]`를 기록 3개의 프레임에 쓰면 모두 불일치여도 종료되었다. 동결 때 재계산한 프레임 수로 어느 라운드든 `threshold ≥ min(sample_size, frame)`이면(프레임이 비어 있지 않을 때) 동결을 거부하고 보류한다(`Rule`).
5. **시범 선정.** 같은 고정 절차(약정, 공표 전 고정 체크포인트, 시드)를 명세에 정했다(PROTOCOL §12.1, VC-097). 도구는 M6이다.
6. **그 밖.** 공표 구간의 정의(UTC, `election_epoch_day` 기준 15분 구간, 값을 알 수 있게 된 가장 이른 순간), 명부를 서명자별로 한 번 색인, 선거 불일치의 고유 거부(`Election`), 아무것도 열지 않았을 때 `all_reconstructed`는 거짓, 빈 비콘 출력 거부, 문서의 낡은 표현.

## 개정 3 (2026-11-04, 셋째 독립 리뷰 반영)

1. **경계의 여유(H1).** 개정 2는 고정 체크포인트가 `binding + 1 < published`이면 된다고 보았지만, §5.4가 허용하는 정직한 시계 오차(1분)를 빠뜨렸다. 1분 늦은 증인은 공표 직후 1분 동안 `P − 1`을 읽고 `P − 2`에 서명하므로, 비콘 값을 아는 운영자가 본문(채움 체크포인트, 또는 `P − 2`로 적은 약정)을 골라 `PAPER_AUDITED`에 이를 수 있었다(리뷰의 P6, P6b). `CLOCK_ERROR_BUCKETS` = 1(정직한 시계 오차 1분 이하가 15분 구간보다 작아 구간 경계 하나만 넘을 수 있음)을 두고 `binding + WITNESS_TIME_TOLERANCE + CLOCK_ERROR_BUCKETS < published`(`binding ≤ P − 3`)를 요구한다. 논증은 4항에 적었다. 운영 여유(3구간에 1시간)는 그대로 이것을 덮는다.
2. **위협의 경계(보강).** 공모한 증인 정족수가 시각을 거슬러 서명한 고정 체크포인트는 흔적을 남기지 않는다. 분기는 분할 보기 감시(장부 교환, ADR-0018)가 찾아내지만, 거슬러 적은 시각은 사슬 안에서 다른 정상 체크포인트와 구별되지 않는다. 그러므로 이 경로는 증인 정족수의 정직에만 기대며, 외부 시점확인(ADR-0034)이 연결되어 고정 체크포인트가 `latest()`가 공표보다 앞서는 TSA 토큰을 지녀야 할 때 비로소 사라진다.
3. **증인의 따라잡기.** 시각 조건 때문에 자리를 비운 증인은 놓친 체크포인트에도 그 다음에도 서명할 수 없어, 체크포인트를 수록하는 동안 한 구간 넘게 자리를 비운 증인은 선거 끝까지 빠졌다(13/9/4에서 다섯이면 체크포인트가 멈춘다). `WitnessMemory::adopt`가 정족수 서명이 검증된 체크포인트를 서명 없이 받아들여 기억을 전진시킨다(PROTOCOL §5.4, ADR-0016 4항).
4. **VC-116의 허용.** 시계가 1분 이내로 앞서는 증인은 구간의 마지막 1분에 다음 구간을 증언하므로 그 직후의 TSA 토큰은 체크포인트보다 한 구간 앞에 놓인다. 토큰 구간에 `CLOCK_ERROR_BUCKETS`를 더해 비교한다(PROTOCOL §5.5, ADR-0034).
5. **문서.** 낡은 "공표보다 엄격히 앞섬", 테스트 세계의 "READY + 1", ADR-0035의 남은 후속 문장, 시범 선정의 여유·정렬 키·비교군(ADR-0026의 도구에 맡김, ROADMAP M6).

## 개정 4 (2026-11-04, 넷째 독립 리뷰 반영)

넷째 리뷰는 여유가 건전함을 확인했다(1초 단위 전수 모의에서 공표 뒤 서명된 고정 체크포인트는 하나도 받아들여지지 않음). 바꾼 것은 따라잡기다.

1. **빈 기억에서의 받아들임(M1).** 증인이 공개되지 않은 X에 서명한 뒤 기억을 잃고 빈 기억에서 공표된 직전 체크포인트를 받아들이면, 같은 순번에 Y에 서명할 수 있다. 비잔틴 증인과 함께 두 정족수가 생기고, 감사에서는 X와 Y가 모두 `P − 3` 이하의 고정 체크포인트가 될 수 있어 운영자가 비콘을 본 뒤 고를 수 있었다(되감은 백업도 같다; TLC로 확인). `adopt`는 빈 기억을 거부한다(`NoMemory`). 기억을 잃거나 되감긴 증인은 그 선거 동안 f에 센다; 빈 기억으로 받아들이는 길은 없다; 한 번도 서명하지 않은 증인도 시작부터 함께하지 못했으면 f에 센다. 시각 간격을 이용한 복구는 모델 검사 뒤의 과제로 남겼다(ROADMAP).
2. **증인 집합에의 결속(L1).** `Verified<Published>` 토큰은 아무 명부로나 만들 수 있었다. `adopt`는 genesis에서 한 번 만든 `WitnessSet`(genesis 해시, 식별자, 명부, 프로필, 다양성)으로 `evaluate`를 직접 돌린다.
3. **분기 알림(L2).** 받아들이는 것은 자기 다음부터의 열이고 첫 것의 이전 해시가 자기 본문이어야 한다. 다르면 `SplitView`(VC-065의 증거: 자기 본문과 정족수 서명 후속).
4. **시각의 위 한계(I1).** 증언하는 정직한 증인은 자기 시계 구간까지만 서명하고 두 정직한 시계는 한 구간 넘게 어긋나지 않으므로 `now + CLOCK_ERROR_BUCKETS`보다 늦은 체크포인트는 경보 `TimeAhead`로 거부한다.
5. **문서(L3, I3–I6).** VC-116 허용을 ADR-0034와 FAILURE_CASES에도 적고 TSA 정확도 조건을 더했다. TLA+ 모델에 `HonestAdopt`. 앞선 시계의 추가 여유는 15분이 아니라 1분(최악 46분). 시범 추출의 정렬은 길이 접두 없는 식별자 바이트, 층 변수 이름은 `u`.

