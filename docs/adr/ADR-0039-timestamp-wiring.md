# ADR-0039: 시점확인의 연결 — genesis 기관 목록, `TimestampRecord`, 체크포인트 판정, 감사 고정 체크포인트

> English summary: Step M5 2h wires ADR-0034's external timestamps into the ledger and the verifier, through `ityv-tsa`'s public API only (`PinnedTsa::from_bytes`, `verify_token`, `Imprint::of`, `VerifiedTimestamp`). The genesis gets a twelfth entry set, fixed for the election: `TimestampAuthorityEntry` (0x0050), one per authority, with its operator, whether the government runs it, the accuracy its policy guarantees for tokens that state none, and one to four `ityv-tsa` pins, one per signing certificate, so that a certificate can rotate without an amendment; `GenesisBody` goes to version 7. The genesis stage refuses a pin `ityv-tsa` does not read, one that does not allow SHA-512, one without its certificate, or one under which no token could verify (no allowed signature algorithm that the certificate's key makes over an allowed digest); a certificate or a public key pinned twice; a declared accuracy outside one second to one minute; an operator, compared without regard to ASCII case, with authorities of both kinds; an operator that is a witness's or an election commission's organisation; and a set without a government and a non-government authority (VC-114). The kind is the genesis's declaration, which the verifier cannot check. A `TimestampRecord` (0x004F) ledger event carries one authority's token over one earlier ledger event, named by its schema and object hash (the frame's `event_hash`): a signed checkpoint, a signed genesis or amendment, or a witnessed legal decision (and, from Part B, a voter-roll event); the decoder refuses any other top-level schema and the verifier any other witnessed body (VC-117). A record without a token is the operator's note that the authority did not answer. A record whose authority is not pinned, whose target is not an earlier accepted event of a stamped kind, or whose token does not verify under any of the authority's pins over SHA-512 of the target hash is listed and holds the ledger (`TimestampInvalid`, 72). Every rule judges a token by the latest instant its authority allows (`genTime` plus the larger of the stated and the declared accuracy; a token stating more than a minute is refused), the conservative direction for each rule: a valid token over a checkpoint whose latest instant's bucket plus `CLOCK_ERROR_BUCKETS` is below the checkpoint's bucket ends the chain there (`TimestampMismatch`, 73; VC-116); a checkpoint is anchored when tokens of a government and a non-government authority of two operators have their latest instant within its bucket plus `ANCHOR_WINDOW` (VC-115). The verifier now decides the ledger's anchor deadline from the tokens of the last valid checkpoint, which covers every earlier one, and uses the caller's clock only to tell an open window from a missed one (`Publications { now, board }` replaces the caller's anchor status). Timestamp records after the last checkpoint do not keep step 2 from passing, since the last checkpoint's tokens can only follow it. The audit's binding checkpoint must now also carry, in frames before the seed, tokens of a government and a non-government authority of two operators whose latest instant is before the publication bucket begins (`AuditRefusal::Unstamped`). This is required, not "when present": a "when present" rule lets the operator who withholds the tokens fall back to the witnesses' time, which is what the rule removes; the liveness cost is the bucket rule's (a binding checkpoint stamped within 45 minutes, which the operator controls), with the same remedy (hold, full hand count). The bucket rule stays as well, so a seed chosen after the beacon now needs both the witness quorum and two timestamp operators of both kinds to lie.

- 상태: 제안
- 날짜: 2026-11-04
- 관련: ADR-0028(genesis 형식, 버전 번호), ADR-0034(시점확인), ADR-0036(감사, 4항과 개정 2·3), ADR-0037(`ityv-tsa`, 9항의 연결 단계 기록); `docs/spec/PROTOCOL.md` §4.1, §5.4, §5.5, §12.1, §14 2항·끝; `docs/spec/ENCODING.md` §6, §8.54, §8.74, §8.75; 법령 개정안 15; VC-114..118

## 맥락

ADR-0034는 체크포인트, genesis와 변경, 명부 동결과 보관 영수증, 법적 결정에 서로 다른 운영 주체의 시점확인 토큰을 받게 하고, 검증기가 그 토큰으로 역산 금지(VC-116)와 앵커 기한(VC-115)을 스스로 판정하게 했다. ADR-0037은 토큰 하나를 검증하는 `ityv-tsa`를 만들고, 연결 단계가 지킬 것을 9항에 적었다: 시각은 구간이고, 토큰 바이트는 유일하지 않아 기관 단위로 세며, 기대 nonce는 받지 않고, 인증서가 바뀌면 핀이 여럿 필요하다. ADR-0036은 감사의 고정 체크포인트가 비콘 공표보다 앞섬을 증인의 시각 증언으로만 확인하며, 시점확인이 연결되면 `latest()`가 공표보다 앞서는 토큰도 요구하라고 남겼다(4항, 개정 2·3).

정해지지 않은 것: genesis 안의 기관 목록의 자리와 형식, `TimestampRecord`의 필드와 대상의 이름 짓기, 토큰이 없는 체크포인트와 마지막 체크포인트의 기한, 정확도를 밝히지 않은 토큰의 구간, 한 기관의 토큰이 여럿일 때와 같은 운영 주체의 기관이 여럿일 때, 거부와 보류, 고정 체크포인트 토큰을 필수로 할지와 버킷 규칙과의 관계.

## 결정

1. **genesis의 기관 목록(집합 12, 고정).** 기관마다 `TimestampAuthorityEntry`(0x0050, 열쇠 `tsa_id`) 하나: 기관 ID(`AuthorityId`), 운영 주체(`OrgId`), 구분(1 정부 운영, 2 정부 밖), 정확도(밀리초; 인코딩은 0–3,600,000, 검증기는 1,000–60,000만 받는다, 2·5항), 핀 1–4개(`ityv-tsa`의 핀 바이트, 각 1–16,952바이트, 바이트 엄격 오름차순). ENCODING §8.74.
   - 집합으로 둔다. 핀 하나가 인증서를 담으면 16 KiB를 넘을 수 있어 본문(16 KiB)에 들어가지 않고, 항목 집합은 ADR-0028의 방식 그대로다.
   - 고정이다(9–12번 집합). 개정안 15 ②가 "기관의 목록과 서명 인증서는 … 선거 전에 기준정보에 고정한다"고 하고, ADR-0037 9항이 인증서 교체를 핀 여럿으로 다룬다. 그래서 `GenesisAmendmentBody`는 바뀌지 않는다.
   - 정확도는 기관이 보장하는 정확도다(RFC 3161 §2.4.2는 정확도를 정책으로 정하게도 한다, ADR-0037 9항). 핀은 정책을 8개까지 허용하고 정책은 요청자가 고르므로, 이 값은 핀이 허용하는 모든 정책의 정확도를 덮어야 한다(가장 거친 것 이상). 토큰이 정확도를 밝혀도 이 값보다 작게 쓰지 않는다(5항). 0은 받지 않는다: 시각이 정확한 기관은 없고, 0이면 정확도를 밝히지 않은 토큰의 구간이 한 점이 된다.
   - 집합이 늘어 본문의 모양이 바뀌므로 `GenesisBody`는 버전 7이다(ADR-0028 결과 항목의 규칙). 버전 6 본문은 버전 7 디코더가 받지 않는다.

2. **genesis 규칙(VC-114).** genesis 단계가 집합 전체를 본다(`Rule::*`).
   - `TimestampAccuracy`: 정확도가 1초(`MIN_POLICY_ACCURACY_MS`)보다 작거나 1분(`MAX_TIMESTAMP_ACCURACY_MS`)보다 크다. 1분은 정직한 증인 시계의 상한과 같은 값이다. 가장 늦은 순간이 그만큼만 늦어지므로 앵커 창과 감사의 공표 전 규칙(8항)이 정직한 기관에게 열려 있다. RFC 3161 기관은 대개 1초 이하를 밝힌다.
   - `TimestampPin`: 핀을 `PinnedTsa::from_bytes`가 읽지 못하거나, 허용 다이제스트에 SHA-512가 없거나(모든 각인이 SHA-512다, ADR-0034 3항), 인증서 사본이 없거나, `PinnedTsa::signer_key`가 키를 주지 않는다: 사본이 서명자 인증서로 읽히지 않거나, 허용된 서명 알고리즘 가운데 그 키가 만들고 그 다이제스트도 허용된 것이 없다. 어느 경우든 그 핀으로는 어떤 토큰도 검증되지 않거나 키를 비교할 수 없다. ESS v2는 허용된 어느 다이제스트로도 쓸 수 있고 SHA-512가 늘 허용되므로 따로 막히지 않는다.
   - `TimestampCertificate`: 두 핀이 같은 서명 인증서(SHA-256)를 가리킨다. 한 기관이 둘로 셀 수 있다.
   - `TimestampKey`: 두 핀의 인증서가 같은 공개키(`SubjectPublicKeyInfo`)다. 한 서명자가 두 인증서로 두 기관이 될 수 있다. 한 기관 안에서도 거부한다: 인증서를 바꿀 때는 키도 바꾼다.
   - `TimestampOperator`: 같은 운영 주체의 기관이 정부 운영과 정부 밖으로 나뉜다. 운영 주체는 정부이거나 아니다. 운영 주체는 이름으로 비교한다: ASCII 대소문자와 구분 기호 `.`·`_`·`:`·`-`를 무시한다. `MOIS-GPKI`, `mois-gpki`, `MOIS_GPKI`는 한 운영 주체이고, 앵커에서도 하나로 센다(명부 보관 기관의 조직과 같은 함수, ADR-0040).
   - `TimestampOperatorConflict`(genesis의 모든 상태에서, 집합 사이 규칙): 운영 주체가 증인의 조직, 서명자 명부의 조직(사무원·참관인·보관 담당자·법원·위원장·감사인), 보고 단위가 가리키는 선관위의 조직 가운데 하나다(이름으로 비교). 토큰은 증인의 시각과 선관위의 기록을 확인하므로 그 운영 주체는 그들이 아니어야 한다. genesis에는 중앙선관위 자체의 조직 ID가 없어(본문은 선관위의 키만 담는다) 보고 단위의 구·시·군 선관위 조직과 비교한다.
   - `TimestampAuthorities`: 정부 운영 기관이나 정부 밖 기관이 없다.
   - 같은 운영 주체·같은 구분의 기관 여럿은 받는다. 앵커에서 하나로 센다(5항).

3. **`TimestampRecord`(0x004F, 장부 이벤트).** 선거, 대상 이벤트의 스키마(프레임이 적은 것)와 객체 해시(프레임의 `event_hash`), 기관 ID, 토큰(`Option<Bytes<16384>>`). ENCODING §8.75.
   - 기록 하나에 기관 하나, 토큰 하나다(ADR-0034 3항: "대상 객체의 스키마와 해시, 기관 ID, DER 토큰 바이트"). 기관 단위로 세는 규칙이 기록의 모양에 그대로 맞는다.
   - 대상은 장부의 이벤트다. 체크포인트는 `SignedCheckpoint` 이벤트(본문과 증인 서명)의 객체 해시이므로 토큰은 본문만이 아니라 정족수의 서명이 그 시각에 있었음을 보인다. genesis와 변경은 `SignedGenesis` 이벤트, 법적 결정은 그것을 실은 `WitnessedEvent`다. 각인은 대상 해시 64바이트의 SHA-512다.
   - 대상 스키마는 0x0010, 0x0028, 0x0033뿐이다(디코더가 거부, Kani `timestamp_rules_are_exact`). `WitnessedEvent`는 법적 결정 본문일 때만 받는다(명부 사건은 ADR-0040이 더한다). 투함 기록·확인 카운터·진행 기록은 어느 쪽으로도 대상이 될 수 없다(VC-117).
   - 토큰이 없는 기록은 운영자가 남긴 "응답 없음"(ADR-0034 3항)이다. 검증기는 목록으로만 보이고 보류하지 않는다. 시각의 증거가 아니기 때문이다. 다만 기관과 대상은 토큰이 있는 기록과 같이 확인한다(4항): 없는 이벤트, 시점확인을 받지 않는 종류, 뒤에 실린 이벤트를 대상으로 한 "응답 없음"은 거짓 진술이므로 거부하고 보류한다.
   - 자기 서명은 없다. 토큰이 기관의 서명이고, 프레임은 증인의 체크포인트가 덮는다.

4. **기록의 검증과 거부.** `verify_timestamps`가 모든 기록을 프레임 순으로 읽는다. 기관, 대상, 토큰의 순서로 확인하며 토큰이 없는 기록도 앞의 둘을 거친다. 기관이 genesis에 없으면 `Authority`, 대상이 색인이 받은 앞 프레임의 그 스키마·해시 이벤트가 아니거나 시점확인을 받는 종류가 아니면 `Target`, 기관의 어느 핀으로도 토큰이 검증되지 않으면 `Token(오류)`(핀이 토큰의 서명자가 아니라는 것만 말하는 `CertificateNotPinned`·`SignerIdentifierMismatch`가 아닌 첫 오류, 없으면 첫 오류. 핀이 인증서 사본을 지니므로(2항) 다른 서명자의 토큰은 사본이 대신 쓰여 `SignerIdentifierMismatch`가 된다)이다. 받지 못한 기록은 모두 목록에 남고 장부 전체가 `HOLD_REVIEW`다(`TimestampInvalid`, 72). 사슬은 끝나지 않는다. 토큰은 보강 증거이며 신뢰의 뿌리가 아니다(ADR-0034 5항). nonce는 확인하지 않는다(ADR-0037 9항: 요청한 운영자가 맞춰 본다).

5. **시각과 세 비교.** 받아들인 토큰의 시각은 기관의 주장이 허용하는 가장 늦은 순간이다: `genTime` + 토큰이 밝힌 정확도(`VerifiedTimestamp::latest`)와 genesis 항목의 정확도 가운데 큰 것. 토큰이 정확도를 밝히지 않았거나 작게 밝혔어도 기관이 보장하는 정확도보다 좁게 보지 않는다. 1분보다 큰 정확도를 밝힌 토큰은 받지 않는다(`TimestampProblem::Accuracy`, 보류 `TimestampInvalid`). 구간 경계가 정수 초이므로 정수 초(내림)로 둔다. 세 규칙 모두 이 순간과 구간 시작을 비교한다(`start(k) = election_epoch_day·86400 + 900k`, 1970년 이전·epoch 이전 구간도 부호 있는 정수로, Kani `token_bucket_comparison_is_exact`).
   - **역산 금지(VC-116).** 체크포인트 구간 `B`에 대해 `b(latest) + CLOCK_ERROR_BUCKETS < B`, 곧 `latest < start(B − 1)`이면 역산이다. 정직한 경우의 하한: 정직한 증인의 시계는 1분 이내로 앞서므로 `B`의 시작 1분 전보다 일찍 `B`에 서명하지 않고, 그 뒤에 요청한 토큰은 정직한 기관이면 그보다 늦게 나온다. 가장 늦은 순간은 그보다도 늦으므로 `B − 1` 이후다. 정확도는 구간을 위로만 넓히므로 정직한 체크포인트를 역산으로 보이게 하지 않는다. PROTOCOL §5.5의 "허용을 그만큼 넓히거나 받지 않는다" 가운데 넓히는 쪽이다.
   - **앵커 창(VC-115).** `b(latest) ≤ B + ANCHOR_WINDOW`, 곧 `latest < start(B + 5)`.
   - **고정 체크포인트(7항).** `latest < start(P)`.
   - 가장 늦은 순간은 세 규칙 모두에서 보수적인 쪽이다: 역산 판정을 늦추고(오판 없음), 앵커와 공표 전 판정은 어렵게 한다.

6. **체크포인트마다.** 증인 규칙을 통과한 체크포인트에 대해:
   - 그 `SignedCheckpoint` 이벤트를 대상으로 한 유효 토큰 가운데 하나라도 역산이면 그 체크포인트에서 사슬이 끝나고(`CheckpointFindingKind::Backdated`, 뒤 체크포인트는 확인하지 않음) 장부가 `HOLD_REVIEW`다(`TimestampMismatch`, 73). 토큰은 어느 프레임에 실렸든 센다. 서명된 시각이 증거이고 프레임의 위치는 아니다.
   - 앵커(`VerifiedCheckpoint::anchoring`): 창 안의 유효 토큰이 정부 운영 기관과 정부 밖 기관에서 왔고 운영 주체가 둘 이상이면 충족이다. 한 기관의 토큰 여럿, 한 기관의 인증서 둘, 같은 운영 주체의 기관 둘은 각각 하나로 센다(ADR-0037 9항).
   - 결과: 한 기관이 어떤 체크포인트에든 이른 시각의 토큰을 내면 장부가 보류된다. ADR-0034 7항과 FAILURE_CASES §8이 정한 그대로이고 실패를 닫는 쪽이다. 그 토큰은 증인들이나 그 기관 가운데 하나가 시각을 속였다는 증거다.

7. **장부의 앵커 기한.** 검증기가 마지막 유효 체크포인트의 토큰으로 정한다(`CheckpointChain::anchor_deadline(now)`). 마지막 체크포인트는 그 앞의 모든 체크포인트를 덮으므로, 앞의 체크포인트가 토큰을 받지 못했어도 마지막 것이 앵커되면 장부의 앵커는 충족이다(앞 것의 앵커 결과는 그대로 보인다). 마지막 것이 앵커되지 않았으면 호출자의 지금 시각이 `B + ANCHOR_WINDOW` 안일 때 대기, 넘으면 기한 위반(`AnchorsShort { have: 두 구분 가운데 있는 수, need: 2 }`)이고 상태는 `UNVERIFIED`다(보류 아님, FAILURE_CASES §8). ADR-0034 4항의 "아직 시점확인이 없는 마지막 체크포인트에 대해 … 그때만 호출자의 시계를 쓴다" 그대로다.
   - 호출자는 앵커 상태 대신 지금 시각을 넘긴다: `Publications { now, board }`. 지정 공개 검증자의 수신 게시(§5.5 첫 문단)는 운영 의무로 남지만 검증기의 입력은 아니다.
   - 앞 체크포인트의 앵커는 기한을 정하지 않지만, 체크포인트의 구간을 시각으로 쓰는 규칙은 앵커된 체크포인트만 쓴다(결과, 개정 6항).
   - 마지막 체크포인트 뒤에 체크포인트와 시점확인 기록만 있으면 2단계는 통과다. 마지막 체크포인트의 토큰은 그 뒤에만 실릴 수 있어서 그것까지 덮기를 요구하면 끝이 없다. 시점확인 기록은 기관의 서명된 진술이고 다른 단계가 읽는 장부 내용이 아니다: 빼면 앵커가 모자랄 뿐이고, 위조하면 보류다.

8. **감사의 고정 체크포인트(ADR-0036 4항의 이월).** 시드는 비콘 관찰이 있을 때 고정 체크포인트가 다음을 지닐 때만 받는다: 시드보다 앞 프레임에 실린, 고정 체크포인트(그 `SignedCheckpoint` 이벤트)를 대상으로 한 유효 토큰 가운데, 가장 늦은 순간이 공표 구간의 시작보다 앞서는(`latest < start(P)`) 것이 정부 운영과 정부 밖 기관, 두 운영 주체에서 있다. 아니면 시드를 받지 않고 보류한다(`AuditRefusal::Unstamped`, `AuditSeedRefused`).
   - **필수로 한다.** "있으면 확인"이면 토큰을 싣지 않는 운영자는 증인 시각만의 규칙으로 돌아가고, 이 규칙이 없애려는 의존이 그대로 남는다. 살아 있음: 운영자가 요청 시각을 정하고, 앵커 때문에 토큰은 어차피 한 시간 안에 받으며, 기관은 둘 이상 고정되고 응답이 없으면 다른 기관에 요청한다. 고정 체크포인트는 공표보다 3구간(45분) 이상 앞서야 하므로(버킷 규칙) 그 사이에 두 구분의 토큰을 받으면 된다. 이 시간은 정확도 상한(1분, 2항)이 있어서 생긴다: 구간 `P − 3`의 체크포인트는 그 구간 안에 서명되므로 토큰을 받을 시간은 적어도 30분에서 정확도 1분을 뺀 만큼이다(구간 시작에 서명했으면 45분에서 1분을 뺀 만큼). 정확도가 상한 없이 44분쯤을 넘으면 `latest < start(P)`인 토큰이 있을 수 없다. 놓치면 버킷 규칙을 놓친 것과 같이 보류이고 구제도 같다(전수 수검표, 분쟁·법적 결정, PROTOCOL §12.1).
   - **버킷 규칙과의 관계.** 둘 다 요구한다. 버킷 규칙 `binding ≤ P − 3`은 증인 정족수에 정직한 증인이 있고 그 시계가 1분 이내라는 가정에서 나온다(허용 1구간, 시계 오차 1구간). 토큰 규칙 `b(latest) ≤ P − 1`은 두 기관 가운데 하나가 정직하다는 가정에서 나온다. 토큰은 참 시각의 구간을 말하므로 증인의 허용이나 시계 오차가 필요 없고, `P`가 공표 순간을 내림한 구간이라 `latest < start(P) ≤` 공표 순간이다. 둘을 모두 요구하므로 비콘을 본 뒤 시드를 고르려면 증인 정족수가 시각을 속이고 정부 운영 기관과 정부 밖 기관이 함께 날짜를 거슬러 서명해야 한다. ADR-0036 개정 3의 2항이 말한 "증인 정족수의 정직에만 기대는" 경로가 닫힌다.
   - 시드보다 뒤에 실린 토큰은 세지 않는다. 시드는 실린 때의 장부로 판정하고, 나중의 기록으로 판정이 바뀌지 않는다.
   - 약정 자체의 토큰은 요구하지 않는다. 고정 체크포인트가 약정을 덮으므로 고정 체크포인트가 공표 전에 있었다면 약정도 그렇다.
   - 관찰이 없으면 비교할 공표가 없어 감사가 종료되지 않을 뿐 아무것도 거부하지 않는다(ADR-0036과 같다).

9. **API.** `ityv-tsa`의 공개 API만 쓴다. 바꾼 것: `ityv-tsa`는 처음에는 바뀌지 않았고, 리뷰 반영에서 읽기 전용 `PinnedTsa::signer_key`를 더하고 각인 비교를 서명 앞으로 옮겼다(ADR-0037 1·8항 개정). `ityv-verify`: 새 모듈 `timestamp`(`verify_timestamps`, `TimestampStage`, `StampedToken`, `Anchoring`, `TimestampRefusal`, `TimestampProblem`, `Unanswered`); `CheckpointChain`에 수명 인자와 `timestamps()`·`anchor_deadline(now)`; `VerifiedCheckpoint`에 `event_hash`·`anchoring`; `CheckpointFindingKind::Backdated`; `FixedSets::timestamp_authorities`; `Publications { now, board }`(`anchors` 제거); `AuditRefusal::Unstamped`; genesis 규칙 넷. `ityv-encoding`: `AuthorityId`, `TimestampAuthorityEntry`·`TimestampPins`·`PolicyAccuracy`·`TimestampAuthorityKind`, `TimestampRecord`, `EntrySet::TimestampAuthorities`, `ENTRY_SET_COUNT` 12, `SCHEMA_VERSION_GENESIS` 7. `ityv-state`: 보류 사유 72·73. `ityv-ledger`(리뷰 반영): `check_anchor`·`REQUIRED_ANCHORS` 삭제, `Breach::AnchorsShort`는 앵커 기한의 구분 수. `tools/`와 `apps/`의 genesis 생성과 `Publications` 사용은 이 API에 맞춰야 한다(이 단계에서 바꾸지 않았다).

## 결과

- 체크포인트의 앵커 기한을 검증기가 서명된 시각으로 스스로 판정한다. 호출자의 시계는 마지막 체크포인트가 아직 토큰을 받지 못했을 때 창이 열려 있는지만 가른다.
- 증인 정족수가 공모해 거슬러 적은 체크포인트는 정부 운영 기관과 정부 밖 기관이 함께 날짜를 거슬러 서명하지 않으면 앵커되지 못하고, 한 기관의 정직한 토큰이 역산을 드러낸다.
- 다만 장부의 상태를 정하는 것은 마지막 체크포인트의 앵커뿐이다(7항). 앞 체크포인트가 앵커되지 않아도 장부는 보류되지 않으므로, 증인 정족수가 공모하면 기관이 정직해도 앵커되지 않은 중간 체크포인트의 구간을 거슬러 적을 수 있다. 이것을 받아들이는 대신 체크포인트의 구간을 시각으로 쓰는 규칙은 앵커된 체크포인트만 쓴다. 집계 범위의 증인 시각(VC-057)은 범위보다 앞 프레임의 두 구분·두 운영 주체 토큰으로 앵커된 마지막 체크포인트의 구간이고(그런 체크포인트가 없으면 0이라 범위가 이르다고 거부되고 보류된다), 감사의 고정 체크포인트는 8항의 토큰을 요구한다. 늦은 마감의 24시간(VC-100)은 체크포인트가 아니라 사람이 서명한 마감의 구간으로 재므로 이 시각을 쓰지 않는다. 그래서 거슬러 적은 중간 체크포인트는 장부의 내용을 바꾸지 못하고, 그 체크포인트를 시각으로 쓰려던 사건만 거부된다. 모든 체크포인트의 앵커를 요구하지 않는 이유는 기각한 대안에 있다.
- 감사의 시드 고르기는 증인 정족수와 두 구분의 시점확인 기관이 모두 공모해야 한다.
- 시험은 실제 토큰을 쓴다. `ityv-verify` 시험이 OpenSSL로 시험용 기관(RSA-2048, 2024–2036 유효 인증서)과 토큰을 그 자리에서 만들고, 원하는 구간의 `genTime`을 같은 길이로 적은 뒤 `messageDigest`와 서명을 OpenSSL로 다시 만든다(`ityv-tsa` `forge.py`의 방식). 개인키는 메모리에만 두고 OpenSSL 호출 하나 동안만 임시 디렉터리에 쓰며, 호출이 끝나거나 실패해도(패닉 중에도) 지운다. 디렉터리 이름에는 예측할 수 없는 부분이 있고 그 경로에 아무것도 없을 때만 만든다(기존 디렉터리나 심볼릭 링크를 쓰지 않는다). `ityv-verify`의 통합 시험은 모두 시험 genesis의 기관을 만들므로 PATH의 OpenSSL 3.0 이상이 필요하다. LibreSSL(macOS의 `openssl`)은 `ess_cert_id_alg`가 없어 ESS v1으로 묶으므로 쓸 수 없다. 첫 사용에서 `openssl version`을 확인하고 아니면 그 이유로 시험이 실패한다. 건너뛰는 시험은 없다.

## 한계

- 기관 시각의 진실성(ADR-0034 5항), 인증서 폐지, 양자 공격자의 토큰 위조는 다루지 않는다.
- 정부 운영과 정부 밖의 구분, 운영 주체의 이름은 선관위와 독립검증위원회가 함께 서명한 genesis의 선언이다. 검증기는 그 선언이 사실인지(어느 기관을 정부가 운영하는지, 두 운영 주체가 실제로 다른 조직인지) 확인할 수 없다. 확인하는 것은 선언들 사이의 일관성뿐이다: 한 운영 주체는 한 구분, 대소문자만 다른 이름은 한 운영 주체, 한 키는 한 번, 운영 주체는 증인이나 선관위의 조직이 아님. 선언이 거짓이면 genesis를 서명한 두 기관의 책임이고, 공표된 genesis를 누구나 대조할 수 있다.
- genesis·변경·법적 결정의 토큰은 검증해 보이지만 요구하는 규칙은 없다. 투표 종료 뒤 전 기간 공표의 시점확인은 장부 밖 행위여서 다루지 않는다.
- 보관 증거의 재시점확인(VC-118, RFC 4998)은 보존 절차이며, 검증기는 장부에 있는 토큰만 확인한다.
- 한 기관이 이른 시각의 토큰 하나로 장부를 보류시킬 수 있다(6항). 실패를 닫는 쪽이고 그 토큰이 증거다.

## 기각한 대안

- **기관 목록을 본문에.** 인증서를 담은 핀은 본문 상한을 넘는다. 기각.
- **변경할 수 있는 집합.** 개정안 15 ②가 선거 전 고정을 요구하고, 인증서 교체는 핀 여럿으로 된다. 기각.
- **기록 하나에 기관 여럿의 토큰.** ADR-0034 3항의 필드와 다르고, 기관 단위 계수와 거부 사유가 기록 안에서 섞인다. 기각.
- **체크포인트 본문 해시를 각인.** 정족수 서명이 그 시각에 있었음을 보이지 못한다. 기각.
- **모든 체크포인트의 앵커를 요구.** 기관 장애 한 시간으로 장부가 영원히 `UNVERIFIED`에 남는다. 마지막 체크포인트가 앞의 것을 덮으므로 그것으로 판정한다. 기각.
- **`genTime`으로 판정.** 정확도가 큰 토큰이 앵커를 넓히고 역산을 오판한다(ADR-0037 9항). 기각.
- **고정 체크포인트 토큰을 있을 때만 확인.** 8항. 기각.
- **고정 체크포인트 토큰에 버킷 규칙만큼의 여유(`P − 3`).** 토큰은 참 시각을 말하므로 증인의 허용과 시계 오차가 필요 없다. 여유를 더하면 이유 없이 살아 있음만 줄어든다. 기각.

## 연결되는 검증

- `ityv-encoding` `tests/m5_timestamp.rs`(왕복, 규칙, 벡터 `timestamp_authority_entry.txt`·`timestamp_record.txt`, 대상 스키마 전수, 속성 테스트), `tests/m5_genesis.rs`(집합 12, 버전 6 거부), 다시 만든 `genesis_body.txt`·`signed_genesis.txt`; Kani `timestamp_rules_are_exact`, `event_codes_are_exact`(구분 코드).
- `ityv-verify` `tests/timestamp.rs`(실제 토큰: 두 운영 주체의 앵커, 밝힌 정확도와 genesis 정확도 가운데 큰 것에 따른 창과 허용의 경계, 1분을 넘게 밝힌 토큰의 거부, 토큰 없는 기록의 대상 확인, 대소문자만 다른 운영 주체, 역산이 사슬을 끝냄, 받지 못한 기록마다의 사유와 응답 없음 기록, 회전된 인증서와 같은 운영 주체, genesis·법적 결정의 토큰, 상태), `tests/genesis.rs` `refuses_a_timestamp_authority_set_that_breaks_a_rule`(검증될 수 없는 핀, 사본 없는 핀, 한 키의 두 인증서, 정확도의 경계, 대소문자만 다른 운영 주체, 증인·선관위와 같은 운영 주체), `ityv-tsa` `tests/tokens.rs` `a_pin_names_its_signer_key_when_some_token_could_verify`, `tests/report.rs`(앵커 기한, 마지막 체크포인트가 앞을 덮음), `tests/audit.rs` `the_binding_checkpoint_needs_tokens_from_before_the_publication`, `timestamp` 단위 시험(구간 시작, 세 비교의 경계, 정책 정확도의 올림, 계수); Kani `token_bucket_comparison_is_exact`.
- `ityv-state` 보류 사유 72·73(`codes_are_dense_and_below_128`, Kani `hold_set_is_sticky`).

## 개정 (2026-11-05, 독립 리뷰 반영)

독립 리뷰(486347c 대상)가 찾은 것과 바꾼 것. 이 ADR의 결정은 위에 고쳐 적었다.

1. **토큰 없는 기록(L1).** "응답 없음" 기록은 대상을 확인하기 전에 목록에 올라, 없는 이벤트·시점확인 대상이 아닌 종류·뒤에 실린 이벤트를 가리켜도 받아들여졌다. 이제 기관, 대상, 토큰의 순서로 확인한다(3·4항).
2. **검증될 수 없는 핀(L2).** SHA-512만 허용하고 SHA-256 서명만 허용한 핀이 genesis 규칙을 통과했다. 이제 핀은 인증서 사본을 담고, 허용된 서명 알고리즘 가운데 그 키가 만들고 다이제스트도 허용된 것이 있어야 한다(`PinnedTsa::signer_key`, 2항).
3. **운영 주체의 정체(L3).** 운영 주체는 대소문자만 다르게 적어도 다른 운영 주체였고, 한 키를 두 인증서로 두 기관에 핀할 수 있었으며, 운영 주체가 증인이나 선관위와 같아도 막지 않았다. 이제 대소문자를 무시해 비교하고(genesis와 앵커 계수 모두), 한 공개키는 한 번만, 운영 주체는 증인과 선관위의 조직이 아니어야 한다(2항). 구분이 선언일 뿐임은 한계에 적었다.
4. **정확도(I1, I3).** 정확도를 밝히지 않은 토큰에만 genesis의 정확도를 썼고 0도 받았으며, 정확도가 크면(약 44분 이상) 감사의 공표 전 규칙을 지킬 수 없었다. 이제 가장 늦은 순간은 밝힌 정확도와 genesis 정확도 가운데 큰 것으로 정하고, genesis 정확도는 1초–1분이며 핀이 허용하는 모든 정책을 덮어야 하고, 1분을 넘게 밝힌 토큰은 거부한다(1·2·5·8항).
5. **비용(I5).** 기록이 가리킬 수 있는 세 스키마의 이벤트만 색인하고, `ityv-tsa`가 각인을 서명 검증 앞에서 비교한다(ADR-0037 8항 개정).
6. **중간 체크포인트의 시각(I2).** 장부의 앵커 기한은 마지막 체크포인트로만 정하므로 앵커되지 않은 중간 체크포인트의 구간이 집계 범위의 증인 시각으로 쓰였다. 이제 증인 시각은 범위보다 앞 프레임의 토큰으로 앵커된 체크포인트에서만 온다(`verify_tally`). 감사의 고정 체크포인트는 이미 그렇게 했고, 늦은 마감의 기한(VC-100)은 체크포인트 구간을 쓰지 않는다. 받아들이는 위험은 결과에 적었고, PROTOCOL의 VC-115 문장을 코드에 맞췄다.
7. **시험의 임시 디렉터리(I4).** 키를 쓰는 임시 디렉터리가 패닉 때 남았고, 이름을 예측할 수 있었으며 이미 있는 디렉터리나 링크도 받았다. 이제 가드가 패닉 중에도 지우고, 이름에 무작위 부분을 넣어 새로 만들 때만 쓰며, OpenSSL 3을 처음에 확인한다(결과).
8. **죽은 API(I6).** `ityv_ledger::check_anchor`와 `REQUIRED_ANCHORS`는 호출자가 준 지정 공개 검증자 영수증 셋을 세던 규칙으로, 7항 뒤로는 상태에 쓰이지 않았고 `Breach::AnchorsShort`의 문서는 여전히 영수증을 말했다. 둘을 지우고(Kani 하네스는 게시판 기한을 대신 확인한다) `AnchorsShort`는 두 구분 가운데 있는 수와 2로 문서화했다. 호출자가 준 목록이 장부보다 더 앵커된 것처럼 보이게 할 길이 없어진다.

## 개정 2 (2026-11-05, 둘째 독립 리뷰 반영)

둘째 리뷰(2h단계 B와 개정 1 대상)가 찾은 것 가운데 시점확인에 관한 것.

1. **조직 이름(I-b).** 운영 주체는 대소문자만이 아니라 구분 기호도 무시하고 비교한다(`MOIS-GPKI`와 `MOIS_GPKI`). 명부 보관 기관의 조직과 같은 함수다. 운영 주체와 겹치면 안 되는 조직에 서명자 명부의 모든 조직을 더했다(2항).
