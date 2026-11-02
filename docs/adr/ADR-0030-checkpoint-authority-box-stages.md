# ADR-0030: 체크포인트 사슬, 장부에 싣는 법적 승인 `SignedLegalAuthorization`, 투표함 단계

> English summary: Step M5 2c adds three stages to `ityv-verify`. (1) The checkpoint chain (PROTOCOL §14 item 2): each `SignedCheckpoint` must carry a diverse witness quorum from the genesis witness set, follow the previous valid checkpoint (sequence, previous hash, non-shrinking tree, same election, ledger, key set and pinned genesis), cover only frames before its own, and carry the tree root, the box-close root and the open-dispute root that the verifier recomputes from the ledger. The chain ends at the first checkpoint that breaks a rule and the whole ledger is held (`CheckpointInvalid`); the tree size of the last valid checkpoint is the fixed part of the ledger. (2) The legal authorization had no ledger envelope: the genesis pins the object hash of a `LegalAuthorizationBody`, but nothing carried the commission's and the committee's signatures. A new object `SignedLegalAuthorization` (schema `0x0042`) carries the body bytes and both hybrid signatures under purpose `legal-auth`. The index accepts only the pinned body; `authorize_ledger` takes the first one whose signatures verify under the genesis keys and hands the tokens to `ityv_state::authorize`. Without one the whole ledger is held (`AuthorizationMissing`) and no gated stage can grant a capability. (3) The box stage (§14 item 4) drives `ityv-state`'s ballot-box machine for every expected box with the box's indexed events in frame order. Capabilities are granted for the day of the box's opening (records carry no time, VC-001). A close is the box's close or a late close according to the state the box is in when it comes, so tokens for both purposes are prepared in advance and a refused close leaves the box open for the next. An out-of-district close takes the station's last issuance count before it. A post-close batch attestation is paired with the `LateBatchClose` that names its body hash. Every signature is verified under the key the genesis registers. A refused event holds the box (`BoxEventRefused`); a box without a close holds it (`CloseMissing`, completeness). A commitment-unit swap is refused as unsupported until the stage follows amendments.

- 상태: 채택
- 날짜: 2026-11-02
- 관련: ADR-0016(증거 장부), ADR-0025(상태 크레이트), ADR-0028(genesis 정규 형식), ADR-0029(검증기 크레이트); `docs/spec/PROTOCOL.md` §4.4, §5.3, §5.4, §7, §10, §14; `docs/spec/ENCODING.md` §8.2, §8.3, §8.60; `docs/ROADMAP.md` M5

## 맥락

M5 2b단계는 genesis 전체 확인(1단계)과 장부 색인(3단계)을 만들었다(ADR-0029). 그 위에 장부가 잘리거나 바뀌지 않았다는 증인 보증(2단계)과, 투표함마다 개시에서 마감·인계·개표까지를 상태 기계로 따라가는 단계(4단계)가 남았다.

4단계를 만들다가 명세의 틈을 찾았다. `ityv-state`의 능력 토큰(`PUBLIC_BOARD`, `BALLOT_MARK` 등)은 법적 승인 `Authorization`에서만 나오고, `Authorization`은 genesis가 고정한 승인 본문과 그 본문에 대한 선관위·위원회 서명 토큰으로만 만들어진다(`ityv_state::authorize`, VC-006..008). 그런데 `ENCODING.md` §8.2는 "서명은 이 본문을 감싸는 genesis 객체가 운반한다"고 적었고, genesis 객체(`SignedGenesis`, 0x0033)에는 승인 서명을 둘 자리가 없었다. 공표된 데이터만으로 승인을 확인할 수 없었다.

## 결정

1. **체크포인트 사슬(§14 2항, VC-011..014).** `verify_checkpoints`는 색인의 `SignedCheckpoint`를 프레임 순서로 읽는다. 체크포인트마다:
   1. genesis 증인 집합의 `q` 이상이 purpose `checkpoint`로 본문 바이트에 서명했고 조직·공급자·지역 하한을 채운다(`ityv_ledger::evaluate`, VC-014).
   2. 직전의 유효한 체크포인트를 잇는다: 번호 +1(첫 체크포인트는 1과 0 이전 해시), 이전 해시 = 직전 본문의 객체 해시, 트리 크기 감소 없음, 같은 선거·장부·키 집합, 핀의 genesis(`validate_successor`, VC-012).
   3. 자기를 싣는 프레임보다 앞선 프레임만 덮는다(`tree_size` < 자기 프레임 순번).
   4. `root_hash`는 처음 `tree_size`개 프레임 해시(거부된 프레임 포함)의 트리 root다(VC-011).
   5. `box_close_root`는 그 프레임들에서 색인이 받은 `BoxClose`(장치·수동·늦은 마감 모두) 객체 해시의 정렬 집합 root다.
   6. `dispute_root`는 그 프레임들의 분쟁 이벤트를 적용한 뒤 미해결인 분쟁의 접수 본문 객체 해시(`ityv_state::Dispute`가 분쟁을 가리키는 그 해시)의 정렬 집합 root다. 접수는 열고, 기술 해결은 해소하고, 법적 회부는 다시 미해결로 만들며, 조사는 바꾸지 않고, 보지 못한 접수를 가리키는 이벤트는 분쟁 단계에 맡긴다.

   규칙을 어긴 첫 체크포인트에서 사슬이 끝난다. 발견이 남고 장부 전체가 `CheckpointInvalid`로 보류되며 그 뒤 체크포인트는 확인하지 않는다(각 체크포인트가 앞의 것을 보증하므로). 마지막 유효 체크포인트의 트리 크기가 장부의 고정된 부분이다(`covered`). 다른 선거의 체크포인트는 색인이 먼저 거부하고(`OtherElection`), 첫 체크포인트의 0이 아닌 이전 해시는 본문 디코더가 거부한다.

2. **장부의 법적 승인 `SignedLegalAuthorization`(0x0042).** 새 객체가 승인 본문과 두 서명을 함께 싣는다: `body: Bytes<512>`(`LegalAuthorizationBody` 객체 전체, 다른 스키마는 `SchemaMismatch`) ‖ `commission_sig: [u8; 4691]` ‖ `committee_sig: [u8; 4691]`. 두 서명의 메시지는 `body` 바이트, purpose는 `legal-auth`다(`ENCODING.md` §8.60). genesis는 지금처럼 본문의 객체 해시를 고정한다(`legal_authorization_hash`).
   - 색인은 선거 이벤트로 받되, 본문이 genesis가 고정한 것이 아니면 무효다(`NotPinned`, 장부 전체 `HOLD_REVIEW`, ADR-0029). 같은 바이트의 재수록은 다른 이벤트처럼 거부한다(VC-101).
   - `authorize_ledger`는 색인이 받은 것 가운데 두 서명이 genesis 본문의 선관위·위원회 키로 검증되는 첫 객체를 고르고, 토큰을 `ityv_state::authorize`에 넘긴다(범위 전제 규칙, VC-008). 서명이 맞지 않는 사본은 건너뛴다. 같은 본문을 다른 서명 바이트로 다시 싣는 것은 막지 않는다. 고정된 본문이 하나뿐이므로 어느 사본이든 같은 승인이다.
   - 유효한 승인이 없으면 장부 전체가 `HOLD_REVIEW`(`AuthorizationMissing`)이고, 능력이 필요한 어떤 단계도 그 능력을 얻지 못한다.
   - 서명을 genesis 안에 넣지 않은 이유: 승인은 법령 개정·시행에 따라 genesis와 다른 시점에 확정될 수 있고(부속서의 단계적 시행), genesis 본문은 승인의 해시만 고정하면 충분하다. 승인 객체를 따로 두면 genesis 형식을 바꾸지 않는다.

3. **능력의 날.** 능력은 날마다 확인한다(`Authorization::grant`, 시행 구간). 시간은 genesis의 `election_epoch_day`를 기준으로 한 15분 구간뿐이므로(§3) 이벤트의 날은 `epoch_day + time_bucket / 96`이다. 투표함 개시는 그 날의 `PUBLIC_BOARD`로 상태 기계에 들어간다. 투함 기록에는 시간이 없으므로(VC-001) 기록의 `BALLOT_MARK`는 그 투표함 개시의 날로 확인한다. 시행 구간 밖의 개시는 거부된다.

4. **투표함 단계(§14 4항, VC-037..040, VC-100).** `verify_boxes`는 genesis 마지막 상태의 예상 투표함마다 `BoxSpec`(증명된 genesis 항목, 경로, 명부)을 만들고, 색인의 그 투표함 이벤트를 프레임 순서로 `ityv-state`의 투표함 상태 기계(`BallotBox`)에 넣는다.
   - `BoxOpened`: 아직 열리지 않았으면 준비(한 번)와 개시. 거부된 개시 뒤의 다음 개시는 준비된 투표함을 연다. 열린 투표함의 개시는 순서 위반이다.
   - `CastRecord`, `ChallengeOpening`, `BatchAttest`: 열린(또는 대체 상태의) 투표함에 센다. 기록 자체의 서명과 증명은 기록 단계(5단계)가 본다.
   - `FallbackDeclared`·`FallbackEnded`: 열린 투표함과 대체 상태 사이를 오간다.
   - `BoxClose`: 열린 투표함이면 마감(purpose `box-close`), 닫힌 투표함이면 늦은 마감(`late-box-close`, 수동 마감을 24시간 안에 대신할 때만). 어느 쪽인지는 그 이벤트가 올 때의 상태가 정하므로, 두 purpose의 토큰을 미리 다 만들어 둔다. 거부된 마감은 투표함을 열어 둔 채로 두고 다음 마감이 그 투표함의 마감이 된다. 관외 투표함의 마감은 그 마감 앞에서 그 투표소의 마지막 `IssuanceCount`와 함께 넣는다(봉투 수 대조, 없으면 `IssuanceMissing`).
   - 마감 뒤 `BatchAttest`는 그 배치 본문의 객체 해시를 적은 `LateBatchClose`와 짝지어 늦은 배치 마감으로 넣는다(어느 쪽이 먼저 와도 된다). 끝까지 짝이 없는 것은 거부(`Unmatched`)다.
   - `SealChange`, `CustodyHandoff`: 닫힌 투표함의 보관 사슬. `ImprintAudit`: 닫힌 투표함을 개표 상태로.
   - 그 밖의 사람 서명 이벤트(분쟁 등)는 다른 단계의 것이라 이 단계는 건드리지 않는다.

   모든 서명은 이 단계가 genesis 명부가 그 서명자 식별자에 등록한 키(장치는 그 투표함의 장치 키)로 검증해 토큰을 만들고, `ityv-state`가 토큰을 서명자·역할·조직·purpose·바이트에 결속한다. 키가 없거나 서명이 맞지 않으면 거부(`Signature`)다. 토큰은 디코드한 이벤트를 빌리고 상태 기계는 토큰을 빌리므로, 단계는 투표함마다 이벤트를 먼저 모두 디코드하고, 그다음 토큰을 만들고, 그다음 상태 기계를 돌린다.

5. **보류와 완전성.** 투표함마다 단계(준비·열림·대체·닫힘·개표), 마감 수량, 거부된 이벤트 목록(프레임 순번과 이유: 상태 기계의 거부, 서명, 순서, 능력, 짝 없음, 미지원)과 보류를 낸다. 보류는 상태 기계의 것(마감 불변식, 수동 마감, 열린 배치, 보관 사슬, 각인 판독), 거부된 이벤트가 있으면 `BoxEventRefused`, 닫히지 않았으면 `CloseMissing`, 그리고 색인의 그 투표함·투표소·장부 보류와 승인 단계의 보류의 합이다. `complete()`는 모든 예상 투표함에 `CloseMissing`이 없을 때 참이다. 상태 사다리(§14 끝)는 이 둘을 따로 쓴다: 불변식은 `LOG_CONSISTENT`, 완전성은 `SOURCE_COMPLETENESS_CHECKED`의 조건이다.

6. **아직 하지 않는 것.** 변경으로 장치 키가 바뀐 투표함은 상태 기계가 `BallotBox::follow`로 따라갈 수 있지만, 이 단계는 아직 변경 시점과 이벤트를 맞추지 않는다. 그래서 `BoxUnitSwap`은 `Unsupported`로 거부되고 그 투표함은 보류된다. 기록의 서명·증명과 배치 포함(5단계), 투표함 수량과 진행 기록의 대조(진행 단계)도 다음 단계다.

## 결과

- 공표된 데이터만으로 법적 승인을 확인할 수 있고, 승인 없는 장부는 어느 능력도 얻지 못한다.
- 장부의 앞부분은 증인 체크포인트가 고정하고, 체크포인트의 세 root는 검증기가 다시 계산한 값과 같아야 한다.
- 투표함마다 거부된 이벤트가 프레임 순번과 이유와 함께 남아, 보류의 근거를 사람이 따라갈 수 있다.
- 비용: 마감은 두 purpose로 서명을 두 번 검증한다(마감은 투표함마다 한두 건이다).

## 대안

- **승인 서명을 `SignedGenesis`에 넣기.** genesis 형식(버전 6)을 바꾸고, 승인과 genesis가 함께 확정되어야 한다. 기각.
- **마감의 종류를 이벤트 순서로 정하기(첫 마감은 마감, 그 뒤는 늦은 마감).** 거부된 첫 마감 뒤의 올바른 마감을 늦은 마감으로 잘못 읽는다. 기각.
- **기록마다 그 날의 능력을 확인하기.** 기록에는 시간이 없다(VC-001). 시간을 넣으면 투함 순서가 드러난다. 기각.
