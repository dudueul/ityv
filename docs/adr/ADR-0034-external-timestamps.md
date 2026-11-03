# ADR-0034: 독립 시점확인 기관(TSA)의 체크포인트 시점확인

> English summary: The ledger's checkpoints carry only the time bucket their witnesses declare, and the verifier has no clock. Today the anchor deadline of §5.5 is judged by the caller. Each signed checkpoint, the genesis, the roll freeze and roll custody receipts, and the final board publication now also receive RFC 3161 timestamp tokens. These must come from at least two of the timestamp authorities the genesis pins, run by different operators, at least one run by the Korean government and at least one not. The tokens are recorded on the ledger as `TimestampRecord` events. The verifier checks each token itself, against the pinned authority key, policy and the imprint of the checkpoint object hash. It then checks two things from the signed time: the checkpoint was not backdated (the time is not before its declared bucket), and it was anchored within the window. So a rewritten or forked history made later cannot carry the earlier times without the authorities colluding across operators. Only checkpoint-level objects are timestamped, never individual records (VC-001). The tokens' classical signatures are corroboration, not the root of trust: the witnesses' hybrid signatures stay primary, and archived evidence is re-timestamped under post-quantum algorithms before the classical ones expire (RFC 4998). Token parsing lives in a small separate no_std crate with fuzzing and Kani, not in the core verifier.

- 상태: 제안
- 날짜: 2026-11-03
- 관련: ADR-0006(암호 방향), ADR-0016(공개원장 크레이트), ADR-0029–0031(검증기, 공표 기한), ADR-0033(명부 보관); `docs/spec/PROTOCOL.md` §5.3–§5.5; 법령 개정안 9(암호 기록의 보존과 알고리즘 전환)

## 맥락

체크포인트(§5.3)는 증인 정족수가 서명한 장부 root와 시간 구간(15분)을 담는다. 그 시간은 증인들이 적은 값이다. §5.5의 외부 앵커는 지정 공개 검증자 셋 이상의 수신 게시이고, 그 기한(1시간)의 판정은 지금 호출자가 넘기는 `Publications`에 맡긴다. 검증기에는 시계가 없기 때문이다(ADR-0031).

그래서 두 가지가 외부에서 확인되지 않는다.
- 체크포인트가 적힌 시각에 정말 있었는가. 증인 정족수가 공모해 뒤늦게 만든 사슬을 그 시각의 것처럼 적을 수 있다.
- 앵커가 기한 안에 이루어졌는가. 이것은 호출자의 시계와 수신 게시에 기대고 있다.

공인된 시점확인(타임스탬프) 기관은 "이 해시값이 이 시각에 존재했다"를 자기 키로 서명한다(RFC 3161). 서로 다른 운영 주체의 기관 여럿이 같은 체크포인트에 시점을 찍으면, 그 체크포인트를 나중에 만든 것으로 바꾸려면 그 기관들이 함께 날짜를 거슬러 서명해야 한다.

## 결정

1. **시점확인 기관 목록을 genesis에 고정한다.** 항목마다 기관 ID, 운영 주체, 구분(정부 운영 / 정부 밖), 서명 인증서(또는 공개키)의 해시, 허용 정책 OID, 허용 해시 알고리즘을 둔다. 목록에는 정부가 운영하는 기관이 하나 이상 있어야 한다(예: 행정 전자서명 인증체계의 시점확인. 구체 기관은 하위 규정으로 지정한다). 정부 밖의 인정 기관도 하나 이상 있어야 한다. 선택으로 공개 블록체인 앵커(예: OpenTimestamps)를 둘 수 있으나 정족수에는 세지 않는다.

2. **무엇에 시점을 찍는가.** 다음 객체에 찍는다.
   - 모든 서명된 체크포인트(§5.3)
   - genesis 핀과 변경
   - `RollFreeze`와 `RollCustodyReceipt`(ADR-0033)
   - 투표 종료 뒤 전 기간 공개원장 공표(§5.5)
   - 법적 결정의 수록(§13)

   개별 투함 기록, 확인 카운터, 진행 기록에는 찍지 않는다. 기록마다 정확한 시각이 붙으면 투표 순서와 시각이 드러난다(VC-001). 기록은 닫힌 배치 단위로만 장부에 오므로(VC-079), 체크포인트의 시각은 배치보다 세밀한 것을 드러내지 않는다.

3. **요청과 수록.** 장부 운영자는 체크포인트 객체 해시(SHA3-512, 64바이트)의 SHA-512를 `messageImprint`로 삼아 요청한다(기관들이 널리 지원하는 알고리즘이며 genesis가 고정한다). 요청에는 `certReq`와 무작위 nonce를 넣는다. 받은 토큰은 `TimestampRecord` 이벤트로 장부에 수록한다. 이벤트에는 대상 객체의 스키마와 해시, 기관 ID, DER 토큰 바이트가 들어간다. 이 이벤트는 다음 체크포인트가 덮는다. 기관이 응답하지 않으면 다른 기관에 요청하고, 그 사실도 수록한다.

4. **검증.** 검증기는 토큰마다 다음을 확인한다.
   - CMS 서명이 genesis가 고정한 그 기관의 인증서로 검증된다.
   - 정책 OID와 해시 알고리즘이 허용된 것이다.
   - `messageImprint`가 대상 객체 해시의 SHA-512이다.
   - `genTime`을 선거 epoch 기준 시간 구간으로 바꾼다.

   그다음 체크포인트마다 판정한다.
   - **역산 금지.** 유효 토큰의 시각 구간이 체크포인트가 적은 구간보다 앞서면, 그 체크포인트의 시간은 거짓이다. 사슬 규칙 위반으로 다룬다(`CheckpointInvalid`).
   - **앵커 기한.** 서로 다른 운영 주체의 유효 토큰 둘 이상(정부 운영 하나와 정부 밖 하나 포함)의 시각이 체크포인트 구간 + 앵커 창(§5.5, 4구간) 안이면, 그 체크포인트의 앵커는 충족이다.
   - 늦거나 모자라면 그 체크포인트의 앵커는 충족되지 않는다. 그 체크포인트가 덮은 부분까지만 확인된 앵커가 있다.

   검증기는 이 판정으로 `Publications.anchors`를 스스로 정한다. 아직 시점확인이 없는 마지막 체크포인트에 대해 "아직 기한 안인가"를 판정하려면 여전히 지금 시각이 필요하다. 그때만 호출자의 시계를 쓴다.

5. **역할의 한계.** 시점확인은 "그 해시가 그 시각까지 존재했다"만 증명한다. 내용이 맞는지는 증명하지 않는다. 신뢰의 뿌리는 여전히 증인 정족수의 하이브리드 서명(ML-DSA-87 + Ed25519)이다. 시점확인 토큰은 오늘의 고전 서명(RSA·ECDSA)을 쓰므로, 양자 공격자는 언젠가 과거 시각의 토큰을 위조할 수 있다. 그래서 다음을 따른다.
   - 토큰은 보강 증거다. 토큰이 없거나 위조돼도 증인 서명의 사슬 판정은 그대로다. 토큰이 다른 사실을 말할 때만 보류가 생긴다.
   - 보존 기간 동안 보관 토큰과 장부 root를 주기적으로 다시 시점확인한다(RFC 4998 Evidence Record). 고전 알고리즘이 위험해지기 전에, 양자 내성 서명을 지원하는 기관으로 갱신한다(개정안 9의 알고리즘 전환).
   - 기관이 양자 내성 서명(ML-DSA)을 지원하면 그것을 우선한다.

6. **TCB 경계.** RFC 3161 토큰은 DER로 인코딩된 CMS 서명 자료이며 RSA·ECDSA 검증이 필요하다. 이 파서와 검증을 핵심 검증기에 넣으면 TCB가 커진다. 그래서 다음 조건의 작은 별도 크레이트 `ityv-tsa`에 둔다.
   - `no_std`, `unsafe` 없음, 패닉 없음.
   - 필요한 DER 부분집합만 엄격하게 파싱한다(정규 DER, 길이 상한, 알 수 없는 필수 확장 거부).
   - 퍼징과 파서의 Kani 증명을 둔다.

   검증 쪽에는 비밀이 없으므로 서명 검증의 시간 부채널은 문제가 아니다. 의존 크레이트는 정확한 버전으로 고정하고 감사한다. `ityv-verify`는 `ityv-tsa`가 검증한 결과(기관, 시각 구간, 대상 해시)만 받는다.

7. **보류 사유(새로).**
   - `TimestampMismatch`: 유효 토큰이 체크포인트의 시간보다 앞선 시각을 말한다.
   - `TimestampInvalid`: 장부에 수록된 토큰이 검증되지 않는다(위조, 다른 대상, 고정되지 않은 기관).

   조용히 버리지 않는다. 토큰이 모자라거나 늦은 것은 보류가 아니라 앵커 미충족이다. 상태는 `UNVERIFIED`에 머문다.

8. **검증 조건(새로).**
   - VC-114: 시점확인 기관과 정책은 genesis에 고정한다. 정부 운영과 정부 밖이 각각 하나 이상이다.
   - VC-115: 체크포인트마다 서로 다른 운영 주체의 유효 토큰 둘 이상이 앵커 창 안에 있어야 앵커가 충족된다.
   - VC-116: 토큰 시각이 체크포인트 구간보다 앞서면 사슬 위반이다.
   - VC-117: 개별 기록에는 시점확인을 하지 않는다.
   - VC-118: 보관 증거는 알고리즘 전환 전에 다시 시점확인한다.

## 결과

- 증인 정족수가 공모해도, 서로 다른 운영 주체의 시점확인 기관들이 함께 날짜를 거슬러 서명하지 않으면 사슬을 과거 시각으로 꾸밀 수 없다.
- 앵커 기한을 검증기가 서명된 시각으로 스스로 판정한다. 호출자의 시계가 필요한 것은 아직 기한이 남은 마지막 체크포인트뿐이다.
- 명부 동결과 보관 영수증(ADR-0033)이 선거 전에 있었다는 것도 외부 시각으로 증명된다.

## 비용과 위험

- 외부 기관의 가용성에 기댄다. 기관 여럿과 재요청, 수록된 실패 기록으로 줄인다.
- 기관의 키 유출이나 날짜 조작에는 운영 주체 다양성(정부·정부 밖)으로 대비한다.
- DER·CMS 파서는 공격면이다. 별도 크레이트, 엄격한 부분집합, 퍼징, Kani로 줄인다.
- 정부 운영 기관에 의존하는 것은 같은 정부가 선거 관리에 관여할 때 독립성 문제가 될 수 있다. 정부 밖 기관이 반드시 함께 서명해야 앵커가 충족되므로, 어느 한쪽만으로는 충족되지 않는다.

## 대안

- **공개 블록체인만 쓰기.** 운영 주체가 없어 독립성은 높다. 그러나 법적 증거력과 국내 접근성에 대한 합의가 없고, 확인 지연이 있다. 선택 앵커로만 둔다.
- **기록마다 시점확인.** 투표 순서와 시각이 드러난다(VC-001 위반). 기각.
- **지정 공개 검증자의 수신 게시만 유지(현행).** 시각이 서명되지 않는다. 보강한다.
