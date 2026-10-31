# ADR-0016: 장부 크레이트 `ityv-ledger`의 경계, 서명된 체크포인트 객체, 증인 정책

> English summary: `ityv-ledger` is the TCB crate for the evidence ledger: the RFC 9162-shaped SHA3-512 Merkle tree with an allocation-free incremental accumulator and fixed-size inclusion and consistency proofs, the frame chain rules and the on-disk frame stream with torn-tail isolation, the checkpoint rules a witness checks before signing (a state machine that mirrors the `LedgerWitness` TLA+ model), the witness quorum and diversity policy, the new `SignedCheckpoint` object (schema 0x0010) that carries a checkpoint body with its witness signatures, and the publication-deadline rules. It is `no_std`, allocation-free, single-writer by contract, and owns no storage, network or clock; those stay outside the TCB. Verification: V1, V2 (Kani on the tree arithmetic and small trees), V4 (the existing TLA+ model); V3 for the Merkle algorithms is an open item.

- 상태: 채택
- 날짜: 2026-10-31
- 관련: ADR-0003, ADR-0007, ADR-0012, ADR-0015; `docs/spec/PROTOCOL.md` §5; `docs/spec/ENCODING.md` §6, §8.1, §8.3, §8.4; `docs/models/LedgerWitness.tla`; `docs/ROADMAP.md` M2

## 맥락

증거 장부(§5)는 모든 서명 이벤트의 원본이고 공개 게시판은 증인 체크포인트로 고정된다. 운영자(선관위)는 신뢰하지 않으므로 장부의 안전성은 (1) 프레임 사슬과 Merkle 트리의 수학, (2) 증인이 서명 전에 확인하는 규칙(VC-012·VC-013), (3) 정족수와 다양성(VC-014)에서 나온다. 이 셋은 저장소·네트워크·시계와 분리된 순수 함수로 두어야 검증기(M5)와 증인 도구가 같은 코드를 쓰고, Kani와 TLA+가 같은 규칙을 검사한다. 명세는 체크포인트 본문(0x0004)은 정하지만 증인 서명을 운반하는 객체는 정하지 않았다.

## 결정

1. **범위.** `ityv-ledger`는 다음만 담는다: `merkle`(§5.3 트리, 누산기, 포함·일관성 증명의 생성과 검증, 정렬 집합 root), `frame`(§5.1 프레임 사슬 규칙과 디스크 스트림 파서), `checkpoint`(§5.4 본문 규칙, 증인 서명 전 상태기계, `SignedCheckpoint` 객체), `policy`(VC-014 정족수·다양성과 프로필 유효성), `publication`(§5.5 기한). 저장소, 파일·DB 입출력, 네트워크, 벽시계, 이벤트 본문 색인, 투영 상태(M4), genesis 파싱, 검증기 파이프라인(M5)은 밖이다.
2. **해시 영역.** 리프 = `SHA3-512(0x00 ‖ 프레임 해시)`, 노드 = `SHA3-512(0x01 ‖ 왼쪽 ‖ 오른쪽)`, 빈 트리의 root = `SHA3-512("")`(RFC 9162 §2.1). 트리 모양은 RFC 9162(왼쪽 완전, 가장 큰 2의 거듭제곱 분할). 크기 상한 2^40이므로 누산기 봉우리와 포함 증명은 40개 이하, 일관성 증명은 41개 이하(RFC 9162: 깊이 + 1)의 고정 배열이다. `box_close_root`와 `dispute_root`는 같은 해시 규칙으로 만든 **정렬 집합 트리**다: 리프는 이벤트 해시를 바이트 오름차순으로 정렬한 것이고 중복은 거부하며 빈 집합의 root는 빈 트리의 root다.
3. **단일 작성자.** 선거별 장부의 작성자는 하나다. 크레이트는 추가 규칙(seq가 1씩 증가, `prev_hash` 일치, `election_id` 불변)을 강제하고 같은 seq의 동일 바이트 재전송은 멱등, 다른 바이트는 충돌로 보고한다. 상호배제와 내구 기록의 원자성은 호스트의 책임이다(P0-13). 디스크 스트림은 `u32_be 길이 ‖ 프레임 객체`의 연속이며 마지막 레코드가 잘렸으면 그 오프셋을 `TornTail`로 보고하고 앞 구간은 그대로 유효하다(VC-010).
4. **증인 상태기계.** 증인 도구는 `WitnessMemory`(스키마 0x0011: 마지막으로 서명한 체크포인트의 seq, `tree_size`, `root_hash`, 본문 해시, 세 식별자의 해시)를 영속 저장한다. `may_sign`은 기억을 **소비**하며, VC-012의 다섯 조건(직전 체크포인트와의 일관성 증명, `tree_size` 단조 비감소, `previous_checkpoint_hash` 일치, genesis 해시 일치, 두 root의 재계산 일치)과 `checkpoint_seq = 마지막 + 1`, `election_id`·`ledger_id`·`keyset_id` 불변을 모두 확인할 때만 서명 가능 토큰과 **전진한 기억**을 함께 돌려주고, 실패하면 기억을 그대로 돌려준다. 확인과 전진이 한 동작이고 토큰은 복제되지 않으므로 같은 seq에 두 본문의 토큰이 동시에 존재할 수 없다(VC-013). 도구는 전진한 기억을 영속화한 뒤에 서명한다: 그 사이에 중단되면 서명 하나를 잃을 뿐 분기를 서명하지 않는다. 기억 파일이 없으면 도구는 빈 기억을 만들지 않고 외부 앵커에서 복구한다(P0-14). 이 규칙은 `docs/models/LedgerWitness.tla`의 `HonestSign`과 같다.
5. **서명된 체크포인트 객체.** `SignedCheckpoint`(스키마 0x0010, `ENCODING.md` §8.4) = `body: Bytes<4096>`(인코딩된 `CheckpointBody` 객체 전체, 헤더 포함) ‖ `signatures: Array<{witness_id: Ident<64>, signature: [u8; 4691]}, 64>`(`witness_id` 오름차순, 중복 없음). 각 서명은 `body` 바이트에 대한 purpose `checkpoint`의 하이브리드 서명이다. 장부의 체크포인트 이벤트는 이 객체이며 프레임의 `event_schema_id`는 0x0010이다. 최종 체크포인트의 SLH-DSA 보존 서명(§5.6)은 별도 이벤트로 붙인다.
6. **정족수 정책.** `QuorumProfile { witnesses: n, quorum: q, byzantine_max: f }`는 `q ≤ n`이고 `2q − n > f`일 때만 유효하다(두 정족수의 교집합이 비잔틴 수보다 크다; TLA+ 모델의 `ASSUME`). 기본 프로필은 13/9/4, 대안 19/13/6. 공표된 `SignedCheckpoint`가 유효하려면 모든 서명이 명부의 키로 검증되고, 명부 밖 ID나 중복 ID가 없으며, 서명자 수가 `q` 이상이고 서로 다른 조직 7·공급자 4·지역 3 이상이어야 한다(VC-014). 하나라도 틀리면 객체 전체가 무효다(닫힌 실패). 다른 본문에 대한 서명은 바이트가 다르므로 검증에 실패하며 한 정족수로 합산되지 않는다.
7. **기한.** 체크포인트는 `time_bucket + 4`(1시간) 안에 지정 공개 검증자 3곳 이상의 수신 서명이 있어야 하고, 전 기간 게시판은 투표 종료 `time_bucket + 96`(24시간) 안에 공표되어야 한다. 크레이트는 구간 산술과 위반 판정만 제공하고 시각은 호출자가 준다.
8. **타입 경계.** 검증 결과는 이 크레이트가 만드는 `Verified<T>` 토큰이며 `T`는 검증 입력을 참조한다(ADR-0015 §2와 같은 규칙; `ityv-crypto`의 토큰은 그 크레이트만 만들므로 각 TCB 크레이트가 자기 토큰을 갖는다). 고정 용량: 증인·서명 64, 포함 증명 40, 일관성 증명 41, 봉우리 40. `alloc`을 쓰지 않는다.
9. **검증 사다리.** V1(속성·변이·회귀 벡터: 트리 root, 증명, 스트림, 객체), V2(Kani: 트리 모양 산술, 작은 트리의 증명 생성·검증 왕복과 위치 검사, 누산기와 전체 계산의 일치, 프로필 유효성, 정족수 계수), V4(`LedgerWitness.tla`). Merkle 알고리즘의 V3(Verus/Creusot)는 미해결 항목이다.

## 결과

- `ENCODING.md` §6 등록부에 0x0010과 0x0011을 추가하고 §8.4·§8.5에 필드 정의를 둔다. `PROTOCOL.md` §5.3에 빈 트리와 정렬 집합 root의 정의를, §5.4에 `SignedCheckpoint`를 명시하고 부록 A의 체크포인트 이벤트 스키마를 0x0010으로 바꾼다.
- 증인 도구(M8)와 검증기(M5)는 이 크레이트의 `may_sign`과 `evaluate`를 그대로 쓴다. 정족수 수학 행(ITYV-BEH-110·111·112)은 이 크레이트가 담당한다.
- 대량 증명 생성(리프 2^40)은 호스트 저장소의 캐시가 필요하다. 크레이트의 증명 생성은 리프 접근자 위에서 O(n) 해시를 하는 참조 구현이며 검증기와 작은 도구에 충분하다.

## 기각한 대안

- 증인 서명을 체크포인트마다 별도 이벤트로 기록: 이벤트 수가 증인 수만큼 늘고 정족수 판정이 여러 프레임에 걸친다.
- Merkle 트리를 `alloc`으로 메모리에 구성: 2^40 상한과 `no_std` 장치 코어에 맞지 않는다. 누산기와 접근자로 대체.
- 명부 밖 서명을 무시하고 유효한 것만 세기: 위조 서명이 섞인 객체를 공표물로 받아들이게 되어 닫힌 실패 원칙에 어긋난다.
