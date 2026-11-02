# ADR-0029: 공개 검증기 크레이트 `ityv-verify`의 경계, 단계 값, genesis 전체 확인과 장부 색인

> English summary: `ityv-verify` is the TCB crate that runs the public verifier of PROTOCOL §14 over whole data sets. It is `no_std` with `alloc` (it holds whole sets and ledgers, and must also run in a browser for observers), `unsafe`-free and panic-free, with no clock, no I/O and no unordered collections, and depends only on the four sibling TCB crates. Each stage returns a value only this crate can make and the next stage takes it, so no stage runs on input an earlier stage refused. It is the only place where `Verified` signature tokens are made from published data; callers never pass tokens in. Step 2b builds two stages. Stage 1, `verify_genesis`, takes the out-of-band pin, the signed genesis with every entry of every set and every amendment with the full amendable sets of the state it creates; it checks the pin, verifies all signatures and seals the genesis through `ityv-state`, re-decodes every entry, re-checks order and uniqueness, recomputes every count and root, checks the sets against each other, and does the same for each amendment's state. New cross-set rules: an observer token must name an observer of its organisation on the roster, device identifiers (boxes, check-in units, modules) are distinct, and no two keys of one genesis state may share a half. Stage 3, `build_index`, reads the frame stream against the verified genesis: frame chain, event by hash, canonical decoding by the frame's schema, who the event concerns (box, station, election), that a genesis, amendment or legal authorization on the ledger is the one the pin names, replayed events (VC-101) and records of a box after its close (VC-039). A refused frame is never dropped silently: it becomes a finding and holds its box, every box of its station, or the whole ledger. Three hold reasons are added to `ityv-state`.

- 상태: 채택
- 날짜: 2026-11-02
- 관련: ADR-0007(헌법), ADR-0016(증거 장부), ADR-0018(공개 미러), ADR-0025(상태 크레이트), ADR-0028(genesis 정규 형식); `docs/spec/PROTOCOL.md` §4, §5.1, §14, 부록 C; `docs/assurance/VERIFICATION_LADDER.md`; `docs/ROADMAP.md` M5

## 맥락

M5 2a단계가 genesis를 본문과 항목 집합 11개로 나누면서, 상태 기계는 항목 하나를 포함 증명으로만 받게 되었다(ADR-0028). 포함 증명은 항목 하나가 있음을 보이지만, 같은 열쇠의 다른 항목이 없음도, 집합끼리 맞물린다는 것도 보이지 못한다. 그 확인은 모든 항목을 받는 검증기가 해야 했다(ADR-0028 8항, VC-104). 장부도 같다. 같은 이벤트가 두 번 실리는 것(VC-101)과 마감 뒤에 그 투표함의 기록이 실리는 것(VC-039)은 개별 이벤트로는 보이지 않고, 장부 전체를 순서대로 읽어야 보인다.

검증기는 헌법이 TCB로 정한 크레이트다(`CONSTITUTION.md` §0). 투표소 장치와 달리 전국 집합(투표함 2.5만, 투표소 1.5만, 서명자 수만)과 장부 전체를 다뤄야 하므로 크기가 고정된 값만으로는 만들 수 없다. 참관인과 시민이 브라우저에서도 돌릴 수 있어야 한다(ADR-0018).

## 결정

1. **경계.** `ityv-verify`는 `crates/` 아래의 TCB 크레이트이고 워크스페이스 lint를 그대로 상속한다. `#![no_std]`에 `alloc`만 쓴다(헌법 §1.3이 힙을 금지하는 것은 현장 장치 코어와 정규 인코딩이다). 시계, 입출력, 순서가 무작위인 자료구조가 없다(`BTreeMap`·정렬된 벡터만, 헌법 §1.8). 의존성은 `ityv-encoding`, `ityv-crypto`, `ityv-ledger`, `ityv-state`뿐이고 외부 의존성을 더하지 않는다. 할 일은 나누어 맡는다:
   - `ityv-crypto`: 서명 검증. 검증기는 공표된 데이터에서 서명을 검증해 `Verified` 토큰을 만드는 유일한 곳이다. 호출자는 토큰을 넘기지 않는다.
   - `ityv-ledger`: 트리 root, 포함 증명, 프레임 연결, 찢어진 꼬리.
   - `ityv-state`: 토큰과 서명자·purpose·바이트의 결속, genesis 봉인과 변경, 상태 기계와 보류 사유.
   - `ityv-verify`: 위 셋을 전체 집합과 장부 위에서 돌리고, 단계 값을 만든다.

2. **단계 값.** 단계마다 이 크레이트만 만들 수 있는 값을 돌려주고, 다음 단계는 그 값을 인자로 받는다. `VerifiedGenesis`는 1단계의 모든 규칙이 통과했을 때만 있고, `LedgerIndex`는 `VerifiedGenesis` 위에서만 만들어진다. 그래서 거부된 genesis 위에서 장부를 읽는 코드는 쓸 수 없다(헌법 §1.6·§1.7). 상태 기계에 넘기는 genesis 항목도 `VerifiedGenesis`가 자기가 확인한 집합에서 포함 증명을 만들어 `ityv-state`로 증명한다(`box_entry`, `station_entry`, `roster` 등, 증명은 저장한 트리 단계에서 `O(log n)`). 검증기를 거쳐 상태 기계를 구동하면 상태 기계는 검증기가 전체를 확인한 항목만 받는다. `ityv-state`의 genesis API는 공개이므로 검증기를 거치지 않고 그것을 직접 쓰는 호출자(또는 `VerifiedGenesis::genesis()`의 `Genesis`로 변경을 더 적용하는 호출자)는 이 보장을 받지 못한다.

3. **genesis 단계(§14 1항).** 입력은 호출자가 대역 외로 받은 핀(VC-005), `SignedGenesis` 바이트와 모든 집합의 모든 항목, 그리고 변경마다 `SignedGenesis` 바이트와 그 변경이 만드는 상태의 바뀔 수 있는 집합 8개 전체다(바뀌지 않은 집합도 다시 준다). 순서:
   1. `SignedGenesis`를 디코드하고 본문의 객체 해시가 핀인지 본다(`Pinned::new`).
   2. 고정 집합 셋(투표양식, 신뢰기관, 증인) 전체를 확인하고, 선관위·위원회·서명한 증인마다 하이브리드 서명을 등록 키로 검증해 토큰을 만들고, `Pinned::seal`로 정족수·다양성·키 반쪽 겹침을 확인한다. 서명한 증인이 증인 집합에 없으면 거부한다. 서명 검증이 비싸므로 나머지 집합보다 먼저 한다(본문을 인증한 뒤에야 본문의 root를 믿을 이유가 생긴다).
   3. 나머지 집합마다 항목을 그 스키마의 정규 객체로 디코드하고, 열쇠가 엄격히 오름차순인지(같으면 중복, 작으면 순서 위반), 항목 수와 root를 다시 계산해 본문과 같은지 본다. 임명 집합은 해시의 정렬 집합 root다.
   4. 집합 사이 규칙(아래 4항)을 확인한다.
   5. 변경마다 같은 방식으로 서명을 검증해 `Genesis::amend`(번호, 이전 본문 해시, 같은 선거, genesis의 `q`, VC-105)로 적용하고, 새 상태의 집합 8개를 3·4와 같이 다시 확인한다. 고정 집합(투표양식, 신뢰기관, 증인)은 처음 확인한 것을 쓴다.

   genesis는 전부 아니면 전무다. 첫 위반에서 멈추고, 위반한 상태(0은 genesis, k는 k번째 변경 뒤), 집합, 항목 위치, 규칙을 돌려준다. genesis가 틀리면 그 위의 어떤 판정도 의미가 없기 때문이다(§14).

4. **집합 사이 규칙(VC-104, VC-009, VC-067).** 한 상태의 집합들은 다음을 만족한다.
   - 투표함이 가리키는 투표소·경로·투표양식·보고 단위·모듈이 있고, 그 투표소가 투표함을 목록에 적는다. 투표소가 적은 투표함은 모두 있고 그 투표소를 가리킨다. 그래서 투표소의 목록은 그 투표소를 가리키는 투표함 전부와 같다.
   - 투표소마다 진행 경보 기준이 정확히 하나이고, 모든 기준은 있는 투표소를 가리킨다.
   - 보고 단위의 투표함 수는 그 단위를 가리키는 투표함 수와 같다.
   - 명부 항목의 근무 투표소가 있고, 명부·신뢰기관·증인 항목의 임명 해시가 임명 집합에 있다(VC-009). 변경이 임명 집합을 바꿔도 고정 집합의 임명은 남아야 한다.
   - 투표함의 모듈은 정당 챔버 `P1`…`Pn`마다 정확히 하나, `J`·`A`·`C`는 각각 하나 이하다. 카운터·가명 유닛(사용 중과 예비)의 모듈은 정당 챔버마다 정확히 하나이고 다른 챔버의 모듈은 없다. 모듈 집합에 genesis에 없는 정당 챔버의 모듈이 없다(`N`의 모듈은 디코더가 거부한다). 챔버마다 신뢰기관 항목이 정확히 `n_c`개다(VC-067, VC-017).
   - **새 규칙.** 투표소 참관인 토큰의 참관인은 명부에 참관인 역할로, 토큰과 같은 조직으로, 그 투표소에 등록되어 있고, 두 토큰이 확인 키를 함께 쓰지 않는다. 명부에 없거나 다른 투표소의 사람, 또는 남의 확인 키로 현장 증명의 도전값(§7.9)을 만들 수 없어야 하기 때문이다.
   - **새 규칙.** 명부·신뢰기관·증인 항목은 임명 해시를 함께 쓰지 않는다. 임명 이벤트는 피임명자 한 사람의 것이다(§4.5).
   - **새 규칙.** 모듈 하나는 장치(투표함 또는 카운터·가명 유닛) 하나의 목록에만 있다. 모듈은 꽂히는 장치 하나를 위해 발급되고(`ModuleProvisioned.device_id`, `ENCODING.md` §8.31) 모듈 카운터는 장치별로 이어지기 때문이다.
   - **새 규칙.** 장치 식별자(투표함 ID, 카운터·가명 유닛 ID, 모듈 ID)는 한 상태 안에서 겹치지 않는다. 장치 증명(`DeviceAttestation`)은 장치를 이 식별자 하나로만 가리키므로, 겹치면 어느 장치의 증명인지 정할 수 없다.
   - **새 규칙.** 등록된 모든 하이브리드 키는 유효한 키다(Ed25519 반쪽이 풀리고 약한 키가 아님). 아무것도 검증되지 않는 키를 등록한 투표함은 개시조차 할 수 없으므로 genesis에서 잡는다.
   - **새 규칙.** 한 상태의 모든 하이브리드 키(선관위, 위원회, 투표함의 장치 키와 증명 키, 카운터·가명 유닛의 키와 증명 키, 명부, 모듈의 키와 증명 키, 신뢰기관, 증인)는 서로 어느 반쪽도 겹치지 않는다. VC-098은 한 이벤트의 서명자끼리만 겹침을 막는다. genesis 전체에서 막으면 한 사람이 두 자리로 등록되거나 장치 키가 사람 키로 쓰이는 일을 이벤트가 생기기 전에 잡는다.

5. **장부 색인(§14 3항, VC-010, VC-039, VC-101).** 입력은 `VerifiedGenesis`, 프레임 스트림(디스크 형식 `u32_be 길이 ‖ 프레임 객체`), 이벤트 객체 목록(순서 무관, 같은 객체가 여러 번 있어도 됨)이다. 프레임마다:
   1. 레코드를 파싱하고 체인에 잇는다(순번, 이전 해시, genesis의 선거). 찢어진 꼬리는 격리하고 읽지 않으며 보류가 아니다(VC-010). 망가진 레코드나 끊긴 고리는 장부 전체 보류이고 색인은 거기서 멈춘다. 그 뒤 프레임이 이 장부의 것임을 보일 수 없기 때문이다.
   2. 비공개 이벤트의 프레임(`CheckinCounter` 0x0009 restricted, `SharePackage` 0x000B sealed; §5.2, §12.3)은 공개 장부에 프레임과 `event_hash`만 있으므로 본문 없이 해시로 색인한다(`OPAQUE_SCHEMAS`, 재수록 규칙은 그대로 적용). 스키마가 아직 없는 비공개 이벤트(`SampleOpening`)는 스키마가 생길 때 더한다. 그 밖의 프레임은 `event_hash`인 이벤트를 찾아 프레임의 스키마로 정규 디코드한다. 이 검증기가 아는 장부 이벤트 스키마만 받는다: `LegalAuthorizationBody`(0x0003), `SignedCheckpoint`(0x0010), `CastRecord`(0x0016), `BatchAttest`(0x0017), `ChallengeOpening`(0x0018), `BoxClose`(0x001A), `ScanCountAttest`(0x001B), `DeviceAttestation`(0x0024), `WitnessedEvent`(0x0028, 본문 스키마도 알려진 것), `ProgressTick`(0x0031), `SignedGenesis`(0x0033). 부록 A에서 스키마가 아직 없는 이벤트는 스키마가 생길 때 더한다. 모르는 스키마는 확인할 수 없으므로 장부 전체 보류다.
   3. 이벤트가 적은 선거가 genesis의 선거가 아니면 장부 전체 보류다(같은 장부의 프레임이라도). 이벤트가 누구에 관한 것인지 정한다: 투표함(본문의 `box_id`), 투표소(`IssuanceCount`, `ProgressCheck`, `ObserverCountAttest`, `CheckinUnitSwap`, 카운터·가명 유닛의 진행 기록), 또는 선거 전체(genesis, 체크포인트, 법적 승인과 결정, 투표함 없는 분쟁). 장치 증명은 장치 ID가 투표함이면 그 투표함, 카운터·가명 유닛이면 그 투표소, 아니면 선거 전체다. genesis의 어느 상태에도 없는 투표함·투표소를 가리키면 장부 전체 보류다(변경 전 상태의 투표함·유닛도 안다). 장부에 실린 `SignedGenesis`는 검증된 genesis가 적용한 본문(genesis나 변경)에 대한 것이어야 하고(같은 본문에 증인 서명 묶음이 다른 것은 받는다), 법적 승인은 genesis가 고정한 그 객체여야 한다. 아니면 장부 전체 보류다. 다른 genesis가 장부에 섞여 참관인 도구를 속이지 못하게 하기 위해서다.
   4. 이미 앞 프레임이 실은 이벤트(같은 객체 해시)면 이 프레임은 무효다(VC-101).
   5. 투표함의 **기록**(`CastRecord`, `ChallengeOpening`)이 그 투표함의 첫 `BoxClose` 프레임 뒤에 있으면 무효다(VC-039). 마감 뒤의 `BatchAttest`는 늦은 배치 마감(§7.2.1, VC-100)이므로 기록이 아니며, 짝이 되는 `LateBatchClose`와 96구간 기한은 투표함 단계가 판정한다. 마감 뒤 사람이 서명하는 이벤트(`LateBatchClose`, 인계, 각인 판독 등)와 장치의 마감 진행 기록(`ProgressTick`, ADR-0027)도 기록이 아니다. 두 번째 마감은 색인하고 상태 기계가 판정한다.

   거부한 프레임은 색인에 넣지 않지만 체인에는 남는다(트리 크기와 root는 모든 프레임으로 계산). 거부는 조용히 사라지지 않는다. 발견(`Finding`: 순번, 위치, 이벤트 해시, 범위, 종류)이 되고, 범위에 따라 그 투표함, 그 투표소의 모든 투표함, 또는 장부 전체를 `HOLD_REVIEW`로 둔다. 장부 전체 보류만 색인을 멈추지 않는다는 점에 주의: 빠진 이벤트 하나 때문에 나머지 투표함의 확인을 버리지 않는다. 투표함별 보류 조회(`box_holds`)는 그 투표함·투표소·장부 전체의 보류를 합쳐 돌려주고, 투표함별 이벤트(`box_events`)는 색인할 때 만든 위치 목록으로 장부를 다시 읽지 않고 꺼낸다. 처음 프레임이 다른 이유로 거부된 이벤트의 두 번째 프레임은 재수록으로 표시되지 않지만, 첫 거부가 이미 장부를 보류로 둔다.

6. **보류 사유.** `ityv-state`의 `HoldReason`에 셋을 더한다: `EventReplayed`(33, VC-101), `RecordAfterClose`(34, VC-039), `LedgerUnchecked`(35, 끊긴 체인·빠진 이벤트·정규가 아닌 이벤트·모르는 스키마·genesis에 없는 대상).

7. **`ityv-state`의 작은 변경.** `Pinned`가 `SignedGenesis`를 참조 대신 값으로 들고(`Copy`), `Pinned::new`가 임의 수명의 참조를 받는다. 검증기가 함수 안에서 디코드한 `SignedGenesis`로 봉인한 `Genesis<'a>`를 입력 바이트의 수명으로 돌려줄 수 있게 하기 위해서다. 의미는 같다.

8. **검증 사다리.** V1: 규칙마다 그 규칙만 어긴 genesis로 거부를 확인하는 통합 테스트(실제 하이브리드 서명과 Merkle root), 변경의 사슬·번호·다양성·집합 규칙, 색인의 각 발견 종류와 보류 범위, cargo-mutants 놓침 0. V2: Kani 하네스(모듈 챔버 규칙이 명세식과 같음, 집합 순서 판정). V5(독립 2차 구현과 차분 테스트)는 ROADMAP M5의 뒤 단계다.

## 결과

- 2a단계의 남은 일(집합 전체 확인)이 닫힌다. 상태 기계에 들어가는 genesis 항목은 이제 검증기가 집합 전체를 확인한 genesis에서만 나온다.
- 장부 색인이 생겨 4단계 이후(투표함 완전성, 기록, 참여, 집계, 감사, 분쟁, 연결, 소프트웨어)가 장부 전체를 다시 읽지 않고 투표함별 이벤트를 받는다.
- 아직 없는 것: 체크포인트 사슬(2단계), 4–12단계, 상태 사다리를 묶는 보고서, 미러 모드, 표본 검증 모드, 독립 2차 구현. ROADMAP M5에 남긴다.
- 집합 전체 확인은 전국 규모에서 집합마다 한 번의 선형 순회와 트리 계산이다(투표함 2.5만이면 해시 약 5만 번). 서명 검증은 genesis와 변경마다 최대 66개다.

## 검토한 대안

- **`std` 크레이트.** 파일과 네트워크를 직접 읽게 하면 편하지만 TCB에 입출력이 들어오고 브라우저(WASM)에서 쓰기 어렵다. 입출력은 TCB 밖 도구(`tools/`)가 맡는다.
- **첫 오류에서 장부 검증 전체를 멈춤.** 장부 하나의 빠진 이벤트로 모든 투표함의 확인을 잃는다. genesis와 달리 장부의 문제는 범위가 있으므로 범위별 보류로 둔다. 체인이 끊긴 경우만 멈춘다.
- **변경 전후 모든 상태의 집합을 보관.** 마지막 상태만 보관하고 각 상태의 앵커를 남긴다. 변경 전 상태로 서명된 기록을 그 상태의 항목으로 다시 확인하는 일은 기록 단계(5단계)를 만들 때 필요하면 더한다.
- **키 겹침을 이벤트에서만 확인(VC-098).** 이벤트가 생긴 뒤에야 잡힌다. genesis에서 막는 쪽이 싸고 이르다.
- **마감 뒤의 `BatchAttest`도 기록으로 거부.** 늦은 배치 마감(§7.2.1)을 막아 장치가 멈췄던 투표함의 열린 배치 보류가 영영 풀리지 않는다. 독립 검토에서 찾은 결함이며, 기록은 `CastRecord`·`ChallengeOpening`으로 정했다.
- **재수록을 본문 해시로 판정.** 같은 본문을 다시 서명한 객체(무작위 ML-DSA 서명, 다른 서명자 묶음)도 잡겠지만 명세(VC-101)는 객체 해시로 정한다. 같은 본문의 두 객체는 상태 기계가 같은 사건을 두 번 받지 않는 규칙(같은 슬롯, 같은 배치 번호 등)으로 다룬다.
