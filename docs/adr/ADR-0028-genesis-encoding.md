# ADR-0028: genesis의 정규 형식

> English summary: A national genesis holds about 15,000 stations, 25,000 boxes and tens of thousands of roster signers, so it cannot be one bounded `no_std` object. The genesis becomes a body (`GenesisBody`, schema `0x0002`, version 6) that holds the scalar fields and document pins, the keys of the election commission and the Independent Verification Committee (which may share no key half), the witness quorum and diversity rule, the party roster and chamber thresholds, and for each of eleven entry sets a count and a Merkle root. Each entry is a canonical object of its own schema (boxes, stations, progress policies, reporting units, custody routes, roster signers, chamber modules, ballot styles, trustees, witnesses; appointments are a sorted hash set); a set is strictly ascending by the entry key, its leaves are the entries' object hashes, and its root is the RFC 9162-shaped SHA3-512 root of `ityv-ledger`. The pinned genesis hash is the object hash of the body. `SignedGenesis` (`0x0033`) carries the body with the commission's, the committee's and at least `q` witness signatures. `GenesisAmendment` (`0x0034`) replaces the eight amendable set commitments and the release pin, numbered and chained to the previous body, signed the same way; ballot styles, trustees, witnesses, keys and the quorum cannot be amended because the body has no field for them. Three witnessed station events get canonical bodies: `ObserverCountAttest` (`0x003F`, observers only), `CheckinUnitSwap` (`0x0040`) and a new `BoxUnitSwap` (`0x0041`) for the count a spare commitment unit continues from. `ityv-state` takes every key, box, station, route, roster signer and limit only as an entry proved against a pinned genesis whose signatures it checked, the check-in total only from the observers' signed final count, and spare-device counts only from the signed swap records. Whole-set checks (order, uniqueness, cross-set agreement) belong to the full verifier (VC-104).

- 상태: 채택
- 날짜: 2026-11-02
- 관련: ADR-0002(법적 승인), ADR-0016(증거 장부), ADR-0019(n개 정당 챔버), ADR-0023(소프트웨어 신원과 현장 증명), ADR-0025(상태 크레이트), ADR-0027(투표 진행 기록); `docs/spec/PROTOCOL.md` §4, §6.2, §6.3, §7.10, 부록 A–C; `docs/spec/ENCODING.md` §6, §8.43, §8.48–§8.59

## 맥락

PROTOCOL §4.1은 genesis에 들어갈 것을 나열하지만 인코딩은 없었다. M5 1단계는 상태 기계가 genesis 항목의 바이트를 받도록 `GenesisBox`, `CustodyRoute`, `RosterSigner`, `StationProgressPolicy`를 필드 형으로만 정했고, 나머지는 호출자가 "검증된 genesis에서" 넘겼다. 카운터·가명 유닛의 키, 참관인이 서명한 마지막 확인 인원, 예비 장치가 이어 세는 누계, 법적 승인의 두 키, 분쟁 이벤트의 두 기관 키, 법정 권한 기관의 키가 그랬다. 검증기는 이 값들을 대조할 기준이 없었다.

genesis를 객체 하나로 만들 수도 없다. 전국 선거라면 투표소 약 15,000곳, 투표함 25,000개 이상, 사무원·참관인·보관 담당자 수만 명이다. 하이브리드 공개키 하나가 2,624바이트이므로 투표함 목록만 130MB를 넘는다. TCB 크레이트는 `no_std`이고 힙이 없어서 크기가 고정된 값만 다룬다. 장치와 상태 기계는 자기 투표함·투표소 항목 하나만 알면 되는데 genesis 전체를 받아야 할 이유도 없다.

## 결정

1. **머리와 항목 집합.** genesis는 본문(`GenesisBody`, 0x0002)과 항목 집합 11개로 나눈다. 본문에는 한 번에 담을 수 있는 것만 둔다. 항목 집합은 집합마다 항목 수와 Merkle root만 본문에 들어간다.

   | 자리 | 내용 |
   |---|---|
   | 본문 | `election_id`, `election_epoch_day`, `policy_hash`, `proof_system_id`, 법적 승인 본문 해시, 연결 목록 해시, 릴리스 목록 해시, 선관위 키, 위원회 키, 증인 정족수 `(n, q, f)`와 다양성 하한(조직·공급자·지역), 정당 명부(2–4, `P1`…`Pn`, 의석 내림차순, 자격 근거 해시), 챔버별 `k_c`·`n_c`(`P1`…`Pn`, `J`, `A`, `C`, `N`), 집합 11개의 (항목 수, root) |
   | 집합 1 `Boxes` | `GenesisBox`(0x0035): 투표함, 투표소, 투표양식, 수집 프로필, 경로, 보고 단위, 장치 키, 증명 키, 챔버 모듈 |
   | 집합 2 `Stations` | `StationEntry`(0x0036): 카운터·가명 유닛(사용 중과 봉인 예비, 각 키·증명 키·정당 모듈), 투표소의 모든 투표함, 신원 확인 단말 목록 해시, 참관인 토큰과 확인 키, 투표소 종류 |
   | 집합 3 `ProgressPolicies` | `StationProgressPolicy`(0x0037): 기표소 수, 경보 기준 장수 |
   | 집합 4 `ReportingUnits` | `ReportingUnitEntry`(0x0038): 보고 단위와 속한 투표함 수 |
   | 집합 5 `Routes` | `CustodyRoute`(0x0039) |
   | 집합 6 `Roster` | `RosterSigner`(0x003A): 사무원, 참관인, 보관 담당자, 법정 권한 기관 |
   | 집합 7 `Modules` | `ModuleEntry`(0x003B): 챔버 모듈 키, 증명 키, `ModuleProvisioned` 해시 |
   | 집합 8 `Appointments` | 임명 이벤트 해시(항목 객체 없음, 정렬 집합) |
   | 집합 9 `BallotStyles` | `BallotStyleEntry`(0x003C): 선택지 수 `m`, 청크 수 `k`, 배치 문서 해시 |
   | 집합 10 `Trustees` | `TrusteeEntry`(0x003D) |
   | 집합 11 `Witnesses` | `WitnessRosterEntry`(0x003E). 이 집합의 root가 `witness_roster_hash`다 |

2. **집합의 모양.** 항목의 리프 입력은 그 항목 객체의 객체 해시(`ENCODING.md` §4)다. 객체 해시에 스키마 ID가 들어가므로 한 집합의 항목을 다른 집합의 항목으로 내밀 수 없다. 집합은 항목의 열쇠(투표함 ID, 투표소 ID, 서명자 ID 등) 바이트 오름차순이고 같은 열쇠는 두 번 나오지 않는다. root는 `ityv-ledger`의 RFC 9162 모양 SHA3-512 트리 root이고(PROTOCOL §5.3) 빈 집합은 빈 트리의 root다. 임명 집합만은 해시 자체를 바이트 오름차순으로 둔 정렬 집합이다. 열쇠 순서로 정렬했으므로 검증기는 항목 하나를 이진 탐색으로 찾고, 이웃 항목과 비교해 중복이 없음을 확인할 수 있다.

3. **핀과 서명.** genesis 핀은 본문 객체의 객체 해시다(VC-005). `SignedGenesis`(0x0033)는 본문 바이트와 선관위 서명, 위원회 서명, 증인 서명(`witness_id` 오름차순, 본문의 `q` 이상, 64 이하)을 담는다. 모든 서명은 본문 바이트에 대한 하이브리드 서명이고 purpose는 `genesis`다. 선관위와 위원회 키는 ML-DSA-87 반쪽과 Ed25519 반쪽이 모두 달라야 하며 본문 디코더가 거부한다(VC-006과 같은 이유). 서명에 참여한 증인은 증인 집합에 있어야 하고, 조직·공급자·지역 수가 본문의 하한 이상이어야 한다(VC-014와 같은 규칙). 어느 두 서명자도 키 반쪽을 함께 쓰지 않는다(VC-098).

4. **변경.** `GenesisAmendmentBody`(0x0034)는 번호(1부터), 이전 본문 해시(1번은 genesis 핀, 그 뒤는 직전 변경 본문의 객체 해시), 사유 코드와 사유 문서 해시, 시행 구간, 릴리스 목록 해시, 그리고 바뀔 수 있는 집합 8개(1–8번)의 새 (항목 수, root)를 담는다. 바뀌지 않는 집합도 그대로 다시 적는다. 투표양식, 신뢰기관, 증인 집합과 두 기관 키, 정족수는 본문에 자리가 없어 바꿀 수 없다. 이것을 바꾸려면 새 genesis와 새 핀이 필요하다. 서명은 genesis와 같고 purpose는 `genesis-amendment`, 정족수는 genesis의 `q`다. 변경 전에 증명한 항목으로 서명된 기록은 그대로 유효하다(§4.3, VC-105).

5. **투표소 사건.** 상태 기계가 호출자에게서 받던 수를 서명된 사건으로 바꾼다. 모두 `WitnessedEvent`(0x0028)에 실린다(VC-106).
   - `ObserverCountAttestBody`(0x003F, purpose `observer-count`): 투표소, 카운터·가명 유닛, 확인 인원 누계(마지막 순번), 정기·마감 구분, 시간 구간. 서명은 참관인만, 서로 다른 조직 둘 이상(VC-016).
   - `CheckinUnitSwapBody`(0x0040, purpose `checkin-swap`): 고장 유닛, 예비 유닛, 예비가 보고를 시작하는 슬롯, 확인 여부, 예비가 이어받는 다음 순번, 교부·훼손 회수·반납 누계. 확인하지 못했으면 누계는 0이고 그 투표소의 진행 기록과 참여 등식은 보류다. 사무원 2인과 서로 다른 조직 참관인 2인이 서명한다.
   - `BoxUnitSwapBody`(0x0041, purpose `box-swap`): 투표함, 슬롯, 확인 여부, 투입 장수 누계. 예비 커밋먼트 유닛의 키는 `GenesisAmendment`가 등록하고, 이 사건은 현장에서 확인한 누계를 남긴다. 서명은 `CheckinUnitSwap`과 같다.

6. **상태 기계의 입력.** `ityv-state`의 `genesis` 모듈이 genesis를 받는 유일한 입구다. `Pinned::new`는 핀과 본문 해시를 대조하고, `Pinned::seal`은 선관위·위원회·증인 서명의 검증 토큰을 본문의 키와 증인 항목에 결속해 정족수와 다양성을 확인하며, `Genesis::entry`는 항목 객체를 디코드하고 포함 증명을 현재 root에 대조한다. 상태 기계는 증명된 항목(`Entry`)만 받는다. 이제 호출자가 넘기지 않는 것은 다음과 같다.
   - 투표함의 장치 키·모듈·프로필·경로(`BoxSpec::new`), 카운터·가명 유닛의 키와 예비 유닛, 투표소의 투표함 목록과 경보 기준(`CheckinStream::open`, `StationProgress::new`)
   - 사무원·참관인·보관 담당자·법정 권한 기관의 키(`RosterEntry`는 증명된 `RosterSigner` 항목이다)
   - 법적 승인의 두 키와 승인 객체 자체(`authorize`는 genesis가 고정한 해시의 객체만 받는다), 분쟁 이벤트의 두 기관 키
   - 마감 대조의 확인 인원(`ObserverCount`의 마감 수), 예비 장치가 이어 세는 누계(`CheckinUnitSwap`, `BoxUnitSwap`)와 예비 커밋먼트 유닛의 키(변경된 genesis의 `GenesisBox` 항목)

7. **항목의 출처.** 항목은 증명할 때의 genesis head(마지막으로 적용한 본문의 해시, 변경 전에는 핀)를 함께 기록한다. 항목을 둘 이상 함께 받는 함수는 head가 다른 항목을 거부하고, `Genesis`도 함께 받는 함수는 그 genesis의 현재 head로 증명하지 않은 항목을 거부한다(`Error::StaleEntry`). 그래서 변경이 손상된 커밋먼트 유닛의 키를 바꾼 뒤에는 변경 전 항목으로 투표함 명세나 진행 기록 흐름을 만들 수 없고, 변경 전후 항목을 섞을 수도 없다. 오래 사는 상태 기계(투표함, 진행 기록 흐름)는 만들 때의 genesis 상태(핀, 변경 번호, head)를 기록하고, 변경을 따를 때는 다시 증명한 항목으로 만든 새 명세를 명시적으로 받는다(`BallotBox::follow`, `BoxStream::swap`). 같은 핀의 더 큰 번호로만 갈 수 있다. 명부 조회는 한 head의 명부만 받는다.

8. **검증기의 몫.** 포함 증명은 항목 하나가 있음을 보일 뿐 다른 항목이 없음을 보이지 못한다. 그래서 집합 전체가 필요한 확인은 검증기(`ityv-verify`, M5 2b 이후)가 모든 항목을 받아 한다(VC-104): 열쇠 오름차순과 중복 없음, 항목 수와 root 재계산, 집합 사이의 일치(투표함이 가리키는 투표소·경로·투표양식·보고 단위·모듈이 있음, 투표소가 적은 투표함 목록이 그 투표소를 가리키는 투표함 전부와 같음, 보고 단위의 투표함 수, 투표소마다 경보 기준이 하나, 명부·신뢰기관·증인 항목의 임명 해시가 임명 집합에 있음(VC-009), 정당 챔버와 모듈의 짝(VC-067)). 구현과 추가 규칙(참관인 토큰과 명부, genesis 전체의 키 반쪽 겹침 금지)은 ADR-0029(`ityv-verify`)에 있다.

## 결과

- 장치와 상태 기계는 genesis 핀, 본문(16KB 이하), 서명, 그리고 자기 항목과 증명(40개 해시 이하)만 받는다. 크기는 투표소 수와 무관하다.
- 법정 권한 기관은 명부의 네 번째 역할(`RosterRole::Authority`)로 등록한다. `LegalDecisionRef`는 그 항목의 키로만 받는다. 어떤 분쟁에 어떤 기관이 권한을 갖는지는 여전히 법이 정하고 기계는 판단하지 않는다(VC-049).
- `StationEntry`가 투표소의 투표함 목록을 가지므로, 진행 경보 평가기는 호출자가 고른 투표함 목록 대신 genesis가 정한 목록을 쓴다.
- 스키마 0x0002의 버전 1–5는 내용만 나열한 명세 초안이었다. 처음 인코딩된 것이 버전 6이며 같은 버전 번호를 다른 모양에 다시 쓰지 않는다.
- 투표함 교체의 누계를 `GenesisAmendment`에 적던 문구(§7.10 8항)는 `BoxUnitSwap`으로 바꾼다. 변경은 선관위·위원회·증인 정족수가 서명하는 전국 단위 사건이라 현장에서 센 수를 적기에 맞지 않다.

## 검토한 대안

- **객체 하나.** 크기 상한이 수백 MB가 되고 `no_std` 디코더가 다룰 수 없다.
- **해시 순 정렬 집합.** 체크포인트의 `box_close_root`처럼 해시 순이면 열쇠로 항목을 찾을 수 없고, 같은 열쇠를 가진 두 항목도 막지 못한다.
- **투표소별 하위 genesis.** 투표소마다 서명 묶음이 생겨 서명과 핀이 1만 배로 늘어난다.
- **변경이 genesis 전체를 대체.** 핀이 바뀌어 대역 외 배포를 다시 해야 하고, 변경 전에 서명된 기록을 어느 핀으로 볼지 모호해진다.
