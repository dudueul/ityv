# ADR-0019: 정당 챔버 n개(2–4)

> English summary: Replace the two party-bloc chambers X and Y (and the optional third bloc Z) with one chamber per qualifying party, P1..Pn with 2 ≤ n ≤ 4. Qualification is by size and frozen in genesis: parties that hold National Assembly seats and met the proportional-seat threshold in the most recent general election (3% of the list vote or 5 constituency seats, Public Official Election Act Art. 189(1)), ranked by current seats, top four; never fewer than the top two by seats. The access structure requires every party chamber plus at least three of {J, A, C, N}; with n = 2 it equals the previous structure. One honest party chamber, or two honest chambers among J, A, C, N, keeps every ballot secret. The cost is n veto points on the cryptographic verification layer only: the paper count proceeds and is the legal result, and refusals are public. Pseudonyms combine the PRF outputs of all party modules; scanners carry every party module (at most seven modules); chamber codes become P1–P4, J, A, C, N. The code follows in the same pull request.

- 상태: 채택(ADR-0012의 신뢰기관 접근구조를 대체)
- 날짜: 2026-11-01
- 관련: ADR-0004, ADR-0009, ADR-0012, ADR-0015, ADR-0017; `docs/governance/GOVERNANCE.md` §3; `docs/spec/PROTOCOL.md` §4.1, §6.2–§6.4, §7.1, §9.2, §14; `docs/spec/ENCODING.md` §8.6–§8.19; 법령 부속서 개정안 10; VC-017, VC-031, VC-067

## 맥락

ADR-0012는 여는 값의 share를 정당 블록 둘(X, Y)과 사법·학계·시민·선관위에 나누고, 열 때는 X와 Y가 반드시 있게 했다. 블록은 "서로 대립하는 두 축"이어야 했고 위원회가 선거마다 지정했다. 여기에는 세 가지 문제가 있었다.

1. 어느 정당이 어느 축인지는 객관적으로 정할 수 없다. 지정 자체가 정치 분쟁이 되고, 지정을 비틀면 한쪽 블록에 같은 편 정당만 몰아넣을 수 있다.
2. 블록 챔버 안에서는 소속 정당 가운데 하나만 있어도 그 블록의 몫이 열렸다(1-of-n). 블록 안의 가장 작은 정당 하나가 블록 전체를 대신할 수 있었다.
3. 국회에는 교섭단체 둘 말고도 의석을 가진 정당이 여럿 있는데, 제3 블록은 선택 사항(챔버 Z)으로만 남아 있었다.

## 결정

1. **정당 챔버.** 블록 대신 정당마다 챔버 하나를 둔다. P1…Pn, 2 ≤ n ≤ 4.
2. **자격(규모 기준).** genesis를 작성하는 시점에 국회 의석을 가진 정당 가운데, 직전 국회의원선거에서 비례대표 의석 배분 기준(비례대표 득표율 3% 이상 또는 지역구 5석 이상, 공직선거법 제189조제1항)을 넘은 정당을 현재 의석 순으로 세워 위에서 넷까지 정당 챔버로 한다. 의석이 같으면 직전 선거의 비례대표 득표율 순이다. 자격을 갖춘 정당이 둘이 안 되면 의석 순 상위 둘로 채운다. 직전 선거 뒤에 합당한 정당들은 하나로 세고, 합당 전 정당 가운데 하나라도 기준을 넘었으면 기준을 넘은 것으로 본다. P1이 의석이 가장 많다.
3. **정당 명부.** genesis는 정당 명부(챔버 코드, 정당 이름, genesis 시점 의석 수, 자격 근거 문서의 해시)를 담는다. genesis 이후의 합당·해산·탈당은 챔버를 바꾸지 않는다. 챔버 구성원은 정당이 추천해 임명된 개인이고, 그 의무는 파기 절차까지 이어진다.
4. **접근구조.** Γ = { S : {P1, …, Pn} ⊆ S ∧ |S ∩ {J, A, C, N}| ≥ 3 }. 정당 챔버는 모두 필수다. n = 2이면 이전 구조("X와 Y 포함, 여섯 중 다섯")와 같다.
5. **분산.** `r = r_{P1} + … + r_{Pn} + r_rest`. `r_{Pi}`는 무작위이고 `r_rest`는 {J=1, A=2, C=3, N=4}에 3-of-4 Shamir로 나눈다. 각 챔버의 몫은 다시 구성원 사이에 `k_c`-of-`n_c`로 나누며, 정당 챔버의 기본값은 그 정당이 추천한 구성원 셋 중 둘이다. 블록 챔버의 "소속 정당 중 하나" 규칙은 없어진다.
6. **가명.** 모든 정당 모듈의 PRF 출력을 챔버 코드 순으로 이어 붙여 해시한다. 가명을 계산하거나 특정인의 가명을 다시 만들려면 모든 정당의 PRF 키가 있어야 한다. 정당 PRF 키의 생성, 보관, 주입은 ADR-0024를 따른다. 확인 장치는 정당 모듈 n개를 갖고, `CheckinCounter`에는 그 서명이 모두 붙는다.
7. **스캐너.** 정당 모듈 P1…Pn은 필수이며 위임하지 않는다. J·A·C는 자체 모듈이나 중립 모듈을 쓰고 N은 모듈이 없다. 모듈은 최대 7개다.
8. **인코딩.** 챔버 코드는 `u8`로 1 P1, 2 P2, 3 P3, 4 P4, 5 J, 6 A, 7 C, 8 N이다. X·Y 코드는 폐기한다. 모듈 배열 상한은 6에서 7로, `MemberShare.shares` 상한은 50에서 58(모듈 7 × 청크 8 + 2)로 늘고, 챔버 단위 상한은 8이다.
9. **자격 없는 정당.** 자격이 없는 정당과 무소속은 이전처럼 증인단이나 시민 챔버의 추천 경로로 참여한다.
10. **코드.** `ityv-crypto`(`shares`의 챔버와 접근구조), `ityv-encoding`(챔버 코드, 배열 상한), `ityv-cunit`(모듈 상한 7, 필수 모듈 검사)는 아직 X·Y와 상한 6을 쓴다. 같은 PR 안에서 이 ADR에 맞춘다(ROADMAP M3).

## 결과

- **비밀.** 정당 챔버 하나만 정직하거나, J·A·C·N 가운데 둘이 정직하면 어떤 표도 열리지 않는다. 선관위가 정당 몇 곳과 손을 잡아도 빠진 정당이 하나라도 있으면 열 수 없다.
- **편을 가를 필요가 없다.** 누가 어느 쪽인지 정하지 않아도 된다. 정당을 모두 필수로 두는 것은 편을 정의하지 않고도 정직한 정당 하나로 충분한 유일한 규칙이다.
- **대가.** 정당 챔버 n개가 저마다 암호 검증 층을 멈출 수 있다(거부권 n개). 멈추는 것은 검증 층뿐이고 종이 개표는 계속되며 그 결과가 법적 결과다. 거부 사실과 사유는 공표되고, `GOVERNANCE.md` §3.5의 정당한 사유 없는 거부는 법적 의무 위반이다. 상한 4는 거부권의 수와 스캐너 모듈 슬롯을 함께 묶어 둔다.
- **가용성.** 정당 챔버 구성원은 2-of-3이라 한 명의 키 분실은 견딘다. 정당이 해산하거나 합당해도 챔버는 없어지지 않는다.
- **크기.** 정당이 넷이면 모듈 5개(P1–P4와 중립) 기준으로 공개 기록이 표당 약 3.3KB, 봉인 패키지가 기록당 약 12KB(구성원 24명)다(`PROCESSING_FLOWS.md` §9).
- ADR-0015 §6의 고정 용량(챔버 6)은 코드 변경과 함께 8이 된다.

## 기각한 대안

- **두 블록 유지(ADR-0012 원안).** 축의 지정이 정치 분쟁이 되고, 블록 내부 1-of-n은 가장 작은 정당 하나가 블록을 대표하게 한다.
- **정당 챔버 n개 중 n−1개 이상.** 작은 정당 하나의 거부로는 멈추지 않는다. 하지만 정당이 넷일 때 셋이 모이면 나머지 한 정당 없이도 열리므로, 같은 편 정당이 셋 이상 자격을 얻으면 비밀이 한 진영의 손에 들어간다.
- **의석 비례 가중 임계.** 큰 정당 둘의 가중치가 임계를 넘으면 나머지 정당은 아무 의미가 없어진다. 선형 비밀분산으로 구현하면 share 수가 의석 수만큼 늘어난다.
- **정당 수 상한 없음.** 거부권과 모듈 수가 끝없이 늘고, 군소 정당의 키 관리 역량에 비밀과 가용성을 함께 건다.

## 연결되는 검증

- VC-067: genesis 정당 명부의 형식(2 ≤ n ≤ 4, 코드 P1…Pn이 빈틈없이 이어짐, 의석 내림차순), `trustee_roster`에 모든 정당 챔버가 있음, `expected_boxes`와 `stations`의 모듈 목록에 모든 정당 모듈이 있음. 공개 검증기의 genesis 단계(PROTOCOL §14의 1)가 검사한다.
- VC-017(가명에는 모든 정당 모듈이 필요), VC-031(접근구조 밖의 집합은 아무 정보도 얻지 못함).
- V3: `ityv-crypto` 접근구조 구현을 n = 2, 3, 4에 대해 전수 검사한다(Γ 안의 집합은 복원하고, 밖의 집합이 보는 share는 비밀과 독립). cargo-mutants 놓침 0.
- M7 Tamarin 모델의 비밀성 질의를 정당 챔버 n개로 일반화한다.
