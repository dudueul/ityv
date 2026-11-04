# ADR-0002: 법적 트랙, 단일 아키텍처, 법적 게이트와 단계 활성화

> English summary: One architecture, one codebase, one data model. Deployment profile L0 (evidence layer) runs under current law; L1 (E2E layer) activates only when the genesis carries a legal_authorization object signed by the election commission and the Independent Verification Committee. Modules are gated by capability types and compile-time features. Activation is staged 0-3 and mapped to specific statutory amendments in docs/legal/LEGAL_ANNEX.md. L0 is L1 with gated modules disabled; there is no fork.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0001, ADR-0007, ADR-0012; `docs/legal/LEGAL_ANNEX.md`

## 맥락

현행 공직선거법은 E2E 계층을 세 곳에서 막는다. 제151조⑥은 사전투표용지 바코드 내용을 선거명·선거구명·관할위원회명·일련번호로 고정하고, 유권자 검증코드를 허용하는 조문이 없으며, 암호학적 집계에 법적 지위가 없다. 제167조③·제166조의2는 비밀투표 보호 조문이라 폐지가 아니라 예외 추가가 필요하다. 이것은 악용 가능한 허점이 아니라 입법 공백에 명시적 제한이 겹친 상태다.

## 결정

1. 아키텍처는 하나다. 배포 프로필 L0와 L1은 같은 코드베이스, 같은 데이터 모델, 같은 장부이며 법적 게이트로만 구분된다. 법이 바뀌면 코드가 아니라 genesis의 승인 범위가 바뀐다.
2. 게이트는 genesis 안의 `legal_authorization` 객체다. 필드: 승인 범위 집합, 조문 참조 해시, 시행 구간, 선관위 서명, 독립검증위원회 서명. 두 서명이 모두 있어야 유효하다.
3. 각 L1 모듈은 자기 승인 범위가 서명돼 있을 때만 활성화된다. 코드에서는 capability 타입으로 강제한다. 토큰 값은 genesis 검증기만 만들 수 있고, L0 배포에서는 커밋먼트 객체 자체를 타입상 만들 수 없다.
4. 승인 범위와 활성화 단계:

| 단계 | 필요한 법령 변화 | 활성화되는 범위 | 유권자가 보는 변화 |
|---|---|---|---|
| 0 | 없음(선관위 규칙) | `PUBLIC_BOARD` | 없음 |
| 1 | 신설 제278조의2·제278조의3(독립검증위원회, 증인과 신뢰기관), 제186조의2(봉인 기록의 보존과 파기), 제278조의7(공개 기록의 시점확인), 벌칙 제244조의2 | `TRUSTEE_BODY` | 없음 |
| 2 | 신설 제151조의2(검증표식), 제157조 단서와 신설 제157조의2(투입장치), 제158조 신설 항, 신설 제178조의2·제178조의3(봉인 기록 검증, 위험제한감사), 신설 제181조의2(전자적 검증 참관), 제278조 개정과 신설 제278조의4·제278조의5(인증, 시범·영향평가), 제228조⑤ | `BALLOT_MARK`, `CRYPTO_TALLY_AID`, `RLA`, `OBSERVER_ACCESS`, `DEPLOY_AUTH`, `STAGE_GATE` | 투표지에 투함 ID 각인, 투입 절차 변경 |
| 3 | 제166조의2③·제167조④⑤ 개정(검증코드와 코드 슬립), 신설 제278조의6(검증 이의신청), 제241조③~⑤ 벌칙 | `VOTER_CODE` | 추적코드 슬립 수령 |

   조문 번호는 `docs/legal/LEGAL_ANNEX.md` §2의 번호 원칙을 따른다. 새 제도는 시행 중인 항과 번호가 겹치지 않도록 빈 "조의2" 번호에 두고, 기존 조문에는 그 조를 가리키는 단서만 단다. 단계별 조문의 정본은 같은 문서 §3.2의 단계표다.

5. 모든 구성요소는 사양에 법적 상태 라벨을 단다: `deployable-now`, `needs-rule`, `needs-statute`. 라벨은 `docs/assurance/REQUIREMENTS_HARVEST.md`의 요구사항 행에 기록한다.
6. 단계 전환 조건은 모두 같다. 개인정보 영향평가, 독립 암호 검토, 비구속 병행 모의선거, 인증, genesis 승인 범위 갱신.

## 결과

- L0 프로필은 봉인·수량·인계·우편 3중 대조·공개 증거 장부·분쟁 보전을 제공하며 유권자가 보는 것은 바뀌지 않는다.
- `VOTER_CODE`는 제241조 벌칙(검증코드 요구·수집·매수 금지)이 시행되기 전에는 절대 켜지 않는다.
- L0가 "편의상" 내용 연결 경로를 키우지 못하도록, 커밋먼트와 추적코드 관련 타입은 게이트 토큰 없이 생성 불가능하다.

## 기각한 대안

- 목표 시스템만 설계하고 입법 전까지 현장 증거 없이 대기.
- 현행법용 시스템을 먼저 만들고 E2E를 별도 프로젝트로 미룸.

## 연결되는 검증

- 타입 수준: `ityv-state` 크레이트의 capability 토큰에 대한 컴파일 실패 테스트(trybuild).
- V2: genesis 검증기의 서명·범위 검사 Kani 하네스.
