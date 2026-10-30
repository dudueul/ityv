# ADR-0006: 암호 자세, 영구 비밀성 커밋먼트 구조

> English summary: The public board must remain harmless forever, even against quantum adversaries. Therefore ballots are published as perfectly hiding generalized Pedersen commitments over Ristretto255 with sigma-protocol membership proofs, never as encryptions. Openings are secret-shared to trustees through the chamber access structure using a linear scheme, so trustees reconstruct only aggregate openings; shares are destroyed after the dispute window. Signatures are hybrid ML-DSA-87 AND Ed25519 (both must verify); SLH-DSA co-signs archival checkpoints; share transport uses trustee-provisioned one-time pads as primary and hybrid ML-KEM-1024 + X25519 as fallback; SHA3-512 everywhere; the fixed-width canonical encoding of docs/spec/ENCODING.md. The proof system is versioned so it can be migrated.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0001, ADR-0005, ADR-0012; `docs/spec/PROTOCOL.md`, `docs/spec/ENCODING.md`

## 맥락

ElGamal 계열 E2E는 게시판의 암호문이 계산적으로만 숨겨져 있어 양자컴퓨터가 등장하면 모든 과거 선거의 표가 소급해서 드러난다. 격자 기반 E2E는 표준과 배포 사례가 없다. 한국 선거의 모든 투표지는 단일 선택이므로 준동형 합계로 충분하고 믹스넷은 필요 없다.

## 결정

### 원시 암호

| 용도 | 선택 |
|---|---|
| 해시, 추적코드, 도메인 분리, Fiat-Shamir | SHA3-512 |
| 표 커밋먼트 | 일반화 Pedersen over Ristretto255. 숨김은 무조건적, 결속은 계산적(DLOG) |
| 정형성 증명 | Σ-프로토콜 1-of-m OR 증명(표현 지식). 건전성은 선거 당시에만 필요 |
| 서명 전부 | ML-DSA-87 **그리고** Ed25519. 둘 다 검증돼야 유효 |
| 장기 보존 체크포인트 | SLH-DSA-SHAKE-256s 추가 서명 |
| share 전송 | 1차: 챔버 모듈의 일회용 패드. 2차: ML-KEM-1024 **그리고** X25519 하이브리드(상태 표기 필수) |
| 직렬화 | `docs/spec/ENCODING.md` |
| 구현 | 검증된 라이브러리 우선(libcrux, HACL*/fiat-crypto 백엔드). 독립 2차 구현으로 교차 검증 |

### 커밋먼트 인코딩

- 선택지 집합: 후보 1..m에 `BLANK`(미기표)와 `UNREADABLE`(해석 불가)을 더한 고정 집합. 법적 유효성 판단은 사람이 하며 스캐너의 해석은 잠정값이다.
- 자릿수 묶음: 선택 `v`를 `M^v`로 부호화한다. `M = 2^26`(전국 유권자 수 4,400만을 초과). 커밋먼트 하나가 9개 선택지까지 담는다(9 × 26 = 234비트 < 252비트). 선택지가 9개를 넘는 투표양식은 커밋먼트를 ⌈m/9⌉개로 나눈다.
- 커밋먼트: `C = G_val^{M^v} · G_id^{cast_id} · H^{r}`. 투함 ID는 커밋먼트 안에만 존재한다. 관외의 봉투 라벨은 모듈 기여에서 유도한 독립 토큰이며 커밋먼트에 넣지 않고 share로만 전달한다.
- 정형성 증명: `C / G_val^{M^j}`가 `G_id, H`에 대한 표현을 가진다는 1-of-m OR 증명. 챌린지는 ENCODING.md §4의 Fiat-Shamir 규칙.
- 집계: 투표양식별로 `Π C_i`를 계산하고 신뢰기관이 `Σ r_i`, `Σ cast_id_i`를 복원해 `Σ M^{v_i}`를 얻은 뒤 26비트 자릿수로 후보별 수를 읽는다.

### share와 접근구조

- `r`과 `cast_id`를 선형 비밀분산으로 챔버 접근구조(ADR-0012)에 맞게 분산한다. 상위: `r = r_X + r_Y + r_rest`, `r_rest`는 {J, A, C, N} 중 3-of-4 Shamir. 챔버 내부는 `k_c`-of-`n_c` Shamir. 선형이므로 표별 share를 합산하면 합계의 share가 된다.
- 신뢰기관은 합계만 복원한다. 개별 표는 공개 추첨된 감사 표본에 대해서만 복원한다.
- share 패키지는 공개하지 않으며, 해시만 투함 기록에 남긴다. 불일치가 발견되면 투표함·표 단위로 이분 탐색해 결함 스캐너를 특정한다.
- 인증과 이의 기간이 끝나면 share와 선거별 키를 공개 의식에서 파기한다.

### 은닉 채널 저항

스캐너가 커밋먼트 난수에 선택을 실어 공모자에게 흘리는 공격을 가정한다. 난수는 커밋먼트 유닛이 아니라 챔버 모듈들이 기여하며(`r = Σ_c r_c`), 각 모듈은 발급마다 카운터를 공개 서명하고 자기 챔버 구성원용 일회성 MAC 태그를 봉인 패키지에 넣는다. 카운터 틈은 공개 기록에서 누구나 보고(난수 버리기 탐지), 정족수는 표본 기록의 `r_c`만 복원해 태그를 검사한다(모듈 난수 미사용 탐지). `r`을 결정하는 어떤 값도, 해시조차 공개하지 않아야 영구 비밀성이 유지되므로 모듈 태그는 비공개다. 상세는 `docs/spec/PROTOCOL.md` §7.2, §9.5.

### 버전과 이전

투함 기록은 `proof_system_id`를 가진다. 격자 기반 또는 해시 기반 증명이 성숙하면 게시판 형식을 바꾸지 않고 교체한다.

## 결과

- 게시판 크기는 표당 약 2.5–3KB(기록 자체에는 서명이 없고 모듈·장치 서명은 64건 배치마다 `BatchAttest`로 묶는다), 전국 4,400만 표에 약 110–130GB다. 표마다 ML-DSA-87 서명을 붙이면 20KB를 넘어 900GB에 이르므로 채택하지 않았다. 검증은 병렬화된다. 기관 검증자는 전수, 시민 검증기는 표본과 합계를 검증한다.
- 잔여 위험: 일회용 패드 대신 KEM 대체 경로를 쓴 구간은 전송 녹취 후 ML-KEM과 X25519가 모두 깨지고 임계치만큼의 share가 복원되는 경우에 노출된다. 대체 경로 사용은 공개 상태로 표기한다.
- 격자·해시 기반 증명으로의 이전 계획을 `docs/ROADMAP.md`에 둔다.

## 기각한 대안

- 고전 준동형 암호화(ElGamal): 소급 양자 노출.
- 완전 양자내성 E2E: 미성숙.
- 믹스넷 평문 공개: 불필요하며 투표지 패턴 연결 위험.
