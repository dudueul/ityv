# ADR-0024: 챔버 모듈과 고가치 키의 보관

> English summary: Adopted 2026-11-01. Keep the open MCU chamber module rather than any off-the-shelf HSM; build it on at least two of LPC55S69, STM32U5/H5 and nRF54L; generate every module key inside the module from the chip TRNG mixed with secret chamber-supplied ceremony entropy; encrypt the key area and the pad card at rest under a device-unique key; add a coin-cell tamper switch live only during the election window. Treat the party pseudonym PRF key specially because it is identical in all of a party's check-in modules: generate it offline in a party ceremony, keep it as 2-of-3 Shamir shares on USB HSMs (YubiHSM 2 / Nitrokey HSM 2), inject it into each module wrapped to that module's hybrid KEM key, hold it inside an SE050-class secure element on the check-in modules and compute the PRF there as HMAC-SHA-256, publish a key-check hash so anyone can confirm a party's modules share one key, and downgrade ParticipationSet to restricted if every party's modules are confirmed stolen. Use USB HSMs and PQC-capable network HSMs only for the few hundred high-value keys. Added fleet cost about USD 0.40–0.95M.

- 상태: 채택(2026-11-01). 반영: PROTOCOL §6.4, §6.5, §6.6, §9.4.2, §15, 부록 A·B·C(VC-092..096), ENCODING §8.31·§8.32
- 날짜: 2026-11-01
- 관련: ADR-0019, ADR-0020, ADR-0023; `docs/hardware/KEY_STORAGE.md`; `docs/hardware/DEVICES.md` §5.1, §5.2, §5.5, §6.2; `docs/spec/PROTOCOL.md` §6.4, §6.5, §6.6, §9.4.2, §15

## 맥락

현장 챔버 모듈은 전국 약 25.2만 개다(DEVICES §5.5, n = 4). YubiHSM 2 같은 HSM은 개당 650달러(FIPS판 950달러)이고, 공개 목록에 ML-DSA가 없으며, 저장 공간이 약 128KB이고, 정해진 기능만 하며, 펌웨어가 비공개라 ADR-0023의 재현 빌드 원칙과 맞지 않는다. 다른 보안 칩과 보안 키, MCU를 조사한 결과는 `docs/hardware/KEY_STORAGE.md` §3–§4에 있다. 어떤 상용 부품도 현장 모듈의 일(ML-DSA-87 서명, 카운터 규칙, 수십 MB 패드, 공개 펌웨어, 둘 이상의 MCU 계열)을 개당 14–28달러에 다 하지 못한다.

한편 명세는 정당 PRF 키를 그 정당의 모든 확인 모듈에 어떻게 똑같이 넣는지 정하지 않았다(§6.4는 "챔버 c가 보유"라고만 함). 이 키는 한 정당 안에서 전국 약 1.87만 개 모듈에 같은 값으로 들어가므로, 모듈 하나만 털어도 그 정당 키가 나온다. 모든 정당 키가 모이면 누구의 가명이든 계산할 수 있어, 공개된 `ParticipationSet`에서 그 사람의 투표 참여 여부와 투표소가 드러난다. 선택은 드러나지 않는다(VC-019).

2024–2025년 RP2350 공개 해킹 대회에서 출전자 넷 모두 OTP 비밀을 뽑았다. 실험실 장비가 있는 공격자는 일반 MCU의 읽기 보호를 결국 넘는다고 보고 설계해야 한다.

## 결정

1. **현장 모듈은 공개 MCU 모듈을 유지한다.** 완제품 HSM이나 보안 키를 사서 쓰지 않는다. MCU는 LPC55S69, STM32U5/H5, nRF54L 중 둘 이상을 같은 커넥터와 프로토콜로 지원하고, 정당마다 다른 계열을 쓴다. RP2350에는 오래 가는 비밀을 맡기지 않는다.
2. **키 생성.** 모든 모듈 키는 발급 절차에서 모듈 안에서 만든다. 칩 난수원 출력과, 챔버가 자기 장비로 만들어 유선으로 넣은 비공개 엔트로피를 SHA3-512로 섞는다. `ModuleProvisioned`에는 엔트로피를 넣었다는 사실과 해시 약속만 남긴다.
3. **보관 중 보호.** 키 저장 영역과 패드 카드를 기기 고유 키(PUF 또는 HUK)로 암호화한다. 키 코드는 TrustZone 보안 영역에만 둔다. 디버그를 영구 잠그고, 칩의 글리치·변조 감지를 켠다. 선거 기간에만 코인 전지로 살아 있는 외함 변조 스위치가 열리면 키 영역을 지운다. 외함 전체를 덮는 변조 반응 망은 쓰지 않는다.
4. **정당 PRF 키.**
   - 선거마다 정당 열쇠 생성 절차에서 공기 차단된 컴퓨터로 만들고, 정당 구성원 2-of-3 Shamir 몫으로 나눠 USB HSM(YubiHSM 2 또는 Nitrokey HSM 2, 구성원마다 다른 제품 권장)에 보관한다.
   - 각 확인 모듈의 하이브리드 KEM 공개키(ML-KEM-1024 + X25519)로 감싸 주입한다. 평문은 정당 열쇠 생성 절차의 컴퓨터와 모듈 안에만 존재한다.
   - 확인 카운터 유닛의 정당 모듈에 SE050급 보안 칩을 붙여 PRF 키를 보안 채널로 넣고, PRF를 칩 안에서 `HMAC-SHA-256(key_c, "ityv:prf:v2" ‖ voter_id)`로 계산한다. 정당마다 보안 칩 공급원을 다르게 하기를 권장한다.
   - 각 모듈은 `prf_key_check = SHA3-512("ityv:prfcheck:v1" ‖ 0x00 ‖ key_c)`를 공개해, 한 정당의 모든 모듈이 같은 키를 받았음을 누구나 확인할 수 있게 한다.
   - 몫은 예비 발급과 중복 가명 조사(§6.6)에 쓰고 §6.6 6항의 기한까지 보존한 뒤 파기한다.
   - 모든 정당에서 확인 모듈 도난이 확인되면 그 선거의 `ParticipationSet`은 열람 제한으로 바꾸고 중복 수와 Merkle root만 공개한다.
5. **인계·파기·백업.** 번호 봉인 가방과 두 사람 규칙으로 옮기고, 분실·훼손은 사건과 키 무효로 처리한다. 패드는 쓰자마자 지우고 카드는 선거 뒤 파쇄한다. 본체는 0으로 덮어 재사용한다. 모듈 키는 백업하지 않고 예비 모듈로 대신한다.
6. **고가치 계층(수백 개).** USB HSM은 키 암호화 키, 정당 PRF 몫, 고전 서명 반쪽에 쓴다. 신뢰기관 구성원의 share는 HSM이 든 키 암호화 키로 암호화해 디스크에 둔다. ML-DSA를 하드웨어 안에서 해야 하는 증인·릴리스·genesis·위원회 키에는 PQC 지원 네트워크 HSM(Entrust nShield 펌웨어 13.8.0, Thales Luna)을 쓰거나, USB HSM(Ed25519) + 오프라인 ML-DSA 서명기로 한다. 증인끼리는 제조사를 섞는다.

## 결과

- 함대 추가 비용은 약 40만–95만 달러(보안 칩 약 15만–45만, 변조 스위치 약 25만–50만, USB HSM 수천 달러)로, 모듈 비용(350만–710만 달러)의 약 6–27%다.
- 가장 넓게 퍼진 비밀(정당 PRF 키)이 보안 칩 밖으로 나오지 않는다. 모든 정당 키를 얻으려면 정당마다 다른 보안 칩을 실험실에서 공격해야 한다.
- 칩 난수원의 뒷문 하나로 키가 예측되지 않는다.
- 패드 카드만 잃어버리는 사고는 정보 유출이 아니다.
- 잃는 것: 가명 PRF가 SHA3에서 HMAC-SHA-256으로 바뀌어 해시 통일성 하나를 잃는다. 확인 모듈 펌웨어가 보안 칩 드라이버를 갖게 된다. 보안 칩 펌웨어는 공개되지 않는다(맡기는 것은 PRF 키 하나뿐).
- 남는 위험: 실험실 공격으로 모든 정당의 보안 칩을 털면 투표 참여 여부가 드러난다. 선택은 여전히 드러나지 않는다.

## 기각한 대안

- **현장 모듈을 YubiHSM 2 등 완제품 HSM으로.** 약 1.64억 달러, ML-DSA 없음, 저장 공간 부족, 비공개 펌웨어, 한 회사 의존.
- **Nitrokey 3 같은 완제품 보안 키를 사서 쓰기.** 구조는 같지만 패드 카드와 카운터 규칙, ML-DSA를 넣으려면 결국 펌웨어를 바꿔야 한다. 공개 설계와 Trussed는 참조로 쓴다.
- **모든 모듈에 보안 칩.** 고전 키 반쪽만 보호되고 비용은 세 배다.
- **PQC 보안 칩(SEALSQ QS7001)으로 ML-DSA까지.** 가장 매력적이지만 공급 상태 발표가 엇갈리고 인증이 2026년 4분기 목표이며 단가가 공개되지 않았다. M8에서 시험하고 다시 본다.
- **변조 반응 망.** 25만 개에 전지 관리까지 부담이 크고, 접근구조와 봉인으로 충분하다.
- **ATECC608B.** Ed25519가 없고 새 설계 비권장이다.

## 연결되는 검증

- 반영: PROTOCOL §6.4(HMAC-SHA-256 PRF, 정당 PRF 키 배포), §6.5(공개 제한 전환, `ParticipationRestriction`), §6.6(몫으로 다시 넣기, 보존), §9.4.2(엔트로피 혼합, 패드 카드·키 영역 암호화, 변조 스위치), §15, 부록 A·B·C. ENCODING §8.31 `ModuleProvisioned`(0x0026), §8.32 `PartyKeyCeremony`(0x0027). VC-092 정당 열쇠 생성 절차 기록, VC-093 `prf_key_check` 일치, VC-094 공개 제한 전환, VC-095 모듈 키 생성·보관 보호, VC-096 몫 보존·파기.
- M8: SE050 변형별 HMAC와 SCP03 주입, TROPIC01 HMAC 지원과 단가, QS7001 공급·인증·단가, 세 MCU 계열의 결함 주입 시험, 변조 스위치 오작동률.
- 코드: `ityv-crypto`에 HMAC-SHA-256 PRF와 `prf_key_check`(카운터·가명 유닛 크레이트가 생길 때), 카운터 유닛 펌웨어(M8)에 보안 칩 드라이버. ROADMAP에 적었다.
