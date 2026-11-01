# 챔버 모듈과 고가치 키의 보관: 대안 비교와 전략

> English summary: Research draft comparing alternatives to a YubiHSM-class device for the roughly 252,000 field chamber modules and for the few hundred high-value keys, and laying out a life-cycle key storage strategy for our USB-form open MCU module. Finding: no off-the-shelf HSM or secure element does the whole field-module job (ML-DSA-87 signing, the counter rule, tens of megabytes of pads, open reproducible firmware, two MCU families, about USD 14–28 a unit). Keep the open MCU module from DEVICES.md, choose two of LPC55S69 / STM32U5·H5 / nRF54L, and add one cheap secure element (SE050-class, about USD 2–6) only to the check-in counter unit's party modules to hold the pseudonym PRF key non-exportably, because that key is identical in all of a party's ~18,700 modules and is the one key worth a lab attack. Mix chamber-supplied ceremony entropy into every key, encrypt the pad card at rest under a device-unique key, add a coin-cell tamper switch that zeroizes during the election window (added fleet cost about USD 0.40–0.95M), and never let the PRF key exist in clear outside the party ceremony and the modules. For the high-value tier use USB HSMs (YubiHSM 2, Nitrokey HSM 2) as key-encryption-key holders and share stores, and PQC-capable network HSMs (Entrust nShield firmware 13.8, Thales Luna) where hybrid ML-DSA signing must stay inside hardware. Status: research draft; ADR-0024 is proposed, not adopted.

- 상태: 연구용 초안. 결정은 ADR-0024(제안)이며 아직 채택되지 않았다. 이 문서는 규범이 아니다.
- 날짜: 2026-11-01
- 관련: ADR-0019, ADR-0020, ADR-0023, ADR-0024; `docs/hardware/DEVICES.md` §5.1, §5.2, §5.5, §6.2; `docs/spec/PROTOCOL.md` §6.4, §6.6, §9.4.2, §15
- 가격과 기능은 2026-11-01 기준 공개 자료다. 출처를 붙였고, 확인하지 못한 값은 (미확인)으로 적었다. 대량 단가는 견적으로 다시 확인해야 한다.

## 1. 결론부터

- **현장 모듈(약 25만 개)에 맞는 완제품 HSM이나 보안 칩은 없다.** 우리 모듈은 ML-DSA-87 서명, "한 카운터에 한 본문" 규칙, 수십 MB 패드, 공개 재현 펌웨어(ADR-0023), MCU 계열 둘 이상(DEVICES §6.2)을 개당 14–28달러에 해야 한다. 이 다섯을 한꺼번에 하는 상용 칩은 찾지 못했다. 그래서 **공개 MCU 모듈(DEVICES §5.2)을 그대로 쓰고, 보관 방식을 단단하게 하는 쪽**을 권한다.
- **MCU는 LPC55S69, STM32U5/H5, nRF54L 중 둘.** 셋 다 TrustZone, 기기 고유 키(PUF 또는 HUK), 변조 감지를 갖는다. RP2350은 2025년 공개 해킹 대회에서 OTP 비밀이 네 가지 방법으로 빠져나왔으므로 오래 가는 비밀을 맡기지 않는다.
- **보안 칩은 한 곳에만 넣는다.** 본인 확인 카운터 유닛에 꽂히는 정당 모듈에 SE050급 보안 칩(개당 약 2–6달러)을 붙여 **가명 PRF 키**만 넣는다. 이 키는 한 정당의 모든 확인 모듈(전국 약 1.87만 개)에 똑같이 들어가므로, 하나만 털어도 그 정당의 키가 나온다. 실험실 공격을 들일 가치가 있는 유일한 키다. 함대 비용은 약 15만–45만 달러다.
- **모든 키에 챔버가 가져온 엔트로피를 섞는다.** 칩의 난수원에 뒷문이 있어도 키를 예측할 수 없게 하기 위해서다.
- **패드 카드는 기기 고유 키로 암호화해 둔다.** 카드만 잃어버리면 아무것도 나오지 않는다.
- **선거 기간에는 코인 전지로 변조 스위치를 살려 둔다.** 외함이 열리면 키를 지운다. 개당 약 1–2달러(추정)다.
- **고가치 키(수백 개)에는 HSM이 맞다.** USB HSM(YubiHSM 2, Nitrokey HSM 2)은 키 암호화 키와 몫 보관에, PQC를 지원하는 네트워크 HSM(Entrust nShield 펌웨어 13.8, Thales Luna)은 ML-DSA 서명을 하드웨어 안에서 해야 하는 기관에 쓴다.

## 2. 현장 모듈이 해야 하는 일

| 일 | 키·자료 | 어디에 있나 | 비밀 등급 |
|---|---|---|---|
| 가명 PRF(본인 확인 카운터 유닛의 정당 모듈만) | 정당 PRF 키 `key_c` | 그 정당의 모든 확인 모듈에 **같은 값** | 높음. 모든 정당 키가 모이면 누가 어느 투표소에서 투표했는지(참여)가 드러남. 선택은 드러나지 않음(VC-019) |
| 기록·배치·카운터 서명 | 모듈 서명 키(ML-DSA-87 + Ed25519) | 모듈마다 다름 | 중간. 털리면 그 모듈 서명을 위조할 수 있으나 도난 신고 뒤 무효 처리 |
| 난수 기여(`r_c`, `cid_c`, `lab_c`) | 하드웨어 난수원 | 쓰고 즉시 지움 | 표마다 한 번. 한 챔버의 기여만으로는 아무것도 열리지 않음 |
| 일회용 패드 | 구성원별 패드 | 패드 카드(NOR 플래시) | 중간. 한 챔버의 한 스캐너 몫. 접근구조상 혼자로는 무의미 |
| 현장 증명(ADR-0023) | 증명 키(부트 ROM이 기기 고유 비밀과 이미지 해시에서 유도) | 모듈마다 다름, 밖으로 안 나감 | 중간 |
| 카운터 규칙 | 카운터와 마지막 서명 본문 해시 | 모듈 비휘발 저장소 | 무결성 |

## 3. 현장 모듈 후보 비교

### 3.1 완제품 보안 키와 HSM

| 후보 | 무엇인가 | 맞는 점 | 안 맞는 점 | 출처 |
|---|---|---|---|---|
| YubiHSM 2 | USB HSM | Ed25519, ECC, RSA, HMAC, AES. FIPS 140-3 판 있음 | 개당 650달러(FIPS판 950달러). ML-DSA 공개 목록 없음. 객체 256개·약 128KB. 정해진 기능만. 펌웨어 비공개. 25만 개면 약 1.64억 달러 | [Yubico](https://www.yubico.com/product/yubihsm-2/), [Yubico 스토어](https://www.yubico.com/store/yubihsm-2-series/), [SafeCipher](https://safecipher.co.uk/yubico-yubihsm-2/)(PQC 없음, 제3자), [Trust Panda](https://www.trustpanda.com.au/products/yubihsm-2)(용량, 제3자) |
| Nitrokey 3 | Rust Trussed 기반 공개 펌웨어 보안 키. MCU는 LPC55S6x 또는 nRF52840, 일부에 NXP SE050 | 우리와 같은 구조(공개 Rust 펌웨어 + MCU + 선택적 SE)가 실제 제품으로 돈다는 증거. 펌웨어 v1.7.0부터 OpenPGP가 SE를 기본으로 씀 | 소비자용 완제품이라 패드 카드, 카운터 규칙, ML-DSA를 넣으려면 결국 우리 펌웨어로 바꿔야 함. 소매가 약 53유로(모델 확인 필요) | [Nitrokey 포럼](https://support.nitrokey.com/t/nitrokey-3-changed-specs/3415), [Nitrokey SE050](https://www.nitrokey.com/node/614), [Nitrokey FAQ](https://docs.nitrokey.com/ja/nitrokey3/faq), [BerryBase](https://www.berrybase.de/nitrokey-3c-nfc-security-token-usb-c-nfc-fido2-webauthn-u2f-eal6-secure-element-open-source), [NLnet](https://nlnet.nl/project/Nitrokey-3/) |
| Solo 2 | LPC55S69 기반 공개 하드웨어 보안 키 | 공개 하드웨어 인증(OSHWA, 2021) | 현재 판매·지원 상태 확인 못 함(미확인) | [OSHWA](https://certification.oshwa.org/us001100.html) |

**판단.** 완제품을 사서 쓰는 것은 맞지 않는다. 다만 Nitrokey 3/Solo 2의 공개 설계와 Trussed(Rust)는 우리 참조 설계(`ityv-core`)가 참고하거나 일부 재사용할 수 있는 좋은 선례다.

### 3.2 보안 칩(SE)

| 후보 | 기능 | PQC | 가격(1,000개) | 판단 | 출처 |
|---|---|---|---|---|---|
| NXP SE050/SE051 | ECC, Ed25519(SE051 A2/C2, SE05x 애플릿), AES, HMAC, HKDF(제3자 표기), 보안 채널(SCP03) | 확인 못 함 | 약 2.07–5.99달러(변형·판매처별) | **PRF 키 보관에 권장.** HMAC를 칩 안에서 하고 키를 밖으로 내지 않음. 닫힌 펌웨어지만 PRF 키 하나만 맡김 | [DigiKey SE050E2](https://azcus.digikey.com/en/products/detail/nxp-usa-inc/SE050E2HQ1-Z01Z3Z/16366334), [DigiKey SE050A1](https://azcus.digikey.com/en/products/detail/nxp-usa-inc/SE050A1HQ1-Z01SGZ/10271727), [element14 SE050C2](https://au.element14.com/nxp/se050c2hq1-z01sdz/iot-secure-element-hx2qfn-105deg/dp/3955231), [NXP AN12973](https://nxp.jp/docs/en/application-note/AN12973.pdf)(SE051 EdDSA), [NXP AN12413](https://www.nxp.com/docs/en/application-note/AN12413.pdf)(APDU, HKDF), [LCSC](https://www.lcsc.com/pl/product-detail/C5190917.html)(HMAC·HKDF 표기, 제3자) |
| Tropic Square TROPIC01 | 공개 아키텍처 RISC-V 보안 칩. Ed25519, P-256 ECDSA, X25519(2차 자료) | 확인 못 함 | 공개 단가 없음 | **둘째 공급원 후보.** 설계를 감사할 수 있어 ADR-0023 원칙에 가장 가깝다. HMAC/PRF 지원은 미확인이라 M8에서 확인 | [Tropic Square 출시](https://tropicsquare.com/news-and-events/tropic-square-announces-official-launch-general-availability-of-tropic01---the-industrys-first-open-architecture-tamper-proof-secure-element), [양산](https://tropicsquare.com/news-and-events/tropic01-the-future-proof-secure-element-now-in-full-production-and-available-worldwide), [Embedded Computing](https://embeddedcomputing.com/technology/security/hardware-security/embedded-world-product-showcase-tropic-squares-tropic01-hardware-security-element), [CNX](https://www.cnx-software.com/2025/03/01/tropic-square-tropic01-is-an-auditable-open-architecture-tamper-proof-risc-v-secure-element-se-for-iot-and-microcontrollers/) |
| Infineon OPTIGA Trust M | ECC·RSA, 공장 주입 | 확인 못 함 | 영업 문의(공개가 없음) | 보류 | [Infineon GitHub](https://mtbgit.infineon.cn/Infineon/optiga-trust-m) |
| Infineon TEGRION | 보안 컨트롤러. ML-KEM 구현이 CC EAL6 인증(2025-01) | ML-KEM | 미공개 | eSIM·스마트카드용 컨트롤러라 MCU 옆에 붙이는 부품이 아님. 앞으로 볼 대상 | [Infineon 보도](https://new-origin.infineon.com/cms/en/about-infineon/press/press-releases/2025/INFCSS202501-043.html), [Electropages](https://electropages.com/2025/01/first-common-criteria-certification-post-quantum-cryptography-algorithm-security-controller) |
| Microchip ATECC608B | P-256만, 키 슬롯 16 | 없음 | 칩 단가 확인 못 함 | **제외.** Ed25519 없음, 새 설계 비권장(NRND) | [Microchip](https://www.microchip.com/en-us/product/ATECC608B), [Mouser](https://www.mouser.com/new/microchip/microchip-atecc608b-crypto-devices) |
| Microchip TA100 | 자동차용 | 확인 못 함 | 확인 못 함 | 정보 부족으로 보류 | — |
| SEALSQ QS7001 | RSA, ECC, AES, SHA-2/3, **ML-KEM-1024, ML-DSA-87**, TRNG(제조사 발표) | 있음(제조사 발표) | 공개 단가 없음 | **ML-DSA 키를 칩에 넣을 수 있는 유일한 후보.** 다만 "양산 출하"(2025-11)와 "양산 샘플"(2026-03) 발표가 엇갈리고, CC·FIPS 인증은 2026년 4분기 목표. 한 회사 제품이라 M8에서 시험만 | [SEALSQ 로드맵](https://www.sealsq.com/investors/news-releases/sealsq-announces-comprehensive-2026-certification-roadmap-for-qs7001-secure-element-and-qvault-tpm-product-lines), [Barchart 2025-11](https://www.barchart.com/story/news/36305775/sealsq-qs7001-quantum-resistant-secure-element-delivers-immediate-cnsa-2-0-compliance-with-hardware-embedded-post-quantum-cryptography), [VaultIC409 2026-10](https://thequantuminsider.com/2026/10/12/sealsq-vaultic409-secure-element-post-quantum-cryptography/) |

### 3.3 MCU(모듈 본체)

| 후보 | 키 보호 | 알려진 약점 | 가격 | 판단 | 출처 |
|---|---|---|---|---|---|
| NXP LPC55S69 | SRAM PUF 키 저장소, TrustZone-M, PRINCE 플래시 암호화 | 일반 MCU 수준. 실험실 결함 주입 표적이 되는 칩(ChipWhisperer 타깃 보드 존재) | 1,000개 약 4.92달러 | **권장(계열 A).** Nitrokey 3/Solo 2가 쓰는 칩이라 공개 Rust 생태계가 있다 | [Rocelec](https://www.rocelec.mx/part/01t4w00000PPMcoAAH-LPC55S69JBD100K), [NXP PUF](https://community.nxp.com/t5/LPC-Microcontrollers/LPC55S69-PUF-evaluation/m-p/1063867), [ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/chipwhisperer-target-cw308t/CW308T_LPC55S69/README.html) |
| ST STM32U5 / STM32H5 | HUK와 거기서 유도한 키(DHUK), 부채널 저항 SAES, 변조 시 보안 저장소 자동 삭제(U5), 변조 뒤 DHUK 사용 불가(H5), TrustZone | 일반 MCU 수준 | STM32U585 1,000개 약 5.6–6.2달러(DEVICES §5.2) | **권장(계열 B).** 변조 감지와 키 삭제가 칩에 있다 | [ST H5 보안](https://wiki.st.com/stm32mcu/wiki/Security:Security_features_on_STM32H5_MCUs), [ST H5 보안 저장소](https://prod.st-mediawiki.stormreply.com/stm32mcu/wiki/Security:Secure_Storage_for_STM32H5), [ST U5](https://st.com/content/st_com/en/about/events/events.html/strengthening-mcu-device-security-with-stm32u5.html) |
| Nordic nRF54L | CRACEN 암호 엔진(늘 켜진 변조 감지), KMU 키 슬롯, TAMPC(글리치·전압·온도·외부 핀) | 일반 MCU 수준 | (미확인) | **권장(계열 C, 셋째 공급원)** | [Nordic 데이터시트](https://docs.nordicsemi.com/r/bundle/ps_nrf54l15/page/tampc.html-cracen), [Hubble](https://hubble.com/community/guides/nrf54l15-security-features-trustzone-and-cryptocell-and-secure-boot-explained)(제3자) |
| Raspberry Pi RP2350 | OTP 키, 글리치 감지기, Arm·RISC-V 코어 | 2024–2025 해킹 대회에서 출전자 넷 모두 OTP 비밀을 뽑음(전압 글리치, 전자기 결함 주입, 레이저, FIB와 수동 전압 대비로 안티퓨즈 판독) | 저가 | **오래 가는 비밀은 맡기지 않는다.** 투명한 공개 방식은 본받을 만함 | [Raspberry Pi 결과](https://raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in), [WOOT '25](https://www.usenix.org/system/files/woot25_slides_muench.pdf), [IOActive](https://www.ioactive.com/characterizing-the-raspberry-pico-2-fi-countermeasures-part-1/) |

RP2350 결과가 주는 교훈은 칩 하나의 문제가 아니다. **실험실 장비를 가진 공격자는 일반 MCU의 읽기 보호를 결국 넘는다**고 보고 설계해야 한다. 그래서 키 하나가 털려도 그 기관 하나가 공모한 것과 같게 만드는 접근구조(ADR-0019)가 기본 방어이고, 하나만 털려도 많이 잃는 키(정당 PRF 키)에만 보안 칩을 더한다.

## 4. 고가치 키(수백 개) 후보

| 쓰임 | 수량(대략) | 후보 | 판단 | 출처 |
|---|---|---|---|---|
| 정당 PRF 마스터 키의 몫(정당 구성원 k-of-n) | 정당당 3–5개 | YubiHSM 2, Nitrokey HSM 2 | 몫을 기기 안의 불투명 객체로 보관. 둘 다 써도 됨(구성원마다 다른 제품이면 더 좋음) | [Yubico](https://www.yubico.com/product/yubihsm-2/), [Nitrokey HSM 2 99유로](https://shop.nitrokey.com/shop/nitrokey-hsm-2-7?page=2), [Nitrokey 사양](https://www.nitrokey.com/files/doc/Nitrokey_HSM_factsheet.pdf)(SmartCard-HSM 기반, 일부 독점 부품) |
| 신뢰기관 구성원이 받은 share 저장 | 챔버당 3명, 최대 8챔버 | USB HSM(키 암호화 키) + 암호화된 디스크 | share는 표마다 쌓여 수 GB가 되므로 HSM 안에 다 못 넣는다. HSM은 키 암호화 키만 들고, share 데이터베이스는 그 키로 암호화해 디스크에 둔다 | 위와 같음 |
| 증인 서명 키(하이브리드) | 13곳 이상 | PQC 지원 네트워크 HSM 또는 USB HSM(Ed25519) + 오프라인 ML-DSA 서명기 | ML-DSA까지 하드웨어 안에서 하려면 Entrust nShield(펌웨어 13.8.0에 ML-DSA·ML-KEM·SLH-DSA, NIST CAVP 통과, FIPS 140-3 갱신 심사 중) 또는 Thales Luna(ML-DSA·ML-KEM 지원 표기, 버전 미확인). 증인 사이에 제조사를 섞는다 | [Entrust](https://www.businesswire.com/news/home/20250910020412/en/Entrust-nShield-HSMs-Post-Quantum-Cryptography-Algorithms-Achieve-Validation-from-the-NIST-Cryptographic-Algorithm-Validation-Program), [Thales](https://www.thalestct.com/wp-content/uploads/2022/09/luna-network-hsm-pb-10-01-25.pdf) |
| 릴리스 서명 키(빌더 셋 이상), genesis·위원회 키 | 수십 개 | 위와 같음, 또는 Nitrokey NetHSM | NetHSM은 도구·드라이버·문서가 공개이고 클러스터가 되며 1만 유로 미만(ABI 추정). PQC 지원은 확인 못 함 | [NetHSM 사양](https://www.nitrokey.com/files/doc/Nitrokey_NetHSM_factsheet.pdf), [ABI Research](https://abiresearch.com/market-research/insight/7783874-nitrokey-hsm-a-tough-sell-in-a-highly-dema) |
| Utimaco 계열 | — | — | PQC 로드맵 언급만 있고 버전별 지원은 확인 못 함(미확인) | — |

**판단.** 수백 개 수준에서는 HSM이 맞다. 다만 ML-DSA를 지원하지 않는 USB HSM은 고전 서명 반쪽과 키 암호화 키만 맡기고, ML-DSA 반쪽은 PQC 네트워크 HSM이나 오프라인 서명기(그 키는 HSM이 든 키로 암호화해 보관)로 한다. 증인은 서로 다른 제조사를 써서 한 제품의 결함이 정족수를 무너뜨리지 않게 한다.

## 5. USB 모양 공개 MCU 모듈의 키 보관 전략

### 5.1 생성

- **모듈 안에서 만든다.** 서명 키, 증명 관련 키, 패드는 발급 의식에서 모듈 안에서 만든다. 밖에서 만든 키를 주입하지 않는다(정당 PRF 키만 예외, §5.4).
- **챔버 엔트로피를 섞는다.** 각 챔버는 자기 장비(고가치 계층의 HSM 등)에서 32바이트 이상의 엔트로피를 만들어 의식 현장에서 유선으로 모듈에 넣는다. 모듈은 `seed = SHA3-512("ityv:keygen:v1" ‖ 0x00 ‖ TRNG 출력 ‖ 챔버 엔트로피 ‖ module_id)`로 키를 유도한다. 챔버 엔트로피는 공개하지 않는다. 칩의 난수원에 뒷문이 있어도 챔버 엔트로피를 모르면 키를 예측할 수 없고, 챔버 장비에 뒷문이 있어도 칩 난수원을 모르면 예측할 수 없다.
- **기록.** `ModuleProvisioned`에 챔버 엔트로피를 넣었다는 사실과 그 엔트로피의 해시 약속(의식 참석 챔버만 원본을 앎)을 남긴다. 표마다의 난수 기여(`r_c`)는 계속 칩 난수원만 쓴다(표마다 의식을 할 수 없으므로). 그 대신 기여는 한 챔버 몫일 뿐이라 접근구조가 지킨다.

### 5.2 보관 중 보호

| 층 | 방법 | 비용 |
|---|---|---|
| 기기 고유 키 | LPC55S69은 PUF, STM32는 HUK/DHUK, nRF54L은 KMU. 이 키로 내부 플래시의 키 저장 영역을 암호화한다 | 칩에 포함 |
| 분리 | TrustZone 보안 영역에만 키 코드와 데이터를 둔다. 비보안 쪽은 서명 요청만 한다 | 칩에 포함 |
| 디버그·판독 | 출하 뒤 디버그 포트를 영구 잠그고 판독 보호를 최고 단계로 둔다 | 0 |
| 글리치·변조 감지 | 칩의 전압·클록·온도 감지기를 켜고, 감지되면 키 영역을 지우고 재시작한다 | 칩에 포함 |
| 패드 카드 | 패드는 카드에 **기기 고유 키로 암호화해서** 쓴다(스트림 암호). 카드만 떼어 가면 아무것도 읽을 수 없다. 전송 구간의 정보이론적 안전(일회용 패드)은 그대로이고, 보관 중에만 계산적 보호가 한 겹 더해진다. 쓰자마자 0으로 덮는 규칙(VC-034)도 그대로다 | 0(계산만) |
| 변조 스위치 | 외함에 스위치를 두고 코인 전지로 선거 기간에만 살려 둔다. 열리면 MCU의 변조 입력(STM32 TAMP, nRF TAMPC)이 키 영역을 지운다. 선거 사이에는 키가 이미 지워져 있으므로 전지가 다 돼도 문제없다 | 개당 약 1–2달러(추정) |
| 변조 반응 망(외함 전체를 덮는 감지선) | 하지 않는다. 개당 5–15달러(추정)에 전지 관리까지 25만 개는 부담이 크고, 접근구조와 변조 흔적 봉인으로 충분하다 | — |

### 5.3 사용 중 규칙

- 비밀이 들어가는 연산은 상수 시간으로 한다. 공개 라이브러리(`ityv-crypto`)의 규칙을 따른다.
- 표마다의 비밀(`r_c`, 기여값, 평문 share)은 쓰자마자 0으로 덮는다(VC-020과 같은 원칙).
- 카운터 규칙: 한 카운터 값에는 본문 하나만 서명하고, 서명한 본문 해시를 배치나 마감까지 비휘발 저장소에 둔다(VC-068).

### 5.4 정당 PRF 키는 따로 다룬다

**왜 특별한가.** 같은 사람은 전국 어디서나 같은 가명이 나와야 투표소를 건너는 이중 투표를 잡을 수 있다(§6.5). 그래서 한 정당의 PRF 키는 그 정당의 모든 확인 모듈(정당마다 전국 약 1.87만 개)에 **똑같이** 들어간다. 스캐너의 챔버 모듈에는 이 키가 없다. 하나만 훔쳐 털어도 그 정당 키 전체가 나온다.

**실제 위험.** 가명을 계산하려면 **모든** 정당의 키가 필요하다(§6.4). 공격자가 정당마다 모듈을 하나씩 훔쳐 모두 털면, 주민등록번호를 아는 사람의 가명을 계산해 공개된 `ParticipationSet`(§6.5)에서 **그 사람이 어느 투표소에서 투표했는지, 투표하지 않았는지**를 알 수 있다. 무엇을 찍었는지는 여전히 알 수 없다. 가명은 어떤 기록에도 표와 함께 실리지 않기 때문이다(VC-019). 그래도 투표 참여 여부는 협박이나 매수(기권 강요)에 쓰일 수 있는 민감한 정보이므로 막을 가치가 있다.

**제안.**
1. **선거마다 새 키.** 이미 명세에 있다(§9.4.2). 한 선거의 키가 털려도 다음 선거와 무관하다.
2. **정당 의식에서 오프라인으로 만든다.** 위원회 주관, 참관인 입회 아래 정당 구성원들이 각자 엔트로피를 가져와 공기 차단된 컴퓨터에서 마스터 키를 만든다.
3. **k-of-n으로 나눠 고가치 계층에 둔다.** 마스터 키는 정당 챔버 구성원(기본 2-of-3)에게 Shamir 몫으로 나눠 각자의 USB HSM(YubiHSM 2나 Nitrokey HSM 2)에 보관한다. 평문 마스터는 의식이 끝나면 지운다. 이 몫은 예비 모듈 발급과 중복 가명 조사(§6.6)에 쓰고, 공소시효나 재판이 끝날 때까지 보존한 뒤 파기한다(§6.6 6항).
4. **모듈마다 감싸서 넣는다.** 각 확인 모듈은 발급 때 자기 키 캡슐화 키쌍(ML-KEM-1024 + X25519, `ityv-crypto`의 하이브리드 KEM)을 만들고 공개키만 내놓는다. 정당 의식은 마스터 키를 모듈 공개키마다 감싸서(암호화해서) 보낸다. 감싼 키는 그 모듈에서만 풀린다. 평문 PRF 키는 정당 의식의 컴퓨터와 모듈 안 말고는 어디에도 없다.
5. **보안 칩에 넣는다(권장).** 확인 모듈의 정당 모듈에 SE050급 보안 칩을 붙이고, 모듈이 받은 PRF 키를 보안 칩의 보안 채널(SCP03)로 넣는다. 그 뒤 PRF 계산은 보안 칩 안의 HMAC로만 한다. 키는 칩 밖으로 나오지 않고, 칩을 털려면 일반 MCU보다 훨씬 비싼 실험실 공격이 필요하다. 정당마다 다른 보안 칩 공급원(SE050, TROPIC01 등)을 쓰면 한 칩의 공개 취약점으로 모든 정당 키가 한꺼번에 나오지 않는다.
   - **바뀌는 것.** PRF를 `SHA3-512(... ‖ key_c ‖ voter_id)`에서 `HMAC-SHA-256(key_c, "ityv:prf:v2" ‖ voter_id)`로 바꿔야 한다. SE050은 SHA3 기반 PRF를 칩 안에서 하지 못하기 때문이다.
   - **손익.** 안전성은 둘 다 충분하다(HMAC-SHA-256은 표준 PRF). 잃는 것은 해시를 SHA3 하나로 통일한 일관성 하나다. 얻는 것은 가장 넓게 퍼진 비밀 키가 칩 밖으로 나오지 않는다는 점이다.
   - **TROPIC01 등 HMAC가 없는 칩.** 결정적 서명(Ed25519)을 PRF처럼 쓰는 방법이 있으나 표준 PRF가 아니므로 권하지 않는다. HMAC 지원 여부를 M8에서 확인하고, 없으면 그 정당은 SE050 계열을 쓴다.
6. **같은 키인지 확인한다.** 각 모듈은 `prf_key_check = SHA3-512("ityv:prfcheck:v1" ‖ 0x00 ‖ key_c)`를 `ModuleProvisioned`에 싣는다. 256비트 무작위 키의 해시는 키를 드러내지 않는다. 누구나 한 정당의 모든 모듈이 같은 키를 받았는지 확인할 수 있다. 보안 칩을 쓰면 칩 안에서 같은 값을 HMAC로 계산해 낸다.
7. **도난 대응.** 확인 모듈이 사라지면 사건으로 기록하고 그 모듈의 서명 키를 무효로 한다. 선거 중에 PRF 키는 바꿀 수 없다(바꾸면 같은 사람의 가명이 달라져 중복 검사가 깨진다). 그래서 모든 정당에서 도난이 확인되면, 위원회는 그 선거의 `ParticipationSet`을 공개 대신 열람 제한으로 바꾸고 중복 수와 Merkle root만 공개하는 규칙을 둔다(채택 시 명세 변경 필요, §8).

### 5.5 인계와 보관

- 모듈은 번호 봉인 가방에 넣어 `CustodyHandoff` 사슬로 옮긴다. 혼자 두지 않는다(두 사람 규칙).
- 투표소 개시 때 사무원과 참관인이 봉인 번호와 모듈 ID를 genesis와 대조하고, 현장 증명(ADR-0023)을 받는다.
- 분실이나 봉인 훼손은 사건이다. 그 모듈의 키는 무효로 하고, 그 모듈이 들어간 장치의 기록은 전수 대조 대상으로 둔다(§12.5).

### 5.6 파기와 백업

- **패드:** 쓰자마자 0으로 덮고(VC-034), 선거가 끝나면 패드 카드를 통째로 파쇄한다.
- **모듈 본체:** 파기 의식에서 키 영역, 내부 플래시, RAM을 0으로 덮고 봉인 보관했다가 다음 선거에 새로 발급한다(P4).
- **백업:** 모듈마다의 키는 백업하지 않는다. 고장 나면 미리 발급한 봉인 예비 모듈로 바꾼다. 백업은 정당 PRF 마스터의 k-of-n 몫 하나뿐이다.

## 6. 위협별로 얻는 것과 막는 법

| 위협 | 공격자가 얻는 것 | 막는 법 |
|---|---|---|
| 현장 모듈 하나 도난(스캐너) | 그 모듈의 서명 키, 그 스캐너 그 챔버 구성원 몫의 패드(카드 암호화를 풀면), 그 챔버의 기여. 표 하나 열 수 없음(접근구조) | 인계 사슬, 사건 기록과 키 무효, 패드 카드 암호화, 변조 스위치 |
| 확인 모듈 하나 도난 | 위 + 그 정당의 PRF 키(보안 칩이 없으면) | 보안 칩, 정당마다 다른 칩 공급원, 키 무효, 선거마다 새 키 |
| 정당마다 하나씩, 모두 n개 도난 | 모든 정당 PRF 키를 털면 누구든 가명 계산 → 투표 참여 여부와 투표소. 선택은 아님 | 보안 칩(정당마다 실험실 공격 필요), 도난 탐지, 탐지 시 `ParticipationSet` 열람 제한 전환 |
| 발급 의식의 내부자 | 한 챔버 내부자는 자기 챔버 것만. 선관위 내부자는 키를 보지 못함(모듈 안에서 생성) | 모듈 내부 생성, 챔버 엔트로피, 정당 PRF 마스터의 k-of-n, 참관과 기록 |
| 한 MCU 계열의 공급망 뒷문 | 난수원 뒷문: 챔버 엔트로피가 막음. 판독 뒷문: 그 계열을 쓴 챔버들의 모듈 키 | MCU 계열 둘 이상, 정당마다 다른 계열(DEVICES §6.2), 접근구조 |
| 훔친 모듈에 결함 주입·부채널 공격 | 일반 MCU는 결국 뚫린다고 본다(RP2350 사례) | 변조 스위치, 선거마다 새 키, 탐지 뒤 무효, PRF 키는 보안 칩 |
| 패드 카드 분실 | 카드 암호화 덕분에 카드만으로는 없음. 모듈까지 털어도 한 챔버 한 스캐너 몫 | 카드 암호화, 그 모듈은 KEM 대체 경로로 전환(§9.4.5), 사건 기록 |
| 정당 PRF 몫 보관 구성원 공모 | k명이 모이면 그 정당 키 하나. 혼자로는 가명 계산 불가 | k-of-n, 서로 다른 HSM 제품, 의식 기록 |

## 7. 함대 비용 차이(DEVICES §5.5 수량 기준, n = 4)

| 선택 | 대상 수 | 개당 추가 | 함대 추가 | 판단 |
|---|---|---|---|---|
| 기본(보안 칩 없음) | 약 25.2만 | 0 | 0 | 기준 |
| 확인 모듈 정당 PRF 키를 보안 칩에 | 약 7.5만(카운터 유닛 약 1.87만 × 4) | 약 2.07–5.99달러 | **약 15만–45만 달러** | **권장** |
| 모든 모듈에 보안 칩(고전 키까지) | 약 25.2만 | 약 2.07–5.99달러 | 약 52만–151만 달러 | 고전 키 반쪽만 보호돼 이득이 작다 |
| PQC 보안 칩(QS7001)으로 ML-DSA까지 | 약 25.2만 | 미공개(가정 5–15달러, 미확인) | 가정 시 약 126만–378만 달러 | 인증과 공급 안정 뒤 M8에서 재검토 |
| 변조 스위치와 코인 전지 | 약 25.2만 | 약 1–2달러(추정) | **약 25만–50만 달러** | **권장** |
| 변조 반응 망 | 약 25.2만 | 약 5–15달러(추정) | 약 126만–378만 달러 | 권하지 않음 |
| 정당 PRF 몫용 USB HSM | 정당당 3–5개 | 약 99–950유로·달러 | 수천 달러 | **권장** |
| 현장 모듈을 YubiHSM 2로 | 약 25.2만 | 650달러 | 약 1.64억 달러 | 제외 |

권장 조합의 함대 추가는 약 **40만–95만 달러**다. DEVICES §5.5의 모듈 비용(350만–710만 달러)에 견주면 약 6–27%, 가운데 값으로 약 13%다.

## 8. 채택하려면 바꿔야 할 명세

1. `PROTOCOL.md` §6.4: 정당 PRF 키의 생성(정당 의식, 오프라인), k-of-n 보관, 모듈별 감싼 주입, 평문 존재 범위를 규정. PRF를 `HMAC-SHA-256(key_c, "ityv:prf:v2" ‖ voter_id)`로 바꾸고 가명 식의 입력을 맞춤(보안 칩 채택 시).
2. `PROTOCOL.md` §6.5: 모든 정당에서 확인 모듈 도난이 확인되면 `ParticipationSet`을 열람 제한으로 바꾸고 중복 수와 root만 공개하는 규칙.
3. `PROTOCOL.md` §9.4.2: 챔버 엔트로피 혼합 키 생성, 패드 카드의 보관 중 암호화(기기 고유 키), 변조 스위치와 지움, `prf_key_check` 공개.
4. `PROTOCOL.md` §15: 정당 PRF 마스터 몫의 보존·파기(§6.6 6항과 연결), 모듈 본체 0 덮기 증거.
5. `PROTOCOL.md` 부록 A·C: 새 이벤트 `PartyKeyCeremony`(공개: 정당, 선거, 감싼 모듈 수, k-of-n, 참석자 서명, 키 자료 없음), 새 VC(챔버 엔트로피 기록, 한 정당 모든 모듈의 `prf_key_check` 일치, 지움 증거).
6. `ENCODING.md`: `ModuleProvisioned`에 `entropy_commitment`, `prf_key_check`(정당 확인 모듈만), `se_present` 필드. `PartyKeyCeremony` 스키마.
7. `GOVERNANCE.md`: 정당 PRF 몫 보관 역할과 기본 2-of-3, 고가치 계층 장비 다양화(증인 제조사 섞기).
8. `docs/hardware/DEVICES.md` §5.1·§5.2·§5.5: 확인 모듈의 보안 칩과 변조 스위치 부품표, "모듈 보안 칩을 두지 않는다" 판단을 "확인 모듈 정당 PRF만 둔다"로 고침.
9. `FAILURE_CASES.md`: 모듈·패드 카드·PRF 몫 분실 행.
10. `LEGAL_ANNEX.md`: 모듈 절취·키 추출의 처벌, `ParticipationSet` 공개 제한 전환의 근거.

## 9. 권장 구성

**현장 계층(약 25.2만 개).**
- 공개 MCU 모듈(`ityv-core`)을 쓰고, MCU는 LPC55S69, STM32U5/H5, nRF54L 중 둘 이상으로 한다. 정당마다 다른 계열을 쓴다.
- 모든 키는 모듈 안에서 칩 난수원과 챔버 엔트로피를 섞어 만든다.
- 키 저장 영역은 기기 고유 키로 암호화하고 TrustZone 보안 영역에만 둔다. 디버그는 영구 잠그고, 칩의 글리치·변조 감지를 켠다.
- 패드 카드는 기기 고유 키로 암호화한다.
- 코인 전지로 선거 기간에만 살아 있는 변조 스위치를 둔다.
- 본인 확인 카운터 유닛의 정당 모듈에만 SE050급 보안 칩을 붙여 PRF 키를 넣고, HMAC-SHA-256 PRF를 칩 안에서 계산한다. 정당마다 칩 공급원을 다르게 하는 것을 권장한다(TROPIC01은 HMAC 지원 확인 뒤 둘째 공급원 후보).
- 함대 추가 비용은 약 40만–95만 달러다.

**고가치 계층(수백 개).**
- 정당 PRF 마스터는 정당 구성원 2-of-3 몫으로 나눠 YubiHSM 2나 Nitrokey HSM 2에 둔다.
- 신뢰기관 구성원의 share 데이터베이스는 USB HSM이 든 키 암호화 키로 암호화해 디스크에 둔다.
- 증인·릴리스·genesis·위원회 키는 ML-DSA를 하드웨어 안에서 하려면 Entrust nShield(펌웨어 13.8.0)나 Thales Luna를 쓰고, 그렇지 않으면 USB HSM(Ed25519) + 오프라인 ML-DSA 서명기로 한다. 증인끼리는 제조사를 섞는다.

**M8에서 확인할 것.** SE050 변형별 HMAC 지원과 SCP03 키 주입 절차, TROPIC01의 HMAC 지원과 단가, QS7001의 실제 공급·인증 상태와 단가, 세 MCU 계열의 결함 주입 내성 시험, 코인 전지 변조 스위치의 오작동률.
