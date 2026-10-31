# ADR-0014: 기록 서명 구조, 배치 증명, 창의 피해 한계

> English summary: Per-record hybrid post-quantum signatures would make each public record about 21 KB and the national board about 930 GB. ityv therefore signs every cast record immediately with cheap classical Ed25519 signatures (device and each chamber module) and provides the post-quantum hybrid signatures once per 64-record batch (or 15 minutes, or box close) over a Merkle root of record hashes. For closed batches the per-record authenticity guarantee reduces to the same assumptions as per-record signing. The residual window before a batch closes is bounded to at most 64 records per device, affects only post-quantum attestation status, never the paper count, secrecy or the legal result, and is recoverable by a witnessed late close. Unattested records are published, excluded from the cryptographic tally with a stated reason, and compared with paper in the audit. A sealed emergency deposit path with public counts covers scanner outage. docs/spec/FAILURE_CASES.md enumerates every case.

- 상태: 채택
- 날짜: 2026-10-30
- 관련: ADR-0005, ADR-0006, ADR-0007; `docs/spec/PROTOCOL.md` §7.2.1, §7.6, §10.2; `docs/spec/FAILURE_CASES.md`; VC-053..057

## 맥락

프로토콜 초안은 기록마다 모듈과 장치의 하이브리드 서명을 붙였다. ML-DSA-87 서명은 4,627바이트이므로 모듈 3개와 장치의 서명만으로 기록 하나가 약 21KB, 전국 4,400만 표에 약 930GB가 되어 공개 검증의 배포와 처리가 비현실적이었다. 배치 서명으로 바꾸면 표당 약 2.7KB가 되지만, 배치가 닫히기 전 최대 64건이 서명 없이 존재하는 창이 생긴다는 지적이 있었다.

## 결정

1. **기록 서명.** 커밋먼트 유닛은 기록 본문 해시에 장치 Ed25519 키로, 각 모듈은 `(본문 해시, module_id, counter)`에 자기 Ed25519 키로 서명한다. 기록과 함께 즉시 공개된다.
2. **배치 증명.** 64건마다, 또는 마지막 기록 후 15분, 또는 마감 직전에 기록 해시의 Merkle root와 모듈 카운터 구간에 장치와 모듈이 하이브리드(ML-DSA-87과 Ed25519) 서명한다. 모듈은 자기 카운터 구간이 틈 없이 일치할 때만 서명한다. 서명 전에 커밋먼트 유닛은 메모리 해시 사슬과 저널을 대조한다.
3. **늦은 마감.** 멈춘 장치가 살아나면 사무원 2인과 서로 다른 조직 참관인 2인의 입회 아래 저널에서 미결 배치와 마감을 닫는다.
4. **미증명 기록.** 기록 서명은 유효하나 배치에 포함되지 않은 기록은 `UNATTESTED`로 공개하고, 집계 범위에서 사유를 밝혀 제외하며, 감사에서 종이와 대조한다. 집계 범위는 늦은 마감 기한 이후 확정한다.
5. **비상 투입.** 스캐너와 예비 장치가 모두 없으면 사무원 2인·참관인 2인이 선언한 뒤 봉인된 비상 투입구로 기록 없이 받고 마감의 `no_record_count`로 센다.
6. 헌법의 "둘 다 검증" 규칙은 배치 단위 하이브리드 서명에 적용되며, 기록 단위 고전 서명은 그 위에 추가되는 것이다.

## 결과

- 닫힌 배치의 기록을 위조하려면 서명된 root를 위조하거나 SHA3-512 충돌을 찾아야 하므로, 기록마다 서명할 때와 같은 가정으로 환원된다.
- 창에서 잃을 수 있는 것은 장치당 최대 64건의 양자내성 증명뿐이다. 고전 공격자는 기록 서명 때문에 창을 이용할 수 없고, 양자 공격자가 15분 안에 개입해도 배치에 포함되지 않은 위조 기록은 검증기가 거부한다. 표, 비밀, 법적 결과는 영향을 받지 않는다.
- 모듈이 배치 서명 전에 카운터 연속성을 검사하므로 난수 버리기 공격은 서명 자체로 거부된다. 기록마다 서명할 때보다 강하다.
- 표당 크기는 약 3KB, 전국 약 130GB다. 공개 검증의 서명 검증 수는 64분의 1로 준다.
- FIPS 206(FN-DSA) 확정 후 서명이 약 1.3KB가 되면 기록마다 양자내성 서명을 붙이는 선택을 다시 검토한다.

## 기각한 대안

- 기록마다 하이브리드 서명: 약 930GB, 검증 비용 64배.
- 배치 서명만 두고 기록 서명을 생략: 고전 공격자에게도 15분 창이 열린다.
- 배치 크기 축소(16건): 비용 4배에 창은 4분의 1로만 줄어 비례 효과가 없다.
