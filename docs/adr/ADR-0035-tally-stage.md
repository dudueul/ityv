# ADR-0035: 집계 단계 — 수령 대조, 법적 효과, 집계 범위, 합계 열기, 종이 대조

> English summary: Step M5 2f adds the verifier's tally stage (PROTOCOL §14 item 7) and its ledger objects. The encoding gets `TallyScopeBody` (0x0043), `AggregateOpeningBody` (0x0044), `PaperCountReportBody` (0x0046) and, because no out-of-district record could otherwise ever be resolved or reach a legal decision, `ReceiptResolutionBody` (0x0047); the three trustee-quorum bodies travel in `QuorumSigned` (0x0045), whose every signature covers the quorum message `body_hash ‖ trustees`, so the participant list is signed. The district commission chair becomes a roster role (5) and an event role (9), and the reporting unit names the commission whose chair reports it; because the extended role sets turn published reject vectors into valid inputs, `WitnessedEvent`, `RosterSigner` and `ReportingUnitEntry` move to version 2 rather than changing version 1 in place. `verify_tally` recomputes, for every ballot style and reporting unit of the genesis, the included records and each exclusion's first reason and basis from the record stage, the boxes' units, test styles, receipt resolutions and legal tally effects, then takes a scope only under a qualified trustee quorum, `CRYPTO_TALLY_AID`, and readiness measured in witness time (the latest checkpoint before the scope more than 96 buckets after the last close), compares it with the recomputation, takes an opening only after a checkpoint before it covers its scope and checks it against the sum of the included records' real commitments and the digit range, and compares the opened counts with the paper count signed by the unit's commission chair. Every refused event is listed and held; a second answer to the same question is a repeat or a conflict, never silently ignored; late closes after a scope are refused. The report runs the stage, so a complete clean ledger reaches `CRYPTO_TALLY_VERIFIED`.

- 상태: 채택
- 날짜: 2026-11-03
- 관련: ADR-0012(정족수와 챔버), ADR-0019(정당 챔버), ADR-0020(보고 단위와 종이 대조), ADR-0025(상태 크레이트, 집계 관문), ADR-0028(genesis 인코딩, 버전 번호), ADR-0031(기록 단계·상태 사다리), ADR-0032(분쟁 단계); `docs/spec/PROTOCOL.md` §10.6, §11, §14 7항; `docs/spec/ENCODING.md` §8.42, §8.43, §8.50, §8.61–§8.65; `docs/ROADMAP.md` M5

## 맥락

M5 2e단계까지 검증기는 §14의 1–6항과 9항을 돌리고 `SOURCE_COMPLETENESS_CHECKED`까지 상태를 냈다. 7항(집계)에는 장부 객체도 검증 단계도 없었다. 명세(§11)는 `TallyScope`·`AggregateOpening`·`PaperCountReport`의 내용과 규칙을 말하지만 인코딩, 범위에 드는 기록, 근거 이벤트, 시간 기준, 같은 질문에 두 답이 오는 경우를 정하지 않았다. 관외 기록의 수령 대조(§10.6, `ReceiptResolution`)에는 스키마가 없어서, 관외 기록은 언제나 수령 대조 대기였고 법적 판정(VC-099)이 적용될 기록도 생길 수 없었다. 독립 검토는 2f의 첫 두 커밋에서 다섯 가지를 지적했다: 종이 보고의 위원장이 보고 단위에 묶이지 않음, 접근구조가 빠진 챔버를 1-of-1로 채움, 명세와 코드의 어긋남(버전 포함), 늦은 마감 기한을 정족수가 적은 시각으로 잼, 정족수 봉투의 참여자 목록이 서명 밖에 있음.

## 결정

1. **인코딩(ENCODING §8.61–§8.65).** 수량은 `2^26 − 1` 이하(자릿수 자리올림 없음, §7.4).
   - `TallyScopeBody`(0x0043): 선거, 투표양식, 보고 단위, 포함 수와 정렬 집합 root, `no_record_count`, 제외 목록(기록 해시 엄격 오름차순, 사유 코드 1–8이 §11.1 순서, 근거 0 아님), 시각.
   - `AggregateOpeningBody`(0x0044): 범위 본문 객체 해시, 청크, `T_j`·`R_j`·`S`, 시각.
   - `ReceiptResolutionBody`(0x0047, 명세가 내용만 말한 `ReceiptResolution`): 선거, 관외 투표함 하나, 기록별 결과(§10.6 5항의 다섯 결과). 투표함 단위로 둔 것은 검증기가 그 투표함의 투함 기록 전부를 정확히 한 번씩 다루는지 확인할 수 있기 때문이다. 기록과 맞지 않는 라벨 수(VC-060)는 수령 선관위의 것이라 이 본문에 없다.
   - `QuorumSigned`(0x0045): 세 본문 가운데 하나와 참여 구성원 서명(1–64, 오름차순). purpose는 본문마다 `tally-scope`, `aggregate-opening`, `receipt-resolution`.
   - `PaperCountReportBody`(0x0046): `WitnessedEvent` 본문, purpose `paper-count`, 위원장 1과 서로 다른 조직 참관인 2 이상.

2. **참여자 목록도 서명한다.** 각 구성원은 본문 바이트가 아니라 정족수 메시지 `body_hash ‖ trustees`(본문 객체 해시와 봉투의 구성원 목록, 최대 4,420바이트)에 서명한다. 본문만 서명하면 누구나 자격 있는 더 작은 부분집합으로 봉투를 다시 쌀 수 있고, 기여한 구성원을 목록에서 뺄 수 있다. 본문 해시를 쓰는 것은 `ityv-state`가 힙 없이(`alloc` 없음) 메시지를 만들게 하기 위해서다.

3. **위원장과 버전.** 명부 역할 5(구·시·군 선관위 위원장)와 이벤트 역할 9를 더하고, `ReportingUnitEntry`에 그 단위를 보고하는 선관위 `commission_org`를 더했다. 종이 보고는 그 조직의 명부 위원장만 서명할 수 있다(그 프레임에 시행 중인 genesis 상태의 단위와 명부). 없으면 다른 구의 위원장이 운영자와 짜고 남의 단위 보고를 먼저 올려 진짜 보고를 막을 수 있다. 위원장을 서명자 명부에 두고 단위에는 조직을 둔 것은, 위원장이 바뀌어도 단위를 고칠 필요가 없고 한 선관위가 여러 단위를 맡기 때문이다. 역할 집합이 넓어져 버전 1의 거부 벡터(`role 5`, `role 9`)가 정상 입력이 되므로 `WitnessedEvent`·`RosterSigner`·`ReportingUnitEntry`를 버전 2로 올렸다(ENCODING 머리말: 변경은 `schema_version` 증가를 수반한다, ADR-0028: 같은 번호를 다른 모양에 쓰지 않는다). 버전 1은 공개 장부에 쓰인 적이 없으므로 디코더는 현재 버전만 받는다. `schema_version`이 스키마마다 현재 버전을 주고 모든 디코더가 그것을 쓴다. 새 스키마 0x0043–0x0047은 버전 1이다.

4. **범위에 드는 기록.** 투표양식·보고 단위의 범위는 genesis 마지막 상태에서 그 투표양식과 그 단위를 가진 투표함의 기록이다(기록의 단위는 투표함의 것). 시험용 기록(`TEST-`)은 투표함의 범위에 `TEST_BALLOT`으로 든다. 그 밖의 다른 투표양식 기록은 어느 범위에도 들 수 없으므로 기록 단계가 거부한다(`RecordRefusal::Style`): 기록의 투표양식은 그 프레임까지의 상태에서 투표함의 것이거나 시험용이어야 한다.

5. **근거 이벤트.** 근거는 사유를 주는 장부 이벤트의 객체 해시(프레임이 가리키는 해시)다. `TEST_BALLOT`은 그 투함 기록, `CHALLENGED_SPOILED`는 받아들여진 첫 검증 공개, `CAST_NOT_RECEIVED`·`RECEIVED_LATE`는 수령 대조, `LEGAL_EXCLUDED`는 결정, `UNATTESTED`는 투표함의 유효 마감(마지막으로 받은 마감)이다. `UNATTESTED`에는 "일어난 사건"이 없으므로 배치 없이 투표함을 닫은 사건을 근거로 삼는다. `QUARANTINED`·`SHARE_MISSING`은 아직 장부 스키마(`ImprintFailure`, `ShareReceipt`)가 없어 기록이 이를 수 없다. 코드는 기록 자체를 근거로 둔다.

6. **수령 대조와 법적 효과.** 수령 대조는 정족수 서명, 그 날의 `CRYPTO_TALLY_AID`(수령 대조는 집계 보조의 일부다), genesis의 관외 투표함, 그 투표함의 마감 뒤, 목록이 정확히 그 투표함의 투함 기록(검증 공개된 것 빼고)일 때만 받고 투표함마다 하나다. 법적 결정은 집계 효과(1 포함, 2 제외)가 있을 때만 적용하고, 그 분쟁이 투표함과 기록을 지목한 `POSTAL` 분쟁이며, 그 기록이 앞 프레임의 수령 대조로 `RECEIVED_DAMAGED`나 `WRONG_DISTRICT`가 되어 판정을 기다리고, 아직 결정이 없을 때만이다. 둘째 결정(심급이 달라도)은 받지 않고 보류한다(사람이 가린다). 효과 없는 결정은 아무것도 하지 않는다.

7. **준비와 증인 시각.** 범위의 준비는 범위의 프레임에서 잰다: 그 투표양식의 모든 투표함(모든 단위)의 첫 마감이 앞 프레임에 있고, 투함 기록이 있는 관외 투표함마다 앞 프레임의 수령 대조가 있으며, 판정을 기다리는 그 투표양식 기록마다 앞 프레임의 결정이 있고, 증인 시각이 마지막 첫 마감 + 96보다 크다. 증인 시각은 범위보다 앞 프레임에 있는 유효 체크포인트의 가장 늦은 `time_bucket`이다(없으면 0). 검증기에는 시계가 없고, 범위의 `time_bucket`은 정족수의 주장일 뿐이다. 앞당겨 적은 범위가 늦은 배치 마감이 아직 증명할 수 있는 기록을 `UNATTESTED`로 굳히지 못하게 한다(VC-057). 범위 뒤에 수록된 그 투표양식 투표함의 늦은 배치 마감과 늦은 마감은 받지 않고 보류한다(`LateCloseAfterScope`, 60). 기한은 투표함의 첫 마감(마감 또는 수동 마감)부터 잰다(VC-100이 늦은 마감과 늦은 배치를 그 마감부터 96구간 안으로 묶는다).

8. **재계산과 대조.** 기대 포함 집합과 제외는 전체 장부의 기록 상태로 계산한다(수령 대조·결정 반영). 범위가 그보다 앞서 수록됐다면 준비가 실패하거나 대조가 어긋난다. 대조 항목: 포함 수, 포함 root, `no_record_count`(그 단위 투표함 유효 마감의 합), 제외마다 빠짐·남음·사유·근거.

9. **합계 열기.** 열기는 정족수, 그 날의 권한, 그 투표양식에 있는 청크, 그 단위에 받아들인 범위(본문 해시로), 그 범위 프레임을 덮는 체크포인트가 열기보다 앞 프레임에 있을 것(VC-063, 프레임 0은 덮을 수 없다)을 요구한다. 검증은 기록이 아니라 검증기의 재계산 포함 집합으로 한다: `C_total,j`는 포함 기록의 청크 `j` 커밋먼트 합이고, `verify_aggregate`가 등식을, 자릿수는 포함 수 이하이고 투표양식에 없는 선택지 자리에서 0이어야 한다(VC-024). 모든 청크가 열리면 선택지별 수의 합이 포함 수와 같아야 한다(명세의 "단위 합의 일관성"을 이렇게 읽었다). 등식이 틀리면 `AggregateMismatch`이고 정족수가 §11.3대로 국소화한다.

10. **종이 대조.** `D_t`·`B`·`U`는 열린 수, `F`는 범위의 `no_record_count`, `X`는 제외됐지만 종이가 그 단위 개표에 있는 기록이다: 주 상태가 투함(`UNATTESTED`, `SHARE_MISSING`, 투함된 시험용 기록) 또는 `RECEIVED`인 제외 기록. 검증 공개·격리·미수령·기한 후·법적 제외 기록의 종이는 개표되지 않는다. 종이 보고는 열기 전에도 수록될 수 있다(순서 규칙 없음). 비교는 모든 청크가 열린 뒤에 한다.

11. **같은 질문에 두 답.** 단위의 범위, 청크의 열기, 단위의 종이 보고, 투표함의 수령 대조는 처음 받은 것이 답이다. 같은 본문을 다른 서명 바이트로 다시 실으면 반복(`Repeated`), 다른 본문이면 충돌(`Conflict`)이다. 둘 다 목록에 남고 보류한다. 충돌을 조용히 "이미 있음"으로 넘기면 먼저 올린 쪽이 이긴다.

12. **접근구조.** 접근구조는 genesis 챔버 목록이 `P1…Pn, J, A, C, N`을 그 순서로 정확히 한 번씩 담을 때만 만든다(`expected_chamber`). 빠진 챔버를 1-of-1로 채우거나 두 번 나온 챔버의 뒤 값을 쓰지 않는다. genesis 본문이 이미 순서를 강제하지만, 상태 크레이트의 함수가 그 가정에 기대지 않게 했다.

13. **보류와 완전성.** 받지 못한 이벤트: 범위 `TallyScopeRefused`(52), 열기 `AggregateRefused`(54), 종이 `PaperCountRefused`(56), 효과 `TallyEffectRefused`(58), 수령 대조 `ReceiptResolutionRefused`(59, 새), 늦은 마감 `LateCloseAfterScope`(60, 새). 불일치: `TallyScopeMismatch`(53), `AggregateMismatch`(55), `PaperCountMismatch`(57). 단위를 가리키는 이벤트의 보류는 그 단위에도 건다. 아직 없는 범위·열기·종이 보고는 미완성이다. 보고서의 7단계는 모든 단위가 통과하면 통과, 아니면 실행 안 함이며 보류는 상태로 간다. 참여 장부와 집계가 모두 통과하면 `CRYPTO_TALLY_VERIFIED`다.

## 결과

- 공개 장부만으로 누구나 집계 범위를 다시 계산하고, 정족수가 연 합계가 실제 커밋먼트의 합을 여는지, 종이 결과와 맞는지 확인한다.
- 관외 기록이 수령 대조로 풀리고, 훼손·오배송 기록이 법적 판정으로만 들어온다.
- 다른 구의 위원장, 자격 없는 정족수, 참여자를 뺀 재포장, 앞당긴 시각, 늦은 배치가 집계를 바꾸지 못하고 보류로 드러난다.
- 버전 2가 된 세 스키마의 벡터를 다시 만들었다.

## 한계

- 증인 시각은 증인의 시계를 믿는다. 체크포인트 시각의 외부 앵커(ADR-0034)는 아직 구현되지 않았다.
- 위원장이 그 단위 선관위의 사람인지는 명부의 조직으로만 안다. genesis는 단위 선관위에 위원장이 있는지 확인하지 않는다(없으면 보고할 수 없어 미완성).
- 수령 선관위의 라벨 수(VC-060), 불일치 국소화 기록(§11.3, VC-044), `QUARANTINED`·`SHARE_MISSING`의 장부 사건은 아직 없다.
- 둘째 법적 결정(상급심)은 적용하지 않고 보류한다. 심급 규칙은 법령 부속서의 일이다.
- 선거구나 전국 합계(단위 합계의 합)는 검증기가 내지 않는다. 단위별 결과를 노출할 뿐이다.

## 대안

- **`WitnessedEvent`·`RosterSigner`를 버전 1 그대로 넓히기.** 공개된 거부 벡터가 뜻을 바꾸고 독립 구현이 같은 번호에서 다르게 판정한다. 기각.
- **위원장을 기존 역할 3(선관위)으로 서명하게 하기.** 중앙 선관위 키(분쟁)와 구·시·군 위원장(명부)이 한 역할을 나누어 뜻이 겹친다. 기각.
- **위원장을 단위 항목에 사람으로 두기.** 위원장 교체마다 단위 집합을 바꿔야 하고 서명자가 명부 밖에 생긴다. 기각.
- **범위의 `time_bucket`을 기한의 기준으로 쓰기.** 정족수가 스스로 적는 시각이다. 기각.
- **수령 대조를 투표양식 단위로 두기.** 한 관외 투표함에 여러 선거구 기록이 섞이므로 검증기가 기록 전부를 한 번씩 다루는지 보기 어렵다. 기각.
