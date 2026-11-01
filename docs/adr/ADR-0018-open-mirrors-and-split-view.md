# ADR-0018: 공개 미러, 체크포인트 교환, 분기 증거

> English summary: Anyone may mirror and monitor the public board without permission, as with Certificate Transparency log monitors. The operator must publish public-grade data to everyone on equal terms with no registration and no reuse restrictions; mirrors verify before republishing and are untrusted (they can only withhold, never forge); mirrors, verifiers and voter apps exchange signed checkpoints, and two conflicting witness-signed checkpoints (or a failed consistency proof) are self-contained split-view evidence filed as dispute type 7 SPLIT_VIEW, which puts the board after the fork point in HOLD_REVIEW; voter apps show LOG_CONSISTENT only after cross-checking the checkpoint against two independently operated mirrors or the published checkpoint fingerprint. Mirrors may keep copies forever because the board is perfectly hiding.

- 상태: 채택
- 날짜: 2026-11-01
- 관련: ADR-0001, ADR-0003, ADR-0004, ADR-0012, ADR-0016; `docs/spec/PROTOCOL.md` §5.4–§5.7, §13, §14; `docs/spec/FAILURE_CASES.md` §8; `docs/usecases/USE_CASES.md` 시나리오 S; VC-064..066

## 맥락

장부 운영자(선관위)는 신뢰하지 않는다(ADR-0004). 증인 정족수(§5.4)는 같은 순번에 두 본문을 서명하지 않음으로써 운영자의 분기를 막지만, 증인은 정해진 소수 기관이고 그들이 공모하거나 운영자가 사람마다 다른 공개원장을 보여 주는 경우(split view)를 찾아내는 쪽은 정해져 있지 않았다. 인증서 투명성은 같은 문제를 "누구나 로그를 복제하고, 본 것을 서로 비교한다"로 푼다. 공개원장은 무조건적으로 숨기는 값만 담으므로 누구에게 복제를 허용해도 비밀에 비용이 없다.

## 결정

1. 공개원장 `public` 자료는 가입·인증·식별 없이 누구나 같은 조건으로 받는다. 요청자별 차등 응답과 차단을 금지하고, 보관·재공표에 이용 제한을 두지 않는다(VC-064).
2. 미러는 허가 없이 누구나 운영한다. 검증한 사본만 재공표하며 신뢰 대상이 아니다.
3. 미러·검증자·유권자 앱은 서명된 체크포인트를 교환한다. 같은 seq 다른 본문, 같은 크기 다른 root, 일관성 증명 실패는 분기 증거이며 `DisputeEvent` 유형 7 `SPLIT_VIEW`로 누구나 접수한다. 분기 지점 이후는 `HOLD_REVIEW`다(VC-065).
4. 유권자 앱은 운영 주체가 다른 미러 2곳 또는 공표 지문과 대조한 뒤에만 `LOG_CONSISTENT`를 표시한다(VC-066).
5. 선관위와 위원회는 투표 종료·개표 종료·최종 체크포인트 때 체크포인트 지문(해시 앞 20바이트, Base32 32자)을 관보·방송·신문에 공표한다.
6. 미러 보관에는 기한이 없고 파기 절차(§15)의 대상이 아니다.

## 결과

- 운영자가 분기하거나 공표한 기록을 고치려면 모든 미러와 모든 유권자 앱의 시야를 동시에 속여야 한다. 미러가 하나라도 정직하면 서명된 증거가 남는다.
- 공식 게시처가 멈추거나 일부를 숨겨도 미러가 복원한다. 숨김 자체는 `PublicationBreach`로 기록된다.
- 증인 이중 서명은 교환된 체크포인트에서 자동으로 드러나며 그 서명이 곧 벌칙의 증거다.
- 비용: 공식 게시처의 전송량이 늘어난다. 증분 내려받기와 미러 간 재배포로 완화한다.
- 남는 위험: 모든 미러가 같은 운영자에게만 받는 초기 상태, 유권자 앱 자체의 위조. 앱은 공개 소스·재현 빌드(개정안 11)와 지문 대조로 견제한다.

## 기각한 대안

- **지정 미러만 허용**: 지정 기관이 공모하면 분기를 찾을 사람이 없다. 인증서 투명성의 교훈과 반대다.
- **미러 등록제**: 등록 정보가 차단·차등 응답의 수단이 된다.
- **블록체인 공개 원장**: 합의 비용과 운영 복잡성만 늘고, 분기 탐지는 서명된 체크포인트 교환으로 충분하다(ADR-0016).

## 연결되는 검증

- VC-064 공표 조건, VC-065 분기 증거와 `HOLD_REVIEW`, VC-066 유권자 앱 2곳 대조.
- `docs/models/LedgerWitness.tla`의 분기 불가 성질(증인 정직 가정)에 더해, 증인 공모 시 분기가 교환에서 탐지됨을 M7에서 모델링한다.
- M5 `ityv-verify` 미러 모드의 차분 테스트: 분기 체크포인트 쌍, 고친 프레임, 동결 사본을 입력으로 분기 증거가 생성되는지 확인한다.
