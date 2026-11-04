# 형식 모델 / Formal Models

> English summary: TLA+ models for the verification ladder's V4 level. `LedgerWitness.tla` is the safety model of the ledger checkpoint and witness quorum protocol: an untrusted operator may propose forking checkpoint bodies, honest witnesses only sign chain extensions and never two bodies at one sequence number, Byzantine witnesses sign everything. TLC checks Agreement (no two published bodies at one sequence), Linear (published history never forks) and OneHeadPerSeq under 2·Quorum − N > Byzantine. Tamarin models for secrecy and receipt-freeness are planned.

## 모델 목록

| 파일 | 대상 | 검사 속성 | 상태 |
|---|---|---|---|
| `LedgerWitness.tla`, `.cfg` | PROTOCOL §5.4 체크포인트·증인 정족수, 따라잡기(`HonestAdopt`) | `Agreement`, `Linear`, `OneHeadPerSeq`, `TypeOK` | CI의 `models` 워크플로가 TLC로 검사한다. 결과 로그는 워크플로 아티팩트 `tlc-ledgerwitness-log` |

## 실행

```bash
java -XX:+UseParallelGC -jar tla2tools.jar -config LedgerWitness.cfg LedgerWitness.tla
```

`tla2tools.jar`는 https://github.com/tlaplus/tlaplus/releases 의 공식 배포본 v1.8.0을 쓰며, `.github/workflows/models.yml`이 SHA-256으로 고정해 내려받아 실행한다. 모델 검사는 CI에서 수행되고 로컬 실행은 선택이다. 모델 상수는 `.cfg`에 있다. 증인 13, 정족수 9, 비잔틴 4의 실제 프로필은 상태 공간이 커서 TLC로 전수 검사하지 않으며, 모델의 가정 `2·Quorum − N > Byzantine`가 그 프로필에서도 성립함(18 − 13 = 5 > 4)을 `ASSUME`으로 고정한다. 더 큰 인스턴스는 Apalache의 유계 검사로 다룬다.

## 실행 기록

| 날짜 | 모델 | 인스턴스 | 결과 |
|---|---|---|---|
| 2026-10-31 | `LedgerWitness` | 증인 4, 정족수 3, 비잔틴 1, 이벤트 2종, 로그 길이 ≤ 2, 체크포인트 ≤ 3 | 오류 없음. 생성 상태 517,441, 서로 다른 상태 175,616, 탐색 깊이 10, 30초. CI 실행 41154609741 |
| 2026-11-04 | `LedgerWitness`(`HonestAdopt` 추가) | 같음 | 오류 없음. 생성 상태 540,160, 서로 다른 상태 187,958, 탐색 깊이 10, 14초(로컬, CI와 같은 `-deadlock`·설정; 로컬 TLC는 v1.8.0이 아닌 2026.10.30 빌드) |

## 코드와의 대응

`HonestSign`의 전제(다음 seq, 직전 서명 본문의 접두 확장)는 `ityv-ledger`의 `WitnessMemory::may_sign`이 구현한다(ADR-0016 §4). `HonestAdopt`는 `WitnessMemory::adopt`다: 서명하거나 받아들인 것이 있는 정직한 증인이 공표된 더 뒤의 본문(자기 것의 확장)을 서명 없이 기억에 받아들인다. 기억이 비어 있지 않다는 조건이 핵심이다. 리뷰의 변형 모델(기억을 잃는 `LoseMemory`를 더하고 빈 기억에서도 받아들이게 함)은 10단계 만에 `Agreement`를 깼고, 이 조건을 더하면 성립했다. 기억을 잃거나 되감긴 증인은 모델 밖의 고장이며 `Byzantine`(코드의 f)에 센다. 그 변형은 CI에 넣지 않는다. 코드는 받아들이는 열이 해시로 이어지기도 요구하며, 모델의 접두 관계가 그것을 추상화한다. 코드에는 모델에 없는 전제가 하나 더 있다: `time_bucket`이 증인 시계의 허용 범위 안이고 직전 서명 이상이어야 한다(PROTOCOL §5.4, VC-012). 모델은 시각을 추상화한다. 이 전제는 서명을 줄이기만 하므로 `Agreement`·`Linear`에 영향이 없다. 모델의 접두 관계는 코드에서 일관성 증명 검증으로, `Quorum`은 `QuorumProfile`로 대응하며, 모델의 `ASSUME 2·Quorum − N > Byzantine`는 `QuorumProfile::new`의 유효성 조건이다.

## 모델이 다루지 않는 것

서명 위조, 이벤트 내용의 진실성, 투표함 마감·분쟁 root, 외부 핀, 가용성(liveness). 이들은 암호 크레이트의 검증과 P0 게이트가 다룬다.
