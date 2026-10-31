# 형식 모델 / Formal Models

> English summary: TLA+ models for the verification ladder's V4 level. `LedgerWitness.tla` is the safety model of the ledger checkpoint and witness quorum protocol: an untrusted operator may propose forking checkpoint bodies, honest witnesses only sign chain extensions and never two bodies at one sequence number, Byzantine witnesses sign everything. TLC checks Agreement (no two published bodies at one sequence), Linear (published history never forks) and OneHeadPerSeq under 2·Quorum − N > Byzantine. Tamarin models for secrecy and receipt-freeness are planned.

## 모델 목록

| 파일 | 대상 | 검사 속성 | 상태 |
|---|---|---|---|
| `LedgerWitness.tla`, `.cfg` | PROTOCOL §5.4 체크포인트·증인 정족수 | `Agreement`, `Linear`, `OneHeadPerSeq`, `TypeOK` | CI의 `models` 워크플로가 TLC로 검사한다. 결과 로그는 워크플로 아티팩트 `tlc-ledgerwitness-log` |

## 실행

```bash
java -XX:+UseParallelGC -jar tla2tools.jar -config LedgerWitness.cfg LedgerWitness.tla
```

`tla2tools.jar`는 https://github.com/tlaplus/tlaplus/releases 의 공식 배포본 v1.8.0을 쓰며, `.github/workflows/models.yml`이 SHA-256으로 고정해 내려받아 실행한다. 모델 검사는 CI에서 수행되고 로컬 실행은 선택이다. 모델 상수는 `.cfg`에 있다. 증인 13, 정족수 9, 비잔틴 4의 실제 프로필은 상태 공간이 커서 TLC로 전수 검사하지 않으며, 모델의 가정 `2·Quorum − N > Byzantine`가 그 프로필에서도 성립함(18 − 13 = 5 > 4)을 `ASSUME`으로 고정한다. 더 큰 인스턴스는 Apalache의 유계 검사로 다룬다.

## 실행 기록

| 날짜 | 모델 | 인스턴스 | 결과 |
|---|---|---|---|
| 2026-10-31 | `LedgerWitness` | 증인 4, 정족수 3, 비잔틴 1, 이벤트 2종, 로그 길이 ≤ 2, 체크포인트 ≤ 3 | 오류 없음. 생성 상태 517,441, 서로 다른 상태 175,616, 탐색 깊이 10, 30초. CI 실행 41154609741 |

## 모델이 다루지 않는 것

서명 위조, 이벤트 내용의 진실성, 투표함 마감·분쟁 root, 외부 핀, 가용성(liveness). 이들은 암호 크레이트의 검증과 P0 게이트가 다룬다.
