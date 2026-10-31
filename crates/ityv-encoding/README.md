# ityv-encoding

> English summary: The canonical fixed-width binary encoding for every object ityv hashes or signs, implemented as a `no_std`, allocation-free, `unsafe`-free, panic-free Rust crate with no dependencies. It implements `docs/spec/ENCODING.md` exactly, ships published test vectors, and is the exemplar for the verification ladder: V1 (property tests, mutation testing) and V2 (Kani harnesses) are in the tree and run in CI.

## 무엇인가

ityv가 해시하거나 서명하는 모든 객체의 유일한 바이트 표현을 만든다. `docs/spec/ENCODING.md`가 명세이고 이 크레이트는 그 구현이다. 둘이 다르면 명세가 우선하고 크레이트가 결함이다.

보장하는 것:
- 같은 값은 항상 같은 바이트열. 디코딩 후 재인코딩하면 원래 바이트열과 같다.
- 정규 형식이 아닌 입력은 첫 위반 오프셋에서 거부된다. 자동 정규화나 기본값 채우기가 없다.
- `no_std`, 힙 없음, `unsafe` 없음, 패닉 없음, 의존성 없음. 재귀 없음.

보장하지 않는 것:
- 객체 내용의 진실성, 서명의 유효성, 스칼라·점의 대수적 유효성. 이 크레이트는 길이만 검사한다.

## API

```rust
use ityv_encoding::{
    ElectionId, Hash512, LedgerFrame, SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, SchemaId, Seq,
    decode_object, encode_object,
};

let frame = LedgerFrame::new(
    ElectionId::new(b"KR-2030-PRES").ok_or("bad id")?,
    Seq::new(1).ok_or("seq must be >= 1")?,
    Hash512::ZERO,
    SchemaId::new(0x0005),
    Hash512([0xaa; 64]),
);
let mut buf = [0u8; 256];
let len = encode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut buf)?;
let decoded: LedgerFrame<'_> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &buf[..len])?;
assert_eq!(decoded, frame);
# Ok::<(), Box<dyn core::error::Error>>(())
```

- `Writer`, `Reader`: 호출자 버퍼 위의 경계 검사 인코더·디코더.
- `Encode`, `Decode`: 모든 객체가 구현하는 트레이트.
- `encode_object`, `decode_object`: 16바이트 헤더를 포함한 최상위 진입점.
- 기본형 newtype: `Hash512`, `Scalar32`, `Point32`, `Token192`, `Ident`, `ElectionId`, `LedgerId`, `KeysetId`, `SchemaId`, `Seq`(1 이상), `TreeSize`, `TimeBucket`, `Day`.
- 예시 스키마: `LedgerFrame`(0x0001), `LegalAuthorizationBody`(0x0003)와 `Scope`/`ScopeSet`, `CheckpointBody`(0x0004)와 `CheckpointParts`.

모든 생성자는 파싱한다. `Seq::new(0)`은 `None`이고, `CheckpointBody::new`는 "첫 체크포인트일 때만 이전 해시가 0"이라는 불변식이 깨지면 `None`이다. 잘못된 객체는 타입으로 존재할 수 없다.

## 검증

```bash
cargo test --locked -p ityv-encoding                  # V1: 단위·속성·골든 벡터 테스트
ITYV_UPDATE_VECTORS=1 cargo test --locked -p ityv-encoding --test vectors   # 벡터 재생성
cargo kani -p ityv-encoding                           # V2: Kani 하네스 12개
cargo mutants -p ityv-encoding                        # V1: 변이 테스트
```

속성 테스트는 모든 스키마에 대해 왕복, 모든 단일 바이트 변이가 거부되거나 다른 값으로 디코딩되고 그 재인코딩이 변이 바이트열과 같음(정규성), 모든 진접두사의 거부를 검사한다. Kani 하네스는 정수 왕복, 불리언·존재 태그 엄격성, 식별자 알파벳의 정확성, 헤더 거부, 임의 입력에 대한 리더·라이터의 무패닉, `LedgerFrame` 왕복을 유계 모델 검사로 증명한다.

`vectors/*.txt`는 공개 시험 벡터다. 독립 2차 구현(V5)은 이 파일로 차분 테스트를 한다. 형식은 파일 머리의 주석에 있다.

## 테스트 코드의 lint 완화

`tests/` 아래 통합 테스트 크레이트는 TCB 밖이다. 각 파일 머리에 사유를 적고 `unwrap`, `expect`, `panic`, 인덱싱, 산술 부작용 lint만 완화한다. TCB 크레이트(`src/`)에는 어떤 완화도 없다.
