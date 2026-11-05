// The verification console's vocabulary: the status ladder, what each
// status does not mean, the verifier's stages and the hold reasons in
// Korean. The status and holds themselves always come from the WASM
// verifier; this module only names them.

/** The ladder, lowest first (PROTOCOL §14). `HOLD_REVIEW` is beside it,
 * `LEGAL_CERTIFIED` is never reached by a machine (VC-049). */
export const LADDER = [
  {
    word: "UNVERIFIED",
    means: "검증을 시작하지 않았거나, 체크포인트·앵커가 아직 장부를 덮지 않았다.",
    not: "장부가 틀렸다는 뜻이 아니다. 아직 아무것도 확인되지 않았다는 뜻이다.",
  },
  {
    word: "LOG_CONSISTENT",
    means: "genesis, 체크포인트 사슬, 프레임과 이벤트, 투표함 불변식, 투함 기록이 통과하고 앵커가 충족되었다.",
    not: "모든 투표함이 마감되었거나, 집계가 맞거나, 종이와 대조되었다는 뜻이 아니다.",
  },
  {
    word: "SOURCE_COMPLETENESS_CHECKED",
    means: "그 위에 genesis의 모든 예상 투표함이 마감되었다.",
    not: "참여 장부나 집계가 확인되었다는 뜻이 아니다.",
  },
  {
    word: "CRYPTO_TALLY_VERIFIED",
    means: "그 위에 참여 장부와 모든 단위의 집계(범위, 합계 열기, 종이 보고 대조)가 통과했다.",
    not: "종이 표본 감사가 끝났다는 뜻도, 법적으로 확정되었다는 뜻도 아니다.",
  },
  {
    word: "PAPER_AUDITED",
    means: "그 위에 투표양식마다 표본 감사(동결, 약정, 시드, 표본, 종이 대조, 확대, 수검표)가 끝났다는 것을 검증기가 장부와 호출자가 본 비콘 공표에서 계산했다.",
    not: "법적 확정이 아니다. 선언된 표본 크기와 상한이 위험 한도 공식에서 나온 값인지, 비콘 값과 주사위 기록이 사실인지, 감사인의 판정이 옳은지는 검증 범위 밖이다(ADR-0036 한계).",
  },
] as const;

export const HOLD_WORD = "HOLD_REVIEW";
export const LEGAL_WORD = "LEGAL_CERTIFIED";

export const HOLD_MEANS =
  "어떤 단계가 실패했거나, 보류 사유가 하나라도 있다. 사람이 원인을 확인해야 한다는 뜻이며 그 자체로 부정의 증거는 아니다.";
export const LEGAL_MEANS =
  "기계가 판정하는 상태가 아니다(VC-049). 이 콘솔은 분쟁에 붙은 법적 결정 참조(LegalDecisionRef)의 건수만 보이며 그 내용은 보이지도 확인하지도 않는다.";

/** What no bundle reaches, and what PAPER_AUDITED needs, said on every
 * ladder. */
export const NOT_REACHABLE =
  "LEGAL_CERTIFIED: 기계가 닿는 상태가 아니다(VC-049). PAPER_AUDITED에는 감사까지 실린 장부와 호출자가 본 비콘 공표가 함께 있어야 닿는다. 이 콘솔이 넘기는 비콘 관찰은 시뮬레이터가 만든 시연용 고정 자료다.";

/** The verifier's steps as `verify_ledger` hands them to the status rule. */
export const STEPS: Record<string, string> = {
  Genesis: "1. genesis (핀·서명·집합)",
  Checkpoints: "2. 체크포인트 사슬",
  Frames: "3. 프레임과 이벤트",
  BoxInvariants: "4. 투표함 불변식",
  BoxCompleteness: "4. 투표함 완전성 (모두 마감)",
  Records: "5. 투함 기록",
  Participation: "6. 참여 장부",
  Tally: "7. 집계",
  Audit: "8. 감사 (표본 대조)",
  Connectivity: "11. 연결 (아직 구현 안 됨)",
  Software: "12. 소프트웨어 (아직 구현 안 됨)",
};

export const OUTCOMES: Record<string, string> = {
  PASSED: "통과",
  FAILED: "실패",
  NOT_RUN: "실행 안 됨",
};

export const STAGES: Record<string, string> = {
  frames: "프레임 색인",
  checkpoints: "체크포인트",
  authority: "법적 승인",
  boxes: "투표함",
  records: "투함 기록",
  progress: "진행 기록",
  participation: "참여 장부",
  tally: "집계",
  disputes: "분쟁",
  audit: "감사",
  timestamps: "시점확인",
  roll: "선거인명부",
};

/** The two kinds of timestamp authority (ADR-0039). */
export const TSA_KINDS: Record<string, string> = {
  Government: "정부 운영",
  NonGovernment: "정부 밖",
};

/** Roll amendment reasons (ityv-encoding `RollAmendmentReason`). */
export const ROLL_REASONS: Record<string, string> = {
  ObjectionDecision: "이의신청 결정",
  AppealDecision: "불복 결정",
  Death: "사망",
  Disqualification: "선거권 제한",
  Overseas: "재외선거인·국적 상실",
};

/** The audit events (ityv-verify `AuditEvent`). */
export const AUDIT_EVENTS: Record<string, string> = {
  Freeze: "동결",
  Commit: "약정",
  Seed: "시드",
  Opening: "열기 흔적",
  Comparison: "대조",
  Finding: "발견",
  HandCount: "수검표",
};

/** Why the audit stage refused an event (ityv-verify `AuditRefusal`). */
export const AUDIT_REFUSALS: Record<string, string> = {
  Signature: "서명이 맞지 않거나 등록된 역할·조직이 아니다",
  Capability: "법적 승인에 그 날의 권한(RLA, OBSERVER_ACCESS)이 없다",
  Subject: "감사에 없는 대상(투표양식, 단위, 기록, 장치)",
  Premature: "너무 이르다(앞서야 할 이벤트가 아직 없다)",
  Checkpoint: "고정 체크포인트(약정을 덮는 첫 체크포인트)가 아니다",
  Beacon: "비콘 지정·회차가 다르거나, 관찰한 비콘 값과 다르다",
  Late: "늦다: 비콘 값을 알 수 있게 된 뒤에 입력이 고정되었다",
  Backdated: "고정 체크포인트가 그것이 덮는 약정보다 이르다",
  Unstamped: "고정 체크포인트에 시드 앞 프레임의, 공표 구간보다 앞선 시점확인 토큰이 정부 운영과 정부 밖 두 운영 주체에서 없다(ADR-0039 8항)",
  Rule: "상한이 표본 크기 이상인 라운드(모든 표본이 통과한다)",
  Election: "다른 선거",
  Commit: "약정과 다른 주사위 기록",
  Freezes: "동결 root가 받아들인 동결과 다르다",
  Recompute: "다시 계산한 시드와 다르다",
  NotCalled: "감사가 부르지 않은 기록의 열기(선택을 드러낸다)",
  Opening: "받아들인 열기가 아닌 열기를 적었다",
  Repeated: "이미 받은 본문의 반복",
  Conflict: "같은 대상에 다른 본문(충돌)",
};

/** The comparison reason codes 0–6 (PROTOCOL §12.3). */
export const COMPARISON_CODES: string[] = [
  "0 일치",
  "1 다른 후보",
  "2 후보 → 종이는 무효",
  "3 판독 불가 → 종이는 유효",
  "4 공백 → 종이는 유효",
  "5 투표지 없음",
  "6 각인 불일치",
];

/** The phase of a style's audit (ityv-state `AuditPhase`). */
export const PHASES: Record<string, string> = {
  Sampling: "표본 대조 중",
  Concluded: "종료",
  HandCount: "수검표",
};

/** Hold reasons by code (ityv-state `HoldReason`), with a Korean
 * explanation of what the verifier found. */
export const HOLDS: Record<number, { name: string; ko: string }> = {
  0: { name: "PaperRecordMismatch", ko: "투표소 투표함의 종이 수가 기록 수와 기록 없는 투표지 수의 합과 다르다." },
  1: { name: "AttestedMismatch", ko: "배치가 증명한 기록 수가 기록 수보다 많거나, 열린 배치가 없는데 다르다." },
  2: { name: "SpoilEnvelopeMismatch", ko: "검증 폐기·격리 봉투 수가 검증 폐기와 격리 수의 합과 다르다." },
  3: { name: "ModuleCounterGap", ko: "모듈의 마지막 카운터가 기록·검증 폐기·격리 수의 합과 다르거나, 마감 때 모듈이 개시 때와 다르다." },
  4: { name: "OpenBatches", ko: "마감 때 아직 닫히지 않은 배치가 있다(늦은 배치 마감이 모든 기록을 증명하면 풀린다)." },
  5: { name: "VisitBounds", ko: "방문 수 ≤ 기록 수 ≤ 8 × 방문 수가 성립하지 않는다." },
  6: { name: "FallbackUndeclared", ko: "기록 없는 투표지가 있는데 비상 투입 선언(FallbackDeclared)이 없다." },
  7: { name: "ObservedCountMismatch", ko: "마감에 적힌 수가 장부에서 본 그 투표함의 기록·검증 공개·배치 수와 다르다." },
  8: { name: "ManualClose", ko: "장치 서명 없이 사람 서명만으로 마감했다(같은 수의 늦은 마감이 오면 풀린다)." },
  9: { name: "LateCloseDiffers", ko: "늦은 마감의 사람 수가 수동 마감과 다르다." },
  10: { name: "SealMismatch", ko: "개시 때 봉인 번호가 맞지 않았다." },
  11: { name: "OpeningNonZero", ko: "개시 때 투표함이 비어 있지 않았다." },
  12: { name: "AbsenteePaperNonZero", ko: "관외 투표함의 종이 수가 0이 아니다." },
  13: { name: "StickerVisitMismatch", ko: "관외 투표함의 스티커 수가 방문 수와 다르다(투표소 투표함은 0이어야 한다)." },
  14: { name: "EnvelopeMismatch", ko: "관외 투표함의 봉투 수가 교부한 봉투에서 빈 봉투를 뺀 수와 다르다." },
  15: { name: "IssuanceMissing", ko: "관외 투표함을 봉투 수와 대조할 교부 수 없이 마감했다." },
  16: { name: "CustodyCountMismatch", ko: "인계 기록의 수가 마감과 다르다." },
  17: { name: "CustodySealUnexplained", ko: "인계 중 봉인 값이 봉인 변경 기록 없이 바뀌었다." },
  18: { name: "CustodyIncomplete", ko: "투표함이 인계 사슬을 다 갖추지 못한 채 개표소에 닿았다." },
  19: { name: "ImprintAudit", ko: "개표소 각인 판독에서 각인 없는 투표지나 같은 각인이 나왔다." },
  20: { name: "IssuanceMismatch", ko: "교부 등식(교부 = 기록 + 기록 없음 + 검증 폐기 + 격리 + 훼손 + 반납)이 성립하지 않는다." },
  21: { name: "ParticipationMismatch", ko: "확인 인원이 교부와 맞지 않는다." },
  22: { name: "LegalDecisionPending", ko: "법적 판정을 기다리는 기록이 있다(훼손 도착, 다른 선거구)." },
  23: { name: "StepFailed", ko: "검증 단계 하나가 실패했다." },
  24: { name: "OpenDispute", ko: "해결되지 않은 분쟁이 있다." },
  25: { name: "SplitView", ko: "분기 증거가 있다(사람마다 다른 공개원장)." },
  26: { name: "PublicationLate", ko: "공개원장이 기한(투표 마감 뒤 96구간) 안에 공표되지 않았다." },
  27: { name: "BoxUnderReview", ko: "보류 중인 투표함이 상태에 기여한다." },
  28: { name: "SealBroken", ko: "봉인 변경 기록이 봉인이 깨진 채 발견되었다고 적었다." },
  29: { name: "IssuanceStockMismatch", ko: "용지 재고 등식(받은 용지 = 교부 + 미사용 + 인쇄 손지)이 성립하지 않는다." },
  30: { name: "ProgressUnresolved", ko: "진행 경보가 해소되지 않았다: 현장 확인이 늦거나 없거나 '설명 안 됨'이었다. 마감까지 교부 번호 대조를 한다." },
  31: { name: "CarryOut", ko: "진행 경보 뒤 현장 확인이 투표지 반출을 확인했다." },
  32: { name: "ProgressStream", ko: "장치의 진행 기록이 규칙을 어겼다: 누계 감소, 빠지거나 두 번인 슬롯, 개시 전·마감 뒤 기록, 마감 수와 다른 마지막 기록." },
  33: { name: "EventReplayed", ko: "이미 실린 이벤트가 다시 실렸다. 뒤의 프레임은 무효다." },
  34: { name: "RecordAfterClose", ko: "투표함 마감 프레임 뒤에 그 투표함의 기록이 실렸다. 그 기록은 무효다." },
  35: { name: "LedgerUnchecked", ko: "받을 수 없는 프레임이 있다: 사슬 끊김, 이벤트 없음, 정규가 아님, 모르는 스키마, 다른 선거, 모르는 투표함·투표소, 핀이 아닌 genesis." },
  36: { name: "CheckpointInvalid", ko: "체크포인트가 올바른 후속이 아니거나, 다양한 증인 정족수의 서명이 아니거나, 장부와 다른 root를 적었다. 사슬이 거기서 끝난다." },
  37: { name: "CloseMissing", ko: "예상 투표함에 마감이 없거나 첫 마감이 둘 이상이다(완전성)." },
  38: { name: "BoxEventRefused", ko: "투표함 상태 기계가 이벤트를 받지 않았다: 등록된 서명자와 맞지 않는 서명, 순서 위반, 권한 없음." },
  39: { name: "AuthorizationMissing", ko: "장부에 유효한 법적 승인이 없어 권한이 필요한 단계가 진행되지 않는다." },
  40: { name: "AuthorizationInvalid", ko: "받을 수 없는 법적 승인 객체가 장부에 있다." },
  41: { name: "AmendmentMissing", ko: "검증기가 적용한 genesis 변경이 장부에 없거나 순서가 바뀌었다." },
  42: { name: "RecordRejected", ko: "투함 기록이 거부되었다: 투표양식, 정형성 증명, 기록 서명, 모듈, 같은 카운터." },
  43: { name: "BatchInvalid", ko: "배치 증명이 성립하지 않는다: 서명, 모듈, 배치 번호, 카운터 구간, 구성원 수나 root." },
  44: { name: "RecordSetMismatch", ko: "마감의 기록 집합 root가 받아들여진 기록의 root와 다르다." },
  45: { name: "DisputeRefused", ko: "받을 수 없는 분쟁 이벤트가 있다." },
  46: { name: "ChallengeRejected", ko: "검증 공개(ChallengeOpening)를 받을 수 없다." },
  47: { name: "OpeningMismatch", ko: "장치가 서명한 검증 공개가 그 기록을 재구성하지 못한다. 장치 결함이다." },
  48: { name: "ParticipationSetInvalid", ko: "참여 집합을 받을 수 없다." },
  49: { name: "DuplicatePseudonym", ko: "같은 가명이 두 번 이상 나왔다. 중복 확인 조사 대상이다." },
  50: { name: "KeyProvisioningInvalid", ko: "모듈 발급 기록이나 정당 열쇠 절차 기록을 받을 수 없다." },
  51: { name: "StationCountRefused", ko: "투표소의 교부 수나 참관인 확인 수를 받을 수 없다(서명, 역할, 조직)." },
  52: { name: "TallyScopeRefused", ko: "집계 범위를 받을 수 없다: 정족수, 권한, 대상, 너무 이름(수령 대조·마감 창), 충돌." },
  53: { name: "TallyScopeMismatch", ko: "신뢰기관의 집계 범위가 장부에서 다시 계산한 범위와 다르다." },
  54: { name: "AggregateRefused", ko: "합계 열기를 받을 수 없다: 정족수, 권한, 범위 없음, 체크포인트 전, 반복." },
  55: { name: "AggregateMismatch", ko: "합계 열기가 포함 기록 커밋먼트의 실제 합을 열지 못한다." },
  56: { name: "PaperCountRefused", ko: "종이 계수 보고를 받을 수 없다." },
  57: { name: "PaperCountMismatch", ko: "단위의 종이 수가 확인된 기계 수보다 적거나 총수가 다르다. 그 자체로 부정의 증거는 아니며 감사가 원인을 찾는다." },
  58: { name: "TallyEffectRefused", ko: "집계 효과가 있는 법적 결정을 적용할 수 없다." },
  59: { name: "ReceiptResolutionRefused", ko: "관외 수령 대조를 받을 수 없다." },
  60: { name: "LateCloseAfterScope", ko: "집계 범위가 그 투표양식을 고정한 뒤에 늦은 마감이 실렸다." },
  61: { name: "AuditFreezeRefused", ko: "감사 동결을 받을 수 없다: 서명, RLA 권한, 모르는 투표양식, 그 투표양식의 집계 범위보다 이름, 두 번째 동결, 표본을 모두 통과시키는 상한." },
  62: { name: "AuditFrameMismatch", ko: "동결의 표본 프레임(기록 수나 정렬 집합 root)이 집계 단계가 다시 계산한 포함 기록과 다르다. 그 투표양식은 표본을 뽑지 않는다." },
  63: { name: "AuditSeedRefused", ko: "감사 시드를 받을 수 없다: 서명, 권한, 약정보다 이름, 고정 체크포인트가 아님, 고정 체크포인트가 약정보다 이르거나 비콘 공표보다 3구간 넘게 앞서지 않음, 고정 체크포인트에 시드보다 앞 프레임의 공표 전 시점확인 토큰(정부 운영과 정부 밖, 두 운영 주체)이 없음, 약정과 다른 주사위 기록·회차, 다시 계산한 시드나 관찰한 비콘 값과 다름, 두 번째 시드." },
  64: { name: "SampleOpeningRefused", ko: "표본 열기 흔적을 받을 수 없다: 신뢰기관 정족수, 시드 날의 OBSERVER_ACCESS, 시드보다 이름, 감사가 부르지 않은 기록(지금 라운드의 표본도 전수 대조 장치의 기록도 아님), 같은 기록의 두 번째 열기." },
  65: { name: "SampleOpeningMismatch", ko: "열람 권한이 있는 검증기에 넘긴 제한 열기가 그 기록의 커밋먼트를 열지 못한다." },
  66: { name: "SampleComparisonRefused", ko: "표본 대조를 받을 수 없다: 감사인·참관인 서명, 앞 프레임에 그 기록의 열기 흔적이 없음, 다른 열기를 적음, 기록의 투표함이 아닌 장치, 같은 기록의 두 번째 대조." },
  67: { name: "AuditCustody", ko: "대조에서 각인된 cast id의 투표지가 없거나(코드 5) 두 장이거나 각인이 기록과 다르다(코드 6). 그 투표함의 보관을 조사한다." },
  68: { name: "AuditFindingRefused", ko: "감사 발견을 받을 수 없다: 서명, 그 투표양식의 투표함이 아닌 장치, 같은 발견의 반복." },
  69: { name: "HandCountRefused", ko: "수검표 보고를 받을 수 없다: 그 단위 위원장·참관인의 서명, 모르는 단위나 다른 후보 수, 감사가 수검표를 부르기 전, 두 번째 수검표." },
  70: { name: "AuditCommitRefused", ko: "감사 약정을 받을 수 없다: 서명, 모든 동결보다 이름, 동결과 다른 비콘 지정·회차, 받아들인 동결과 다른 동결 root, 관찰한 비콘 공표 이후의 시각, 두 번째 약정." },
  71: { name: "AuditSampleFailed", ko: "시드에서 그 투표양식의 표본을 뽑지 못했다. 일어나지 않을 일이지만 조용히 미완으로 두지 않는다." },
  72: { name: "TimestampInvalid", ko: "시점확인 기록을 받을 수 없다: genesis가 고정하지 않은 기관, 앞 프레임의 시점확인 대상(체크포인트·genesis·법적 결정·명부 동결과 영수증)이 아닌 대상, 그 기관의 어느 핀으로도 검증되지 않는 토큰, 1분보다 큰 정확도. 토큰 없는 \"응답 없음\" 기록도 기관과 대상을 확인한다." },
  73: { name: "TimestampMismatch", ko: "유효한 시점확인 토큰이 체크포인트가 증인의 시각보다 허용(1구간)을 넘게 일찍 있었다고 말한다. 증인이나 그 기관 가운데 하나가 시각을 속였다. 사슬이 그 체크포인트에서 끝난다." },
  74: { name: "RollEventRefused", ko: "선거인명부 사건을 받을 수 없다: 출처 추출(그 출처 기관, 동결 뒤), 동결(병합한 추출과 다른 출처 root, 빠진 투표구), 보관 영수증(보관 기관이 아님, 앞 프레임의 상태가 아님, 두 번째), 변경(출처 서명, 사슬)." },
  75: { name: "RollCustodyMismatch", ko: "보관 기관이 다시 계산해 서명한 값(항목 root와 수, 인원수 표, 출처 root, 명부 가명 root)이 명부 상태와 다르다. 그 영수증은 정족수에 세지 않고, 분쟁에서 보관 사본을 대조한다." },
  76: { name: "ContestedCheckinInvalid", ko: "열람 권한이 있는 검증기에 넘긴, 장부에 프레임이 있는 이의 투표 기록이 검증되지 않는다: 다른 선거의 것이거나, genesis에 없는 투표소나 유닛의 것이거나, 그 유닛과 정당마다 그 유닛의 모듈 하나가 한 서명이 아니다. 공개 검증기에는 이의 투표 기록의 프레임 수만 보인다." },
  77: { name: "ContestedLabelReused", ko: "열람 권한이 있는 검증기에 넘긴 이의 투표 기록에서 한 봉투 라벨이 서로 다른 기록 둘 이상에 쓰였다. 어느 봉투가 어느 기록인지 알 수 없으므로 그 라벨의 봉투는 모두 개표에서 빠진다. 라벨은 무작위 값이라 장치나 내부자의 잘못이다. 공개 검증기에는 이의 투표 기록의 프레임 수만 보인다." },
  78: { name: "RollIncomplete", ko: "선거인명부가 치러진 선거와 맞지 않는다. 기원의 마지막 상태에 있는 선거일 투표소에 주민 명부 발췌가 없거나(동결 뒤에 더한 투표소), 투표가 끝난 뒤(선거일 투표소의 참여 집합이 처음 공표된 뒤)에 명부 수정이 기록되었다. 선거인을 확인한 명부는 투표 마감 때의 명부이고 그 뒤의 수정은 그것을 바꾸지 못한다." },
};

/** Korean name of the alarm kinds. */
export const ALARMS: Record<string, string> = {
  Floor: "바닥 경보",
  Negative: "음수 경보",
  High: "과다 경보",
};
