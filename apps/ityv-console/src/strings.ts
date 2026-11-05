// 고정 문구 표 (docs/ui/SCREENS.md §0.2) — the prototype screens' only
// source of on-screen text.
//
// Every entry has an id, the Korean string with typed value slots
// (`{name}`), and where it comes from: `SCREENS §n` for a string
// transcribed from the normative screen specification (its `spec`
// placeholders give back the SCREENS.md text verbatim, which `bun test`
// checks), or `prototype` for a label the specification describes but
// does not quote. The canonical table format and its `ui_strings_hash`
// (ENCODING.md §8.26) are M8 work; this module is a development stand-in.

/** The value kinds a slot may hold (SCREENS §0.2: integers, identifiers
 * such as a box ID, fingerprints, status vocabulary), plus `ref`: another
 * entry of this table without slots (a state word or a device name), so
 * even a nested value comes from the table. */
export const SLOT_KINDS = {
  count: "정수",
  sheet: "정수",
  minutes: "정수",
  percent: "정수",
  build: "정수",
  slotTime: "정수",
  identifier: "식별자",
  trackingCode: "식별자",
  semver: "식별자",
  errorCode: "식별자",
  fingerprint16: "지문",
  fingerprint32: "지문",
  status: "상태 어휘",
  ref: "문구 표 항목",
} as const;

export type SlotKind = keyof typeof SLOT_KINDS;

export interface StringEntry {
  /** The Korean string; `{name}` marks a value slot. */
  ko: string;
  /** Kind of each slot. */
  slots?: Record<string, SlotKind>;
  /** Where the text comes from. */
  source: string;
  /** SCREENS.md's placeholder for each slot: filling the slots with these
   * gives back the SCREENS.md text verbatim. */
  spec?: Record<string, string>;
}

const S1 = "SCREENS §1";
const S2 = "SCREENS §2";
const S3 = "SCREENS §3";
const S4 = "SCREENS §4";
const S5 = "SCREENS §5";
const S61 = "SCREENS §6.1";
const S62 = "SCREENS §6.2";
const S7 = "SCREENS §7";
const S01 = "SCREENS §0.1";
const P = "prototype";

export const STRINGS = {
  // §0.1 identity line and detail view (every screen).
  "id.line": {
    ko: "{program} {version} · 빌드 {build} · {fp}",
    slots: { program: "ref", version: "semver", build: "build", fp: "fingerprint16" },
    source: S01,
    spec: { program: "ityv 사전투표 스캐너", version: "1.4.2", build: "2071", fp: "K7QF 2M8D R5WN Q3XA" },
  },
  "id.check": { ko: "소프트웨어 확인", source: S01 },
  "id.attest": { ko: "현장 증명을 하려면 참관인 토큰을 대거나 확인 카드를 넣으세요.", source: S01 },
  "id.detail.title": { ko: "소프트웨어 확인", source: S01 },
  "id.detail.component": {
    ko: "{name} {version} · 빌드 {build}",
    slots: { name: "ref", version: "semver", build: "build" },
    source: P,
  },
  "id.detail.fp": { ko: "{fp}", slots: { fp: "fingerprint32" }, source: P },
  "id.detail.module": {
    ko: "모듈 {module} · 빌드 {build}",
    slots: { module: "identifier", build: "build" },
    source: P,
  },
  "id.detail.boots": { ko: "부팅 횟수 {count}", slots: { count: "count" }, source: P },
  "id.detail.close": { ko: "닫기", source: P },

  // §1 scanner: voter screen.
  "voter.idle": { ko: "투표지를 봉투째 투입구에 넣어 주세요.", source: S1 },
  "voter.reading": {
    ko: "읽는 중이에요. 투표지 {count}장",
    slots: { count: "count" },
    source: S1,
    spec: { count: "N" },
  },
  "voter.decide": {
    ko: "투표지 {count}장을 읽고 잠갔어요.",
    slots: { count: "count" },
    source: S1,
    spec: { count: "N" },
  },
  "voter.cell": { ko: "{sheet}", slots: { sheet: "sheet" }, source: S1 },
  "voter.btn.castAll": { ko: "모두 넣기", source: S1 },
  "voter.btn.choose": { ko: "확인할 장 고르기", source: S1 },
  "voter.choose": { ko: "확인할 장을 고르세요. 확인한 장은 버리고 새로 찍어요.", source: S1 },
  "voter.btn.challenge": { ko: "고른 장 확인하기", source: S1 },
  "voter.btn.back": { ko: "돌아가기", source: S1 },
  "voter.challenged": {
    ko: "고른 {count}장을 열어 인쇄했어요. 인쇄물을 보시고, 확인한 투표지는 새로 받아 찍어 주세요.",
    slots: { count: "count" },
    source: S1,
    spec: { count: "N" },
  },
  "voter.cast": {
    ko: "투표지 {count}장이 투표함에 들어갔어요. 전자 기록은 아직 공개 검증 전이에요({status}).",
    slots: { count: "count", status: "status" },
    source: S1,
    spec: { count: "N", status: "UNVERIFIED" },
  },
  "voter.slip": { ko: "확인 번호 쪽지를 가져가세요. 이 번호로는 누구를 찍었는지 알 수 없어요.", source: S1 },
  "voter.overlap": { ko: "투표지가 겹쳤어요. 돌려드린 투표지를 다시 넣어 주세요.", source: S1 },
  "voter.failed": { ko: "이번 투표지는 처리하지 못했어요. 사무원을 불러 주세요.", source: S1 },
  "voter.fallback": {
    ko: "지금은 스캐너를 쓸 수 없어요. 사무원 안내에 따라 비상 투입구를 써 주세요.",
    source: S1,
  },
  "voter.card": { ko: "확인 카드를 읽었어요. 카드를 가져가세요.", source: S1 },

  // §2 scanner: clerk and observer screen.
  "clerk.box": { ko: "투표함", source: S2 },
  "clerk.box.notOpened": { ko: "개시 전", source: S2 },
  "clerk.box.voting": { ko: "투표 중", source: S2 },
  "clerk.box.fallback": { ko: "비상 투입 중", source: S2 },
  "clerk.box.closing": { ko: "마감 중", source: S2 },
  "clerk.box.closed": { ko: "마감됨", source: S2 },
  "clerk.counts": { ko: "수", source: S2 },
  "clerk.records": { ko: "기록 수", source: S2 },
  "clerk.challenged": { ko: "확인(검증 폐기) 수", source: S2 },
  "clerk.quarantined": { ko: "격리 수", source: S2 },
  "clerk.visits": { ko: "방문 수", source: S2 },
  "clerk.stickers": { ko: "스티커 수", source: S2 },
  "clerk.batch": { ko: "배치", source: S2 },
  "clerk.batch.fill": {
    ko: "{x}/64",
    slots: { x: "count" },
    source: S2,
    spec: { x: "x" },
  },
  "clerk.batch.closed": { ko: "닫힌 배치 {count}", slots: { count: "count" }, source: P },
  "clerk.attest": { ko: "참관 서명", source: S2 },
  "clerk.attest.left": {
    ko: "남은 기록 {count}건 · 남은 시간 {minutes}분",
    slots: { count: "count", minutes: "minutes" },
    source: P,
  },
  "clerk.journal": { ko: "저널", source: S2 },
  "clerk.journal.ok": { ko: "마지막 항목 영속화 확인", source: P },
  "clerk.journal.error": { ko: "오류 {code}", slots: { code: "errorCode" }, source: P },
  "clerk.send": { ko: "송신", source: S2 },
  "clerk.send.slot": {
    ko: "슬롯 {slot} · 남은 시간 {minutes}분",
    slots: { slot: "count", minutes: "minutes" },
    source: P,
  },
  "clerk.send.frames": {
    ko: "이번 세션 프레임 {count}(빈 프레임 포함)",
    slots: { count: "count" },
    source: P,
  },
  "clerk.send.backlog": { ko: "밀린 닫힌 배치 {count}", slots: { count: "count" }, source: P },
  "clerk.modules": { ko: "챔버 모듈", source: S2 },
  "clerk.module.row": {
    ko: "{chamber} {state} · 패드 {percent}%",
    slots: { chamber: "identifier", state: "ref", percent: "percent" },
    source: P,
  },
  "clerk.module.present": { ko: "있음", source: S2 },
  "clerk.module.absent": { ko: "없음", source: S2 },
  "clerk.module.error": { ko: "오류", source: S2 },
  "clerk.attestation": { ko: "현장 증명", source: S2 },
  "clerk.attestation.last": {
    ko: "마지막 증명 {from}–{to} 칸 · 참관인 {observer}",
    slots: { from: "slotTime", to: "slotTime", observer: "identifier" },
    source: P,
  },
  "clerk.attestation.opening": { ko: "개시 증명 있음", source: P },

  // §3 check-in device: clerk screen.
  "checkin.checking": { ko: "신분 확인 중", source: S3 },
  "checkin.done": {
    ko: "확인 완료 · 이 투표소 누적 {count}명",
    slots: { count: "count" },
    source: S3,
    spec: { count: "N" },
  },
  "checkin.roll.ok": { ko: "명부 연결됨", source: S3 },
  "checkin.roll.lost": { ko: "명부 연결이 끊겨 투표지를 줄 수 없어요", source: S3 },
  "checkin.cosign.wait": {
    ko: "참관인 공동 서명 대기 {count}건",
    slots: { count: "count" },
    source: S3,
    spec: { count: "N" },
  },
  "checkin.cosign.done": {
    ko: "참관인 공동 서명 완료 · 누적 {count}명",
    slots: { count: "count" },
    source: S3,
    spec: { count: "N" },
  },
  "checkin.swap": { ko: "예비 유닛으로 바꾸는 중 · 순번과 진행 누계 이어받기 확인 필요", source: S3 },
  "checkin.issue": {
    ko: "교부 {count}장",
    slots: { count: "count" },
    source: S3,
    spec: { count: "7" },
  },
  "checkin.spoiled": {
    ko: "훼손 회수 {count}장 · 다시 교부하세요",
    slots: { count: "count" },
    source: S3,
    spec: { count: "1" },
  },
  "checkin.returned": {
    ko: "반납 {count}장 받음",
    slots: { count: "count" },
    source: S3,
    spec: { count: "1" },
  },

  // §4 counting-centre sorter extension.
  "sorter.box": { ko: "투표함 {box} · 투표양식 {style}", slots: { box: "identifier", style: "identifier" }, source: P },
  "sorter.paper": { ko: "종이 수", source: S4 },
  "sorter.pocket": { ko: "칸 {sheet}", slots: { sheet: "sheet" }, source: P },
  "sorter.unsorted": { ko: "미분류(사람 판정 대기)", source: S4 },
  "sorter.total": { ko: "합계", source: S4 },
  "sorter.equation": { ko: "종이 수 = 기록 수 + 비상 투입 수", source: S4 },
  "sorter.equation.values": {
    ko: "{paper} = {records} + {fallback} · 차이 {diff}",
    slots: { paper: "count", records: "count", fallback: "count", diff: "count" },
    source: P,
  },
  "sorter.imprint.none": { ko: "각인 없는 투표지 {count}", slots: { count: "count" }, source: P },
  "sorter.imprint.twice": { ko: "같은 각인이 두 번 나온 수 {count}", slots: { count: "count" }, source: P },
  "sorter.hold": {
    ko: "이 투표함은 {status}로 기록됩니다",
    slots: { status: "status" },
    source: S4,
    spec: { status: "HOLD_REVIEW" },
  },

  // §5 station gateway.
  "gw.session": {
    ko: "세션 {session} · 슬롯 {slot} · 남은 시간 {minutes}분",
    slots: { session: "count", slot: "count", minutes: "minutes" },
    source: P,
  },
  "gw.frames": {
    ko: "{link} · 이번 세션 {count}(빈 프레임 포함) · 이번 슬롯 {slotCount}",
    slots: { link: "ref", count: "count", slotCount: "count" },
    source: P,
  },
  "gw.inbound": { ko: "들어오는 경로", source: S5 },
  "gw.inbound.none": { ko: "없음", source: S5 },
  "gw.taps": { ko: "관찰 탭", source: S5 },
  "gw.tap": { ko: "{tap} {state}", slots: { tap: "ref", state: "ref" }, source: P },
  "gw.tap.device": { ko: "장치 쪽 탭", source: P },
  "gw.tap.line": { ko: "회선 쪽 탭", source: P },
  "gw.link.scanner": { ko: "스캐너", source: P },
  "gw.tap.inUse": { ko: "사용 중", source: P },
  "gw.tap.idle": { ko: "쉬는 중", source: P },
  "gw.chain": { ko: "사슬", source: S5 },
  "gw.chain.head": { ko: "{link} {head}", slots: { link: "ref", head: "fingerprint16" }, source: P },
  "gw.line": { ko: "회선", source: S5 },
  "gw.line.up": { ko: "바깥 회선 연결됨", source: P },
  "gw.line.down": { ko: "바깥 회선 끊김", source: P },

  // §6.1 observer app: attestation result.
  "obs.att.device": { ko: "장치 {device} · {kind}", slots: { device: "identifier", kind: "ref" }, source: P },
  "dev.kind.scanner": { ko: "투함 스캐너", source: P },
  "dev.kind.unit": { ko: "카운터·가명 유닛", source: P },
  // Program and component names of the prototypes' identity lines (a
  // release manifest would name them; here they are fixed table text).
  "dev.program.scanner": { ko: "ityv 투함 스캐너", source: P },
  "dev.program.checkin": { ko: "ityv 확인 장치", source: P },
  "dev.program.sorter": { ko: "ityv 분류기 확장", source: P },
  "dev.program.gateway": { ko: "ityv 투표소 게이트웨이", source: P },
  "dev.program.observer": { ko: "ityv 참관인 앱", source: P },
  "dev.program.voter": { ko: "ityv 유권자 확인 앱", source: P },
  "dev.comp.interpret": { ko: "해석 유닛", source: P },
  "dev.comp.commit": { ko: "커밋먼트 유닛", source: P },
  "dev.comp.imprinter": { ko: "각인기 제어기", source: P },
  "dev.comp.host": { ko: "호스트", source: P },
  "dev.comp.identity": { ko: "신원 확인 단말", source: P },
  "dev.comp.reader": { ko: "각인 판독기", source: P },
  "dev.comp.gateway": { ko: "게이트웨이", source: P },
  "dev.comp.observer": { ko: "참관인 앱", source: P },
  "dev.comp.voter": { ko: "유권자 확인 앱", source: P },
  "obs.att.sig": { ko: "서명 확인됨", source: S61 },
  "obs.att.nonce": { ko: "도전값 일치", source: S61 },
  "obs.att.fp": {
    ko: "구성 지문 일치: {fp}",
    slots: { fp: "fingerprint16" },
    source: S61,
    spec: { fp: "K7QF 2M8D R5WN Q3XA" },
  },
  "obs.att.ok": { ko: "확인됨", source: S61 },
  "obs.att.fail": { ko: "실패", source: S61 },
  "obs.att.reason.sig": { ko: "서명 오류", source: S61 },
  "obs.att.reason.nonce": { ko: "도전값 다름", source: S61 },
  "obs.att.reason.fp": { ko: "지문 다름", source: S61 },
  "obs.att.reason.build": { ko: "빌드 낮음", source: S61 },
  "obs.att.reason.timeout": { ko: "시간 초과", source: S61 },
  "obs.att.next": { ko: "사건 접수(AttestationIncident) 안내", source: S61 },
  "obs.att.needs": {
    ko: "필요한 것: 참관인 2인(서로 다른 조직)과 사무원 서명, 증명 요약 QR, 장치 ID",
    source: P,
  },
  "obs.att.kept": { ko: "요약 QR 원본과 확인한 시각을 앱에 보관했어요", source: P },

  // §6.2 observer app: progress and alarms.
  "obs.prog.line": {
    ko: "{slot} 칸 · 교부 {issued}장 · 투입 {sheetsIn}장 · 훼손 {spoiled} · 반납 {returned} · 밖에 {out}장(기준 {limit}장)",
    slots: {
      slot: "slotTime",
      issued: "count",
      sheetsIn: "count",
      spoiled: "count",
      returned: "count",
      out: "count",
      limit: "count",
    },
    source: S62,
    spec: { slot: "10:40", issued: "412", sheetsIn: "405", spoiled: "2", returned: "1", out: "4", limit: "24" },
  },
  "obs.alarm.floor": {
    ko: "바닥 경보 · {from}부터 {minutes}분 동안 오간 사람이 없는데 밖에 {out}장 · {until}까지 현장 확인 필요",
    slots: { from: "slotTime", minutes: "minutes", out: "count", until: "slotTime" },
    source: S62,
    spec: { from: "10:20", minutes: "20", out: "1", until: "11:00" },
  },
  "obs.alarm.negative": {
    ko: "음수 경보 · 교부보다 {count}장 더 들어감",
    slots: { count: "count" },
    source: S62,
    spec: { count: "2" },
  },
  "obs.alarm.high": {
    ko: "과다 경보 · 밖에 {out}장(기준 {limit}장)",
    slots: { out: "count", limit: "count" },
    source: S62,
    spec: { out: "31", limit: "24" },
  },
  "obs.prog.suspended": {
    ko: "비상 투입이 있어 이 투표소의 진행 경보는 마감까지 멈췄어요. 마감 등식으로 확인해요",
    source: S62,
  },
  "obs.prog.overflow": {
    ko: "{slot} 칸 · 투입 누계가 64비트를 넘어 합을 셀 수 없어요",
    slots: { slot: "slotTime" },
    source: P,
  },
  "obs.prog.note": { ko: "경보는 확인이 필요하다는 뜻이에요. 어떤 투표지도 무효가 되지 않아요.", source: S62 },
  "obs.check.title": { ko: "현장 확인", source: S62 },
  "obs.check.f1": { ko: "현장 인원으로 설명됨", source: S62 },
  "obs.check.f2": { ko: "반출 확인", source: S62 },
  "obs.check.f3": { ko: "입력 누락 정정", source: S62 },
  "obs.check.f4": { ko: "설명 안 됨", source: S62 },
  "obs.check.holding": { ko: "투표지를 든 사람 수", source: S62 },
  "obs.check.statement": { ko: "진술", source: S62 },
  "obs.check.signers": { ko: "사무원 2 · 다른 조직 참관인 2 서명", source: S62 },
  "obs.check.recorded": {
    ko: "현장 확인 수록 · 프레임 {seq}",
    slots: { seq: "count" },
    source: P,
  },
  "obs.prog.mirrors": { ko: "미러 두 곳의 체크포인트 지문 {fp}", slots: { fp: "fingerprint16" }, source: P },

  // §7 voter verification app.
  "app.included": {
    ko: "이 추적코드는 체크포인트 {n}({status})에 포함되어 있어요. 누구를 찍었는지나 집계가 끝났는지를 뜻하지는 않아요.",
    slots: { n: "count", status: "status" },
    source: S7,
    spec: { n: "N", status: "LOG_CONSISTENT" },
  },
  "app.code": { ko: "추적코드 {code}", slots: { code: "trackingCode" }, source: P },
  "app.fp": { ko: "체크포인트 지문 {fp}", slots: { fp: "fingerprint32" }, source: P },
  "app.compare.match": { ko: "공표 지문과 대조: 같음", source: P },
  "app.compare.differ": {
    ko: "공표 지문과 대조: 다름 · 두 체크포인트를 분기 증거로 저장했어요. 분쟁 접수 방법을 안내해요",
    source: P,
  },
  "app.compare.pending": { ko: "공표 지문과 아직 대조하지 않았어요", source: P },
  "app.uncovered": { ko: "이 추적코드는 공개원장에 있지만 아직 어느 체크포인트에도 들어가지 않았어요", source: P },
  "app.notFound": { ko: "이 추적코드를 공개원장에서 찾지 못했어요. 분쟁 접수 방법을 안내해요", source: P },
} as const satisfies Record<string, StringEntry>;

export type StringId = keyof typeof STRINGS;

/** The status vocabulary (PROTOCOL §14, SCREENS §0.2). */
export const STATUS_WORDS = [
  "UNVERIFIED",
  "LOG_CONSISTENT",
  "SOURCE_COMPLETENESS_CHECKED",
  "CRYPTO_TALLY_VERIFIED",
  "PAPER_AUDITED",
  "HOLD_REVIEW",
  "LEGAL_CERTIFIED",
] as const;

export type StatusWord = (typeof STATUS_WORDS)[number];

export type SlotValue = string | number;

let plain: Set<string> | null = null;

/** Every entry of the table without slots. */
function plainStrings(): Set<string> {
  if (!plain) {
    plain = new Set(
      Object.values(STRINGS as Record<string, StringEntry>)
        .filter((e) => !e.slots)
        .map((e) => e.ko),
    );
  }
  return plain;
}

/** Checks that `value` is a value of `kind`; throws otherwise. A screen
 * that tries to put anything else in a slot fails loudly. */
export function checkSlot(kind: SlotKind, value: SlotValue): string {
  const s = String(value);
  const ok = (() => {
    switch (kind) {
      case "count":
      case "sheet":
      case "minutes":
      case "build":
        return /^\d+$/.test(s);
      case "percent":
        return /^\d{1,3}$/.test(s) && Number(s) <= 100;
      case "slotTime":
        return /^\d{2}:\d{2}$/.test(s);
      case "identifier":
      case "errorCode":
        return /^[A-Za-z0-9._:/-]{1,64}$/.test(s);
      case "trackingCode":
        return /^[0-9a-f]{8}( [0-9a-f]{8}){3}$/.test(s);
      case "ref":
        return plainStrings().has(s);
      case "semver":
        return /^\d+\.\d+\.\d+$/.test(s);
      case "fingerprint16":
        return /^[A-Z2-7]{4}( [A-Z2-7]{4}){3}$/.test(s);
      case "fingerprint32":
        return /^[A-Z2-7]{4}( [A-Z2-7]{4}){7}$/.test(s);
      case "status":
        return (STATUS_WORDS as readonly string[]).includes(s);
    }
  })();
  if (!ok) throw new Error(`slot kind ${kind} cannot hold ${JSON.stringify(s)}`);
  return s;
}

/** Renders string `id` with `values` in its slots. */
export function t(id: StringId, values: Record<string, SlotValue> = {}): string {
  const entry: StringEntry = STRINGS[id];
  const slots = entry.slots ?? {};
  for (const name of Object.keys(values)) {
    if (!(name in slots)) throw new Error(`${id}: no slot ${name}`);
  }
  return entry.ko.replace(/\{(\w+)\}/g, (_m, name: string) => {
    const kind = slots[name];
    if (kind === undefined) throw new Error(`${id}: slot ${name} has no kind`);
    const v = values[name];
    if (v === undefined) throw new Error(`${id}: slot ${name} missing`);
    return checkSlot(kind, v);
  });
}

/** Renders `id` with its SCREENS.md placeholders (tests only). */
export function spec(id: StringId): string {
  const entry: StringEntry = STRINGS[id];
  const placeholders = entry.spec ?? {};
  return entry.ko.replace(/\{(\w+)\}/g, (_m, name: string) => placeholders[name] ?? `{${name}}`);
}
