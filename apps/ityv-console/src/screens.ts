// The device screens of docs/ui/SCREENS.md §1–§7 as pure models.
//
// This is a TypeScript model of the SCREENS.md tables, not device
// firmware (M8): each screen is a function from a state (and, where the
// ledger has it, data the WASM verifier read from a simulator bundle) to
// a list of blocks whose every text comes from the fixed string table
// through `t` (labels) or `v` (typed slot values). The DOM layer only
// draws the model, so `bun test` checks every state's text.

import { type SlotKind, type SlotValue, type StringId, checkSlot, t } from "./strings";
import type { AttestationFixture, GatewayFixture, IndexBox, RecordEntry, StationProgress } from "./data";
import { slotTime } from "./data";

export type Icon = "wait" | "ok" | "warn" | "stop" | "info" | "paper" | "card" | "lock" | "fail";

export interface Block {
  kind: "title" | "text" | "big" | "note" | "row" | "cells" | "alarm" | "section";
  text?: string;
  /** For rows: the label (table string) and the value (slot or string). */
  label?: string;
  value?: string;
  icon?: Icon;
  cells?: { text: string; selected: boolean; n: number }[];
}

export interface ScreenButton {
  text: string;
  shape: "round" | "square";
  enabled: boolean;
  action: string;
}

export interface ScreenModel {
  blocks: Block[];
  buttons: ScreenButton[];
}

/** A typed slot value shown on its own (a count, an identifier). */
export function v(kind: SlotKind, value: SlotValue): string {
  return checkSlot(kind, value);
}

const txt = (id: StringId, values?: Record<string, SlotValue>, icon?: Icon): Block => ({
  kind: "text",
  text: t(id, values),
  icon,
});
const big = (id: StringId, values?: Record<string, SlotValue>, icon?: Icon): Block => ({
  kind: "big",
  text: t(id, values),
  icon,
});
const row = (label: StringId, value: string, icon?: Icon): Block => ({ kind: "row", label: t(label), value, icon });
const section = (id: StringId): Block => ({ kind: "section", text: t(id) });

// ---------------------------------------------------------------------
// §1 scanner voter screen.

export const VOTER_STATES = [
  "idle",
  "reading",
  "decide",
  "choose",
  "challenged",
  "cast",
  "slip",
  "overlap",
  "failed",
  "fallback",
  "card",
] as const;
export type VoterState = (typeof VOTER_STATES)[number];

export const VOTER_STATE_LABELS: Record<VoterState, string> = {
  idle: "대기",
  reading: "읽는 중",
  decide: "결정",
  choose: "고르기",
  challenged: "확인 결과",
  cast: "넣음",
  slip: "쪽지",
  overlap: "겹침",
  failed: "처리 못 함",
  fallback: "비상 투입",
  card: "확인 카드",
};

export interface VoterInput {
  state: VoterState;
  /** Sheets in the visit (1–8). */
  sheets: number;
  /** Positions chosen to check (1-based). */
  chosen: number[];
}

/** The voter screen. Buttons light only in the decide and choose states
 * (VC-068: after every position's record signature). */
export function voterScreen(i: VoterInput): ScreenModel {
  const n = Math.max(1, Math.min(8, i.sheets));
  const cells = (selectable: boolean) =>
    Array.from({ length: n }, (_, k) => ({
      text: t("voter.cell", { sheet: k + 1 }),
      selected: selectable && i.chosen.includes(k + 1),
      n: k + 1,
    }));
  switch (i.state) {
    case "idle":
      return { blocks: [big("voter.idle", {}, "paper")], buttons: [] };
    case "reading":
      return { blocks: [big("voter.reading", { count: n }, "wait")], buttons: [] };
    case "decide":
      return {
        blocks: [big("voter.decide", { count: n }, "lock"), { kind: "cells", cells: cells(false) }],
        buttons: [
          { text: t("voter.btn.castAll"), shape: "round", enabled: true, action: "castAll" },
          { text: t("voter.btn.choose"), shape: "square", enabled: true, action: "choose" },
        ],
      };
    case "choose":
      return {
        blocks: [big("voter.choose", {}, "info"), { kind: "cells", cells: cells(true) }],
        buttons: [
          { text: t("voter.btn.challenge"), shape: "square", enabled: i.chosen.length > 0, action: "challenge" },
          { text: t("voter.btn.back"), shape: "round", enabled: true, action: "back" },
        ],
      };
    case "challenged":
      return { blocks: [big("voter.challenged", { count: Math.max(1, i.chosen.length) }, "paper")], buttons: [] };
    case "cast":
      return {
        blocks: [big("voter.cast", { count: Math.max(0, n - i.chosen.length) || n, status: "UNVERIFIED" }, "ok")],
        buttons: [],
      };
    case "slip":
      return { blocks: [big("voter.slip", {}, "paper")], buttons: [] };
    case "overlap":
      return { blocks: [big("voter.overlap", {}, "warn")], buttons: [] };
    case "failed":
      return { blocks: [big("voter.failed", {}, "stop")], buttons: [] };
    case "fallback":
      return { blocks: [big("voter.fallback", {}, "stop")], buttons: [] };
    case "card":
      return { blocks: [big("voter.card", {}, "card")], buttons: [] };
  }
}

/** The voter flow (a model of SCREENS §1, not firmware): what a button
 * press does in each state. */
export function voterNext(i: VoterInput, action: string): VoterInput {
  switch (action) {
    case "insert":
      return i.state === "idle" ? { ...i, state: "reading", chosen: [] } : i;
    case "read":
      return i.state === "reading" ? { ...i, state: "decide" } : i;
    case "castAll":
      return i.state === "decide" ? { ...i, state: "cast", chosen: [] } : i;
    case "choose":
      return i.state === "decide" ? { ...i, state: "choose", chosen: [] } : i;
    case "back":
      return i.state === "choose" ? { ...i, state: "decide", chosen: [] } : i;
    case "challenge":
      return i.state === "choose" && i.chosen.length > 0 ? { ...i, state: "challenged" } : i;
    case "done":
      if (i.state === "cast") return { ...i, state: "slip" };
      if (i.state === "slip" || i.state === "challenged" || i.state === "card") return { ...i, state: "idle", chosen: [] };
      return i;
    default: {
      const m = /^toggle:(\d)$/.exec(action);
      if (m && i.state === "choose") {
        const k = Number(m[1]);
        if (k < 1 || k > i.sheets) return i;
        const chosen = i.chosen.includes(k) ? i.chosen.filter((x) => x !== k) : [...i.chosen, k].sort();
        return { ...i, chosen };
      }
      return i;
    }
  }
}

// ---------------------------------------------------------------------
// §2 scanner clerk and observer screen.

export const CLERK_STATES = ["notOpened", "voting", "fallback", "closing", "closed"] as const;
export type ClerkState = (typeof CLERK_STATES)[number];
export const CLERK_STATE_LABELS: Record<ClerkState, string> = {
  notOpened: "개시 전",
  voting: "투표 중",
  fallback: "비상 투입 중",
  closing: "마감 중",
  closed: "마감됨",
};

export interface ClerkInput {
  state: ClerkState;
  box: string;
  absentee: boolean;
  records: number;
  challenged: number;
  quarantined: number;
  visits: number;
  stickers: number;
  slot: number;
  framesSent: number;
  chambers: string[];
}

export function clerkScreen(i: ClerkInput): ScreenModel {
  const stateId = `clerk.box.${i.state}` as StringId;
  const closedBatches = Math.floor(i.records / 64);
  const fill = i.records % 64;
  const sinceAttest = i.records % 50;
  const blocks: Block[] = [
    section("clerk.box"),
    { kind: "row", label: v("identifier", i.box), value: t(stateId), icon: i.state === "fallback" ? "warn" : "info" },
    section("clerk.counts"),
    row("clerk.records", v("count", i.records)),
    row("clerk.challenged", v("count", i.challenged)),
    row("clerk.quarantined", v("count", i.quarantined)),
    row("clerk.visits", v("count", i.visits)),
  ];
  if (i.absentee) blocks.push(row("clerk.stickers", v("count", i.stickers)));
  blocks.push(
    section("clerk.batch"),
    txt("clerk.batch.fill", { x: fill }),
    txt("clerk.batch.closed", { count: closedBatches }),
    section("clerk.attest"),
    txt("clerk.attest.left", { count: 50 - sinceAttest, minutes: 120 - ((i.slot * 10) % 120) }),
    section("clerk.journal"),
    txt("clerk.journal.ok", {}, "ok"),
    section("clerk.send"),
    txt("clerk.send.slot", { slot: i.slot, minutes: 10 }),
    txt("clerk.send.frames", { count: i.framesSent }),
    txt("clerk.send.backlog", { count: 0 }),
    section("clerk.modules"),
    ...i.chambers.map((c) =>
      txt("clerk.module.row", { chamber: c, state: t("clerk.module.present"), percent: 97 }, "ok"),
    ),
    section("clerk.attestation"),
    txt("clerk.attestation.opening", {}, "ok"),
  );
  return { blocks, buttons: [] };
}

// ---------------------------------------------------------------------
// §3 check-in device clerk screen.

export const CHECKIN_STATES = [
  "checking",
  "done",
  "rollOk",
  "rollLost",
  "cosignWait",
  "cosignDone",
  "swap",
  "issue",
  "spoiled",
  "returned",
] as const;
export type CheckinState = (typeof CHECKIN_STATES)[number];
export const CHECKIN_STATE_LABELS: Record<CheckinState, string> = {
  checking: "확인 중",
  done: "완료",
  rollOk: "명부 연결됨",
  rollLost: "명부 연결 끊김",
  cosignWait: "공동 서명 대기",
  cosignDone: "공동 서명 완료",
  swap: "카운터 유닛 교체",
  issue: "교부",
  spoiled: "훼손 회수",
  returned: "반납",
};

export interface CheckinInput {
  state: CheckinState;
  checkins: number;
  sheets: number;
}

export function checkinScreen(i: CheckinInput): ScreenModel {
  const b = (() => {
    switch (i.state) {
      case "checking":
        return big("checkin.checking", {}, "wait");
      case "done":
        return big("checkin.done", { count: i.checkins }, "ok");
      case "rollOk":
        return big("checkin.roll.ok", {}, "ok");
      case "rollLost":
        return big("checkin.roll.lost", {}, "stop");
      case "cosignWait":
        return big("checkin.cosign.wait", { count: 2 }, "wait");
      case "cosignDone":
        return big("checkin.cosign.done", { count: i.checkins }, "ok");
      case "swap":
        return big("checkin.swap", {}, "warn");
      case "issue":
        return big("checkin.issue", { count: i.sheets }, "paper");
      case "spoiled":
        return big("checkin.spoiled", { count: 1 }, "warn");
      case "returned":
        return big("checkin.returned", { count: 1 }, "info");
    }
  })();
  return { blocks: [b], buttons: [] };
}

// ---------------------------------------------------------------------
// §4 counting-centre sorter extension.

export interface SorterInput {
  box: IndexBox;
  /** Records and emergency-slot ballots from the close record. */
  records: number;
  fallback: number;
  /** Imprint findings (demo: zero unless a state injects one). */
  unimprinted: number;
  duplicates: number;
  /** Paper read differently from the close (a state of the demo). */
  paperDelta: number;
}

export function sorterScreen(i: SorterInput): ScreenModel {
  const paper = i.box.paper.total + i.paperDelta;
  const rhs = i.records + i.fallback;
  const diff = Math.abs(paper - rhs);
  const blocks: Block[] = [
    txt("sorter.box", { box: i.box.id, style: i.box.style }),
    section("sorter.paper"),
    ...i.box.paper.byCandidate.map(
      (n, k): Block => ({
        kind: "row",
        label: t("sorter.pocket", { sheet: k + 1 }),
        value: v("count", n + (k === 0 ? i.paperDelta : 0)),
      }),
    ),
    row("sorter.unsorted", v("count", i.box.paper.unsorted)),
    row("sorter.total", v("count", paper)),
    section("sorter.equation"),
    txt("sorter.equation.values", { paper, records: i.records, fallback: i.fallback, diff }, diff === 0 ? "ok" : "warn"),
    txt("sorter.imprint.none", { count: i.unimprinted }),
    txt("sorter.imprint.twice", { count: i.duplicates }),
  ];
  if (diff !== 0 || i.unimprinted > 0 || i.duplicates > 0) {
    blocks.push(big("sorter.hold", { status: "HOLD_REVIEW" }, "warn"));
  }
  return { blocks, buttons: [] };
}

// ---------------------------------------------------------------------
// §5 station gateway.

export function gatewayScreen(g: GatewayFixture, slot: number, minutesLeft: number, lineUp: boolean): ScreenModel {
  return {
    blocks: [
      txt("gw.session", { session: g.session, slot, minutes: minutesLeft }),
      ...g.links.map((l) => txt("gw.frames", { link: l.link, count: l.frames, slotCount: l.slotFrames })),
      row("gw.inbound", t("gw.inbound.none")),
      section("gw.taps"),
      ...g.taps.map((tap) =>
        txt("gw.tap", { tap: tap.tap, state: t(tap.inUse ? "gw.tap.inUse" : "gw.tap.idle") }, tap.inUse ? "info" : undefined),
      ),
      section("gw.chain"),
      ...g.links.map((l) => txt("gw.chain.head", { link: l.link, head: l.head })),
      section("gw.line"),
      txt(lineUp ? "gw.line.up" : "gw.line.down", {}, lineUp ? "ok" : "warn"),
    ],
    buttons: [],
  };
}

// ---------------------------------------------------------------------
// §6.1 observer app: attestation result.

export function attestationScreen(a: AttestationFixture, configFp: string): ScreenModel {
  const result = (ok: boolean) => t(ok ? "obs.att.ok" : "obs.att.fail");
  const blocks: Block[] = [
    txt("obs.att.device", { device: a.device, kind: a.kind }),
    { kind: "row", label: t("obs.att.sig"), value: result(a.sig), icon: a.sig ? "ok" : "fail" },
    { kind: "row", label: t("obs.att.nonce"), value: result(a.nonce), icon: a.nonce ? "ok" : "fail" },
    { kind: "row", label: t("obs.att.fp", { fp: configFp }), value: result(a.fp), icon: a.fp ? "ok" : "fail" },
  ];
  if (a.reason) {
    const id = `obs.att.reason.${a.reason}` as StringId;
    blocks.push(big(id, {}, "stop"), txt("obs.att.next", {}, "info"), txt("obs.att.needs"));
  }
  blocks.push({ kind: "note", text: t("obs.att.kept") });
  return { blocks, buttons: [] };
}

// ---------------------------------------------------------------------
// §6.2 observer app: progress and alarms.

export interface ProgressInput {
  station: StationProgress;
  /** Show the counts after this slot. */
  slot: number;
  /** The checkpoint fingerprint both mirrors gave (16 characters). */
  mirrorFp: string | null;
}

export function progressScreen(i: ProgressInput): ScreenModel {
  const s = i.station;
  const point = [...s.series].reverse().find((p) => p.slot <= i.slot) ?? s.series[0];
  const blocks: Block[] = [];
  if (point) {
    const out = point.out ?? 0;
    blocks.push(
      txt("obs.prog.line", {
        slot: slotTime(point.slot),
        issued: point.issued,
        sheetsIn: point.sheetsIn,
        spoiled: point.spoiled,
        returned: point.returned,
        out: Math.max(0, out),
        limit: s.limit ?? 0,
      }),
    );
  }
  const shown = s.alarms.filter((a) => a.slot <= i.slot);
  for (const a of shown) {
    const p = s.series.find((x) => x.slot === a.slot);
    const out = p?.out ?? 0;
    if (a.alarm === "Floor") {
      blocks.push({
        kind: "alarm",
        icon: "warn",
        text: t("obs.alarm.floor", {
          from: slotTime(a.slot - 1),
          minutes: 20,
          out: Math.max(0, out),
          until: slotTime(a.slot + 3),
        }),
      });
    } else if (a.alarm === "Negative") {
      blocks.push({ kind: "alarm", icon: "warn", text: t("obs.alarm.negative", { count: Math.max(0, -out) }) });
    } else if (a.alarm === "High") {
      blocks.push({
        kind: "alarm",
        icon: "warn",
        text: t("obs.alarm.high", { out: Math.max(0, out), limit: s.limit ?? 0 }),
      });
    }
  }
  if (s.suspended && s.lastSlot !== null && i.slot >= (s.firstSlot ?? 0)) {
    blocks.push({ kind: "alarm", icon: "info", text: t("obs.prog.suspended") });
  }
  if (shown.length > 0 || s.suspended) {
    blocks.push({ kind: "note", text: t("obs.prog.note") });
  }
  for (const c of s.checks) {
    blocks.push(txt("obs.check.recorded", { seq: c }, "ok"));
  }
  if (i.mirrorFp) blocks.push({ kind: "note", text: t("obs.prog.mirrors", { fp: i.mirrorFp }) });
  return { blocks, buttons: [] };
}

/** The on-site check form (§6.2): read-only in the prototype. */
export function checkForm(): ScreenModel {
  return {
    blocks: [
      section("obs.check.title"),
      txt("obs.check.f1"),
      txt("obs.check.f2"),
      txt("obs.check.f3"),
      txt("obs.check.f4"),
      row("obs.check.holding", v("count", 0)),
      row("obs.check.statement", v("identifier", "-")),
      { kind: "note", text: t("obs.check.signers") },
    ],
    buttons: [],
  };
}

// ---------------------------------------------------------------------
// §7 voter verification app.

export type AppCompare = "match" | "differ" | "pending";

export interface AppInput {
  code: string;
  record: RecordEntry | null;
  /** Whether a verified inclusion proof puts the record's frame in
   * `checkpoint`. */
  included: boolean;
  checkpoint: number | null;
  checkpointFp: string | null;
  /** The verifier's status of the ledger. */
  status: string;
  compare: AppCompare;
}

/** The status the app may show beside an inclusion: `LOG_CONSISTENT`
 * only after the cross-check (PROTOCOL §5.7 item 4), `HOLD_REVIEW` when
 * the verifier holds the ledger, `UNVERIFIED` otherwise. A higher rung of
 * the ledger is not claimed for one tracking code. */
export function appStatus(ledger: string, compare: AppCompare): string {
  if (ledger === "HOLD_REVIEW") return "HOLD_REVIEW";
  if (compare !== "match") return "UNVERIFIED";
  return ["LOG_CONSISTENT", "SOURCE_COMPLETENESS_CHECKED", "CRYPTO_TALLY_VERIFIED", "PAPER_AUDITED"].includes(ledger)
    ? "LOG_CONSISTENT"
    : "UNVERIFIED";
}

export function voterAppScreen(i: AppInput): ScreenModel {
  const code = i.code.slice(0, 32).replace(/(.{8})/g, "$1 ").trim();
  const blocks: Block[] = [txt("app.code", { code })];
  if (!i.record) {
    blocks.push(big("app.notFound", {}, "stop"));
    return { blocks, buttons: [] };
  }
  if (!i.included || i.checkpoint === null) {
    blocks.push(big("app.uncovered", {}, "wait"));
    return { blocks, buttons: [] };
  }
  const status = appStatus(i.status, i.compare);
  if (i.compare === "match" || i.status === "HOLD_REVIEW") {
    blocks.push(big("app.included", { n: i.checkpoint, status }, status === "LOG_CONSISTENT" ? "ok" : "warn"));
  }
  if (i.checkpointFp) blocks.push(txt("app.fp", { fp: i.checkpointFp }));
  blocks.push(
    i.compare === "match"
      ? txt("app.compare.match", {}, "ok")
      : i.compare === "differ"
        ? txt("app.compare.differ", {}, "stop")
        : txt("app.compare.pending", {}, "wait"),
  );
  return { blocks, buttons: [] };
}
