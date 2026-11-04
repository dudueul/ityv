// The screen models: every state renders from the string table, shows no
// candidate name, read result, voter ordinal, per-event time, pseudonym or
// imprint list, and the voter flow follows the SCREENS.md §1 table.

import { expect, test } from "bun:test";
import { ATTESTATION_FIXTURES, GATEWAY_FIXTURE, type IndexBox, type RecordEntry, type StationProgress } from "../src/data";
import {
  CHECKIN_STATES,
  CLERK_STATES,
  type ScreenModel,
  VOTER_STATES,
  appStatus,
  attestationScreen,
  checkForm,
  checkinScreen,
  clerkScreen,
  gatewayScreen,
  progressScreen,
  sorterScreen,
  voterAppScreen,
  voterNext,
  voterScreen,
} from "../src/screens";
import { DEVICES } from "../src/devices";
import { STRINGS, type StringId, t } from "../src/strings";
import { HOLDS } from "../src/vocab";

const CANDIDATES = ["김가상", "이가상", "박가상", "최가상", "정가상", "한가상", "윤가상", "강가상", "조가상", "서가상"];

function texts(m: ScreenModel): string[] {
  return [
    ...m.blocks.flatMap((b) => [b.text, b.label, b.value, ...(b.cells ?? []).map((c) => c.text)]),
    ...m.buttons.map((b) => b.text),
  ].filter((x): x is string => typeof x === "string");
}

function clean(m: ScreenModel, where: string): void {
  for (const s of texts(m)) {
    for (const name of CANDIDATES) expect(`${where}: ${s}`).not.toContain(name);
    for (const word of ["BLANK", "UNREADABLE", "번째"]) expect(`${where}: ${s}`).not.toContain(word);
    expect(/\d{1,2}:\d{2}:\d{2}/.test(s)).toBe(false);
    expect((s.match(/[0-9a-f]{32}/g) ?? []).length).toBeLessThanOrEqual(1);
  }
}

const station: StationProgress = {
  station: "ST-HB-1",
  limit: 12,
  firstSlot: 468,
  lastSlot: 474,
  ticks: 7,
  suspended: false,
  counterfoil: false,
  close: "Compared",
  holds: [],
  alarms: [
    { slot: 471, alarm: "Floor" },
    { slot: 472, alarm: "Negative" },
    { slot: 473, alarm: "High" },
  ],
  checks: [80],
  series: [468, 469, 470, 471, 472, 473, 474].map((slot, i) => ({
    slot,
    checkins: i + 1,
    issued: i + 1,
    spoiled: 0,
    returned: 0,
    sheetsIn: i,
    out: 1,
  })),
  overflow: false,
};

const box: IndexBox = {
  id: "BOX-HB-1",
  label: "투표함",
  style: "S-HB",
  unit: "RU-HB",
  absentee: false,
  paper: { byCandidate: [4, 3, 1], unsorted: 1, total: 9 },
};

test("every voter state renders, and only decide and choose have buttons", () => {
  for (const state of VOTER_STATES) {
    const m = voterScreen({ state, sheets: 3, chosen: [2] });
    clean(m, state);
    expect(texts(m).length).toBeGreaterThan(0);
    expect(m.buttons.length > 0).toBe(state === "decide" || state === "choose");
  }
  // Position cells carry only the sheet number.
  const d = voterScreen({ state: "decide", sheets: 7, chosen: [] });
  const cells = d.blocks.find((b) => b.kind === "cells")?.cells ?? [];
  expect(cells.map((c) => c.text)).toEqual(["1", "2", "3", "4", "5", "6", "7"]);
});

test("the voter flow follows the SCREENS.md §1 table", () => {
  let s = { state: "idle" as const, sheets: 3, chosen: [] as number[] };
  let x = voterNext(s, "insert");
  expect(x.state).toBe("reading");
  x = voterNext(x, "castAll");
  expect(x.state).toBe("reading"); // no decision while reading (VC-068)
  x = voterNext(x, "read");
  expect(x.state).toBe("decide");
  x = voterNext(x, "choose");
  expect(x.state).toBe("choose");
  expect(voterNext(x, "challenge").state).toBe("choose"); // nothing chosen
  x = voterNext(voterNext(x, "toggle:2"), "toggle:3");
  expect(x.chosen).toEqual([2, 3]);
  expect(voterNext(x, "toggle:9").chosen).toEqual([2, 3]);
  const c = voterNext(x, "challenge");
  expect(c.state).toBe("challenged");
  expect(voterNext(voterNext(x, "back"), "castAll").state).toBe("cast");
  expect(voterNext({ ...s, state: "cast" as never }, "done").state).toBe("slip");
  s = { state: "idle", sheets: 3, chosen: [] };
  expect(voterNext(s, "castAll").state).toBe("idle");
});

test("every other device screen renders every state cleanly", () => {
  for (const state of CLERK_STATES) {
    clean(
      clerkScreen({
        state,
        box: "BOX-HB-1",
        absentee: true,
        records: 130,
        challenged: 1,
        quarantined: 0,
        visits: 130,
        stickers: 130,
        unattested: 2,
        slot: 470,
        chambers: ["P1", "P2"],
      }),
      state,
    );
  }
  for (const state of CHECKIN_STATES) clean(checkinScreen({ state, checkins: 412 }), state);
  for (const delta of [0, 1]) {
    const m = sorterScreen({ box, records: 9, fallback: 0, unimprinted: 0, duplicates: 0, paperDelta: delta });
    clean(m, "sorter");
    expect(texts(m).some((x) => x.includes("HOLD_REVIEW"))).toBe(delta === 1);
  }
  for (const up of [true, false]) clean(gatewayScreen(GATEWAY_FIXTURE, 470, 7, up), "gateway");
  for (const a of ATTESTATION_FIXTURES) clean(attestationScreen(a, "K7QF 2M7D R5WN Q3XA"), a.label);
  const p = progressScreen({ station, slot: 474, mirrorFp: "K7QF 2M7D R5WN Q3XA" });
  clean(p, "progress");
  const all = texts(p).join("\n");
  expect(all).toContain("바닥 경보");
  expect(all).toContain("음수 경보");
  expect(all).toContain("과다 경보");
  expect(all).toContain(t("obs.prog.note"));
  clean(checkForm(), "check");
});

test("the voter app shows LOG_CONSISTENT only after the cross-check and never a higher rung", () => {
  expect(appStatus("CRYPTO_TALLY_VERIFIED", "match")).toBe("LOG_CONSISTENT");
  expect(appStatus("CRYPTO_TALLY_VERIFIED", "pending")).toBe("UNVERIFIED");
  expect(appStatus("LOG_CONSISTENT", "differ")).toBe("UNVERIFIED");
  expect(appStatus("HOLD_REVIEW", "match")).toBe("HOLD_REVIEW");
  expect(appStatus("UNVERIFIED", "match")).toBe("UNVERIFIED");
  const record: RecordEntry = {
    code: "ab".repeat(64),
    box: "BOX-HB-1",
    seq: 12,
    state: "CAST_COMMITTED",
    checkpoint: 2,
    treeSize: 40,
    checkpointFingerprint: "K7QF 2M7D R5WN Q3XA AAAA AAAA AAAA AAAA",
    included: true,
    pathLength: 6,
  };
  const uncovered: RecordEntry = { ...record, checkpoint: null, included: false };
  const base = { code: record.code, record, status: "CRYPTO_TALLY_VERIFIED" };
  const match = texts(voterAppScreen({ ...base, compare: "match" })).join("\n");
  expect(match).toContain("체크포인트 2(LOG_CONSISTENT)에 포함되어 있어요");
  const pending = texts(voterAppScreen({ ...base, compare: "pending" })).join("\n");
  expect(pending).not.toContain("LOG_CONSISTENT");
  expect(pending).not.toContain("CRYPTO_TALLY_VERIFIED");
  for (const compare of ["match", "pending", "differ"] as const) {
    clean(voterAppScreen({ ...base, compare }), compare);
    clean(voterAppScreen({ ...base, compare, record: null }), "missing");
    const u = voterAppScreen({ ...base, compare, record: uncovered });
    clean(u, "uncovered");
    expect(texts(u).join("\n")).not.toContain("포함되어 있어요");
  }
});

test("demo values are marked, ledger values are not", () => {
  const clerk = clerkScreen({
    state: "voting",
    box: "BOX-HB-1",
    absentee: false,
    records: 130,
    challenged: 1,
    quarantined: 0,
    visits: 130,
    stickers: 130,
    unattested: 2,
    slot: 470,
    chambers: ["P1", "P2"],
  });
  expect(clerk.blocks.some((b) => b.demo === true)).toBe(true);
  expect(clerk.blocks.some((b) => b.demo !== true)).toBe(true);
  // Every gateway value comes from the fixture: the session, each link's
  // frames and chain head, each tap and the line. Only section titles and
  // the fixed "no inbound path" row are unmarked.
  const gw = gatewayScreen(GATEWAY_FIXTURE, 470, 7, true).blocks;
  const fixtureBlocks = 1 + GATEWAY_FIXTURE.links.length * 2 + GATEWAY_FIXTURE.taps.length + 1;
  expect(gw.filter((b) => b.demo === true).length).toBe(fixtureBlocks);
  for (const b of gw.filter((x) => x.demo !== true)) expect(["section", "row"]).toContain(b.kind);
  // The attestation's device line and its three checks are fixture values.
  for (const a of ATTESTATION_FIXTURES) {
    const blocks = attestationScreen(a, "K7QF 2M7D R5WN Q3XA").blocks;
    expect(blocks.slice(0, 4).every((b) => b.demo === true)).toBe(true);
  }
  // The progress screen shows only the verifier's values.
  const p = progressScreen({ station, slot: 474, mirrorFp: "K7QF 2M7D R5WN Q3XA" });
  expect(p.blocks.some((b) => b.demo === true)).toBe(false);
});

test("the progress screen keeps 64-bit slots exact and says when a sum overflowed", () => {
  const big = "18446744073709551615";
  const s: StationProgress = {
    ...station,
    firstSlot: big,
    lastSlot: big,
    alarms: [],
    series: [{ slot: big, checkins: 1, issued: 1, spoiled: 0, returned: 0, sheetsIn: null, out: null, overflow: true }],
    overflow: true,
  };
  const all = texts(progressScreen({ station: s, slot: big, mirrorFp: "K7QF 2M7D R5WN Q3XA" })).join("\n");
  expect(all).toContain("64비트를 넘어");
  // 2^64 - 1 is 15 mod 144 (slots per day): the 16th slot, 02:30.
  expect(all).toContain("02:30 칸");
});

test("a slot refuses a value of another kind", () => {
  expect(() => t("voter.reading", { count: "셋" })).toThrow();
  expect(() => t("voter.cast", { count: 3, status: "VERIFIED" })).toThrow();
  expect(() => t("id.line", { program: "p", version: "1", build: 1, fp: "K7QF" })).toThrow();
  expect(t("voter.cast", { count: 3, status: "UNVERIFIED" })).toContain("(UNVERIFIED)");
});

test("every hold code of ityv-state has a Korean explanation", () => {
  for (let code = 0; code <= 71; code++) {
    expect(typeof HOLDS[code]?.ko).toBe("string");
  }
  expect(Object.keys(STRINGS).length).toBeGreaterThan(80);
  void (null as unknown as StringId);
});

test("every device's identity line and detail view fill their slots", () => {
  for (const d of DEVICES) {
    expect(t("id.line", { program: d.program, version: d.version, build: d.build, fp: "K7QF 2M7D R5WN Q3XA" })).toContain(d.program);
    for (const c of d.components) {
      expect(t("id.detail.component", { name: c.name, version: c.version, build: c.build })).toContain(c.name);
    }
    for (const m of d.modules) expect(t("id.detail.module", { module: m, build: 1 })).toContain(m);
  }
});
