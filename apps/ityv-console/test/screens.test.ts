// The screen models: every state renders from the string table, shows no
// candidate name, read result, voter ordinal, per-event time, pseudonym or
// imprint list, and the voter flow follows the SCREENS.md §1 table.

import { expect, test } from "bun:test";
import { ATTESTATION_FIXTURES, GATEWAY_FIXTURE, type IndexBox, type StationProgress } from "../src/data";
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
        slot: 470,
        framesSent: 1168,
        chambers: ["P1", "P2"],
      }),
      state,
    );
  }
  for (const state of CHECKIN_STATES) clean(checkinScreen({ state, checkins: 412, sheets: 1 }), state);
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
  const record = { code: "ab".repeat(64), box: "BOX-HB-1", seq: 12, state: "CAST_COMMITTED", checkpoint: 2 };
  const base = { code: record.code, record, included: true, checkpoint: 2, checkpointFp: "K7QF 2M7D R5WN Q3XA AAAA AAAA AAAA AAAA", status: "CRYPTO_TALLY_VERIFIED" };
  const match = texts(voterAppScreen({ ...base, compare: "match" })).join("\n");
  expect(match).toContain("체크포인트 2(LOG_CONSISTENT)에 포함되어 있어요");
  const pending = texts(voterAppScreen({ ...base, compare: "pending" })).join("\n");
  expect(pending).not.toContain("LOG_CONSISTENT");
  expect(pending).not.toContain("CRYPTO_TALLY_VERIFIED");
  for (const compare of ["match", "pending", "differ"] as const) {
    clean(voterAppScreen({ ...base, compare }), compare);
    clean(voterAppScreen({ ...base, compare, record: null }), "missing");
    clean(voterAppScreen({ ...base, compare, included: false }), "uncovered");
  }
});

test("a slot refuses a value of another kind", () => {
  expect(() => t("voter.reading", { count: "셋" })).toThrow();
  expect(() => t("voter.cast", { count: 3, status: "VERIFIED" })).toThrow();
  expect(() => t("id.line", { program: "p", version: "1", build: 1, fp: "K7QF" })).toThrow();
  expect(t("voter.cast", { count: 3, status: "UNVERIFIED" })).toContain("(UNVERIFIED)");
});

test("every hold code of ityv-state has a Korean explanation", () => {
  for (let code = 0; code <= 60; code++) {
    expect(typeof HOLDS[code]?.ko).toBe("string");
  }
  expect(Object.keys(STRINGS).length).toBeGreaterThan(80);
  void (null as unknown as StringId);
});
