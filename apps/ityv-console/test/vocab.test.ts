// The console's vocabulary against the Rust sources it names: every
// variant the verifier can report has Korean text, so no reason reaches
// the screen as a bare identifier. The tables only name; every value
// shown is the verifier's.

import { expect, test } from "bun:test";
import { AUDIT_EVENTS, AUDIT_REFUSALS, HOLDS, ROLL_REASONS, STAGES, TSA_KINDS } from "../src/vocab";

const repo = `${import.meta.dir}/../../..`;
const source = async (path: string) => Bun.file(`${repo}/${path}`).text();

/** The variant names of `pub enum <name>` in Rust source `text`. */
function variants(text: string, name: string): string[] {
  const start = text.indexOf(`pub enum ${name} {`);
  expect(start).toBeGreaterThan(-1);
  const body = text.slice(start, text.indexOf("\n}", start));
  return [...body.matchAll(/^ {4}([A-Z][A-Za-z0-9]*)\b/gm)].map((m) => m[1]!);
}

const korean = (s: string | undefined) => typeof s === "string" && /[가-힣]/.test(s);

test("every audit event and refusal of ityv-verify has Korean text", async () => {
  const audit = await source("crates/ityv-verify/src/audit.rs");
  const refusals = variants(audit, "AuditRefusal");
  expect(refusals).toContain("Unstamped");
  for (const v of refusals) expect(korean(AUDIT_REFUSALS[v])).toBe(true);
  for (const v of variants(audit, "AuditEvent")) expect(korean(AUDIT_EVENTS[v])).toBe(true);
});

test("every timestamp authority kind and roll amendment reason has Korean text", async () => {
  const ts = await source("crates/ityv-encoding/src/schema/timestamp.rs");
  const kinds = variants(ts, "TimestampAuthorityKind");
  expect(kinds).toEqual(["Government", "NonGovernment"]);
  for (const v of kinds) expect(korean(TSA_KINDS[v])).toBe(true);
  const roll = await source("crates/ityv-encoding/src/schema/roll.rs");
  const reasons = variants(roll, "RollAmendmentReason");
  expect(reasons.length).toBe(5);
  for (const v of reasons) expect(korean(ROLL_REASONS[v])).toBe(true);
});

test("every stage the WASM report names a refusal by has Korean text", async () => {
  const report = await source("apps/ityv-wasm/src/report.rs");
  const stages = new Set([...report.matchAll(/list\.push\(\(\s*[^,]+,\s*"([a-z]+)"/g)].map((m) => m[1]!));
  for (const s of ["timestamps", "roll", "audit", "tally"]) expect(stages.has(s)).toBe(true);
  for (const s of stages) expect(korean(STAGES[s])).toBe(true);
});

test("the hold table names the timestamp and roll holds", () => {
  expect(HOLDS[72]?.name).toBe("TimestampInvalid");
  expect(HOLDS[73]?.name).toBe("TimestampMismatch");
  expect(HOLDS[74]?.name).toBe("RollEventRefused");
  expect(HOLDS[75]?.name).toBe("RollCustodyMismatch");
  expect(HOLDS[76]?.name).toBe("ContestedCheckinInvalid");
  expect(HOLDS[77]?.name).toBe("ContestedRepeated");
  expect(HOLDS[78]?.name).toBe("RollIncomplete");
});
