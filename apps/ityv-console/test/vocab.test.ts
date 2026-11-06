// The console's vocabulary against the Rust sources it names: every
// variant the verifier can report has Korean text, so no reason reaches
// the screen as a bare identifier. The tables only name; every value
// shown is the verifier's.

import { expect, test } from "bun:test";
import {
  AUDIT_EVENTS,
  AUDIT_REFUSALS,
  DEVICE_CLASSES,
  HOLDS,
  INCIDENT_KINDS,
  INCIDENT_PROBLEMS,
  LINK_PROBLEMS,
  MANIFEST_PROBLEMS,
  ROLL_REASONS,
  SESSION_PROBLEMS,
  STAGES,
  STEPS,
  TSA_KINDS,
} from "../src/vocab";

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

/** The variants of `code_enum!` block `name` in Rust source `text`. */
function codes(text: string, name: string): string[] {
  const start = text.indexOf(`    ${name} {`);
  expect(start).toBeGreaterThan(-1);
  const body = text.slice(start, text.indexOf("\n    }", start));
  return [...body.matchAll(/^ {8}([A-Z][A-Za-z0-9]*) = /gm)].map((m) => m[1]!);
}

test("every connectivity finding of ityv-verify and ityv-encoding has Korean text", async () => {
  const verify = await source("crates/ityv-verify/src/connectivity.rs");
  for (const [name, table, n] of [
    ["ManifestProblem", MANIFEST_PROBLEMS, 11],
    ["SessionProblem", SESSION_PROBLEMS, 17],
    ["LinkProblem", LINK_PROBLEMS, 19],
    ["IncidentProblem", INCIDENT_PROBLEMS, 3],
  ] as const) {
    const vs = variants(verify, name);
    expect(vs.length).toBe(n);
    for (const v of vs) expect(korean(table[v])).toBe(true);
  }
  const encoding = await source("crates/ityv-encoding/src/schema/connectivity.rs");
  const classes = codes(encoding, "DeviceClass");
  expect(classes.length).toBe(15);
  for (const v of classes) expect(korean(DEVICE_CLASSES[v])).toBe(true);
  const kinds = codes(encoding, "IncidentKind");
  expect(kinds.length).toBe(10);
  for (const v of kinds) expect(korean(INCIDENT_KINDS[v])).toBe(true);
  expect(STEPS.Connectivity).not.toContain("아직");
});

test("the hold table names the connectivity holds", async () => {
  const hold = await source("crates/ityv-state/src/hold.rs");
  const names = ["ConnectivityManifest", "UplinkSessionRefused", "UplinkFrameInvalid", "UplinkObjectInvalid", "UplinkObjectOutside", "ConnectivityIncident", "ConnectivityIncidentRefused"];
  names.forEach((n, i) => {
    expect(HOLDS[79 + i]?.name).toBe(n);
    expect(korean(HOLDS[79 + i]?.ko)).toBe(true);
    expect(hold).toContain(`${n} = ${79 + i},`);
  });
});

test("the hold table names the timestamp and roll holds", () => {
  expect(HOLDS[72]?.name).toBe("TimestampInvalid");
  expect(HOLDS[73]?.name).toBe("TimestampMismatch");
  expect(HOLDS[74]?.name).toBe("RollEventRefused");
  expect(HOLDS[75]?.name).toBe("RollCustodyMismatch");
  expect(HOLDS[76]?.name).toBe("ContestedCheckinInvalid");
  expect(HOLDS[77]?.name).toBe("ContestedLabelReused");
  expect(HOLDS[78]?.name).toBe("RollIncomplete");
});
