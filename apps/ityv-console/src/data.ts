// Types of what the console reads: the simulator's index (scenario
// metadata, all fictional names) and the WASM verifier's report. And the
// two small demonstration fixtures for screens whose data the ledger does
// not carry yet; each is labelled as a fixture wherever it is shown.

export interface Hold {
  code: number;
  name: string;
}

export interface IndexCandidate {
  name: string;
  party: string | null;
}

export interface IndexBox {
  id: string;
  label: string;
  style: string;
  unit: string;
  absentee: boolean;
  /** The simulator's paper (ground truth of the demo), for the sorter. */
  paper: { byCandidate: number[]; unsorted: number; total: number };
}

export interface IndexStation {
  id: string;
  label: string;
  kind: "early" | "election-day";
  booths: number;
  limit: number;
  openSlot: number;
  closeSlot: number;
  units: [string, string];
  boxes: IndexBox[];
}

export interface IndexElection {
  id: string;
  label: string;
  parties: { chamber: string; name: string }[];
  units: { id: string; label: string }[];
  styles: { id: string; label: string; candidates: IndexCandidate[] }[];
  stations: IndexStation[];
}

export interface IndexScenario {
  name: string;
  file: string;
  bytes: number;
  /** SHA3-512 of the bundle: its metadata applies only to these bytes. */
  sha3: string;
  set: "quick" | "full";
  group: "normal" | "attack";
  election: string;
  title: string;
  injected: string;
  shows: string;
  expected: { status: string; holds: Hold[] };
  slips: { code: string; note: string }[];
}

export interface SimIndex {
  format: string;
  note: string;
  set: "quick" | "full";
  seed: string;
  elections: IndexElection[];
  scenarios: IndexScenario[];
}

/** An integer of the report: a number up to 2^53 − 1, a decimal string
 * beyond (ityv-wasm writes larger values as strings). */
export type Int = number | string;

/** The integer as text, exactly. */
export function intText(v: Int | null | undefined): string {
  return v === null || v === undefined ? "-" : String(v);
}

/** The integer as an exact BigInt. */
export function intBig(v: Int): bigint {
  return BigInt(v);
}

/** The integer as a number for drawing and comparisons; large values
 * lose precision here, never in text. */
export function intNum(v: Int | null | undefined): number {
  return v === null || v === undefined ? 0 : Number(v);
}

/** A timestamp token the verifier took (ADR-0039): public fields only. */
export interface Token {
  frame: Int;
  authority: string;
  operator: string;
  kind: "Government" | "NonGovernment";
  genTime: Int;
  latest: Int;
  /** The time bucket of the latest instant (from the election epoch). */
  latestBucket: Int;
}

export interface Checkpoint {
  frame: Int;
  seq: Int;
  treeSize: Int;
  timeBucket: Int;
  fingerprint: string;
  root: string;
  /** The verifier's anchoring of this checkpoint (VC-115). */
  anchoring: { government: boolean; nonGovernment: boolean; operators: Int; satisfied: boolean };
  tokens: (Token & { inWindow: boolean })[];
}

/** One roll state and the custodians whose receipts agree (ADR-0040). */
export interface RollCustody {
  seq: Int;
  fingerprint: string;
  entryCount: Int;
  custodians: string[];
  pseudonymConfirmed: boolean;
  effective: boolean;
}

export interface RollReport {
  complete: boolean;
  quorum: Int;
  extracts: Int;
  freeze: RollCustody | null;
  amendments: (RollCustody & { number: Int; reason: string; authority: string })[];
  refused: { seq: Int; event: string; refusal: string }[];
  mismatches: { seq: Int; custodian: string }[];
  contestedFrames: Int;
  /** The frame of the first close at an election-day station (set, final count or box close). */
  pollClose: Int | null;
  /** Amendments recorded after the poll close (hold 78). */
  lateAmendments: Int[];
  /** Election-day stations of the last genesis state without an extract (hold 78). */
  missingExtracts: string[];
  holds: Hold[];
}

export interface BoxReport {
  box: string;
  station?: string;
  style?: string;
  unit?: string;
  profile?: string;
  phase: string;
  holds: Hold[];
  close: null | {
    paper: Int;
    records: Int;
    attested: Int;
    withoutRecord: Int;
    challenged: Int;
    quarantined: Int;
    visits: Int;
    envelopes: Int;
    stickers: Int;
  };
  accepted?: Int;
  rejected?: Int;
  unattested?: Int;
}

export interface UnitReport {
  style: string;
  unit: string;
  status: string;
  holds: Hold[];
  unitHolds: Hold[];
  boxes: string[];
  included: Int;
  excluded: Int;
  noRecord: Int;
  chunks: number;
  scope: Int | null;
  scopeProblems: string[];
  openings: { chunk: number; seq: Int; outcome: string }[];
  counts: Int[] | null;
  paper: Int | null;
  comparison: null | { agrees: boolean; firstBelow: Int | null; totalsAgree: boolean };
  complete: boolean;
  passed: boolean;
}

export interface ProgressPoint {
  slot: Int;
  checkins: Int;
  issued: Int;
  spoiled: Int;
  returned: Int;
  /** `null` with `overflow` when the boxes' sum does not fit in 64 bits. */
  sheetsIn: Int | null;
  out: Int | null;
  overflow?: boolean;
}

export interface StationProgress {
  station: string;
  limit: Int | null;
  firstSlot: Int | null;
  lastSlot: Int | null;
  ticks: Int;
  suspended: boolean;
  counterfoil: boolean;
  close: string;
  holds: Hold[];
  alarms: { slot: Int; alarm: string }[];
  checks: Int[];
  series: ProgressPoint[];
  overflow: boolean;
}

/** A record with its inclusion in the first verified checkpoint that
 * covers its frame (`ityv_ledger::verify_inclusion`, in the report). */
export interface RecordEntry {
  code: string;
  box: string;
  seq: Int;
  state: string;
  checkpoint: Int | null;
  treeSize?: Int;
  checkpointFingerprint?: string;
  included: boolean;
  pathLength?: Int;
}

export interface Report {
  format: string;
  bundleHash: string;
  bundleBytes: Int;
  error?: string;
  scenario?: string;
  pin?: string;
  pinHex?: string;
  /** No pin was given: the bundle's own was used. */
  pinFromBundle?: boolean;
  /** The pin used equals the bundle's (always when none was given). */
  pinEqualsBundle?: boolean;
  genesis?: { ok: boolean; error?: string; election?: string; states?: Int; boxes?: Int; stations?: Int };
  status?: string;
  holds?: Hold[];
  countOnly?: boolean;
  receiptScan?: boolean;
  stages?: { step: string; outcome: string }[];
  publications?: { anchors: string; board: string };
  ledger?: { treeSize: Int; root: string; events: Int };
  checkpoints?: {
    covered: Int;
    unchecked: Int;
    valid: Checkpoint[];
    findings: { frame: Int; kind: string }[];
    timestamps: { tokens: Int; unanswered: Int; refusals: { frame: Int; authority: string; problem: string }[] };
  };
  roll?: RollReport;
  boxes?: BoxReport[];
  units?: UnitReport[];
  refused?: { seq: Int; schema: string | null; stage: string; reason: string }[];
  progress?: StationProgress[];
  participation?: {
    complete: boolean;
    duplicates: Int;
    holds: Hold[];
    stations: { station: string; set: Int | null; count: Int | null; observers: Int | null; closed: boolean; holds: Hold[] }[];
  };
  disputes?: { list: { filing: string; type: string; box: string | null; status: string; unresolved: boolean; events: Int[]; decisions: Int }[] };
  records?: RecordEntry[];
  audit?: AuditReport;
}

/** What the audit did with one record: public information only. */
export interface AuditRecord {
  position?: Int;
  code: string;
  box: string | null;
  opened: Int | null;
  reconstruction: string | null;
  comparison: { seq: Int; code: number; name: string; transferMark: boolean } | null;
}

export interface StyleAuditReport {
  style: string;
  units: string[];
  frameCount: Int;
  frameRoot: string | null;
  freeze: Int | null;
  frameProblems: string[];
  rule: { ruleHash: string; riskLimitPpm: Int; beaconSource: string; beaconRound: Int } | null;
  rounds: { size: Int; threshold: Int; drawn: Int; compared: Int; nonzero: Int }[];
  phase: { kind: string; round: Int | null } | null;
  concluded: boolean;
  handCountFrom: Int | null;
  handCounts: { unit: string; seq: Int }[];
  sample: AuditRecord[];
  fullComparison: AuditRecord[];
  devices: {
    box: string;
    station: string;
    records: Int;
    compared: Int;
    codes: Int[];
    transferMarks: Int;
    fullComparisonFrom: Int | null;
    findings: Int[];
    followedUp: boolean;
    holds: Hold[];
  }[];
  reconstructions: { opened: Int; reconstructed: Int; mismatched: Int; notSupplied: Int };
  holds: Hold[];
}

export interface AuditReport {
  bundleHasObservation: boolean;
  observation: {
    fixture: boolean;
    round: Int;
    published: Int;
    outputHex: string;
    outputText: string | null;
    beaconValue: string | null;
  } | null;
  /** WITNESS_TIME_TOLERANCE + CLOCK_ERROR_BUCKETS + 1. */
  margin: Int;
  commit: {
    seq: Int;
    bucket: Int;
    dice: string;
    beaconSource: string;
    beaconRound: Int;
    binding: {
      frame: Int;
      seq: Int;
      bucket: Int;
      fingerprint: string;
      /** The tokens over it: recorded before the seed, and latest instant
       * before the observed publication bucket (null without an
       * observation). The decision is the verifier's seed refusal. */
      tokens: (Token & { beforeSeed: boolean; beforePublication: boolean | null })[];
    } | null;
  } | null;
  seed: { seq: Int; seed: string; beaconRound: Int; beaconConfirmed: boolean } | null;
  passed: boolean;
  allReconstructed: boolean;
  styles: StyleAuditReport[];
  refused: { seq: Int; event: string; refusal: string }[];
  stationMarks: { station: string; marks: Int; compared: Int }[];
  holds: Hold[];
}

/** 15-minute time bucket → "D일 HH:MM" of its start, counted from the
 * election epoch day (PROTOCOL §5.8), exact for any 64-bit bucket. */
export function bucketTime(bucket: Int): string {
  const b = BigInt(bucket);
  const minutes = Number((b * 15n) % 1440n);
  const day = (b * 15n) / 1440n;
  return `${day}일 ${String(Math.floor(minutes / 60)).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}`;
}

/** 10-minute slot → "HH:MM" of its start (slots count from the election
 * epoch day, PROTOCOL §5.8), exact for any 64-bit slot. */
export function slotTime(slot: Int): string {
  const minutes = Number((BigInt(slot) * 10n) % 1440n);
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

/** The day offset of a slot. */
export function slotDay(slot: Int): string {
  return String((BigInt(slot) * 10n) / 1440n);
}

/** The first 16 characters of a grouped 32-character fingerprint. */
export function fp16(grouped32: string): string {
  return grouped32.split(" ").slice(0, 4).join(" ");
}

// ---------------------------------------------------------------------
// Demonstration fixtures (labelled as such on screen). The ledger has no
// DeviceAttestation or UplinkSession events yet (verifier stages 11–12
// are not implemented), so these two screens use fixed demo values.

export type AttestReason = "sig" | "nonce" | "fp" | "build" | "timeout";

export interface AttestationFixture {
  label: string;
  device: string;
  kind: "dev.kind.scanner" | "dev.kind.unit";
  sig: boolean;
  nonce: boolean;
  fp: boolean;
  reason: AttestReason | null;
}

export const ATTESTATION_FIXTURES: AttestationFixture[] = [
  { label: "성공", device: "BOX-HB-1", kind: "dev.kind.scanner", sig: true, nonce: true, fp: true, reason: null },
  { label: "실패: 서명 오류", device: "BOX-HB-1", kind: "dev.kind.scanner", sig: false, nonce: true, fp: true, reason: "sig" },
  { label: "실패: 도전값 다름", device: "BOX-HB-1", kind: "dev.kind.scanner", sig: true, nonce: false, fp: true, reason: "nonce" },
  { label: "실패: 지문 다름", device: "BOX-HB-1", kind: "dev.kind.scanner", sig: true, nonce: true, fp: false, reason: "fp" },
  { label: "실패: 빌드 낮음", device: "ST-HB-1-UA", kind: "dev.kind.unit", sig: true, nonce: true, fp: false, reason: "build" },
  { label: "실패: 시간 초과", device: "ST-HB-1-UA", kind: "dev.kind.unit", sig: false, nonce: false, fp: false, reason: "timeout" },
];

export interface GatewayFixture {
  session: number;
  links: { link: "gw.link.scanner" | "dev.kind.unit"; frames: number; slotFrames: number; head: string }[];
  taps: { tap: "gw.tap.device" | "gw.tap.line"; inUse: boolean }[];
  lineUp: boolean;
}

export const GATEWAY_FIXTURE: GatewayFixture = {
  session: 1,
  links: [
    { link: "gw.link.scanner", frames: 1168, slotFrames: 16, head: "MZXW 6YTB OI3D QMRA" },
    { link: "dev.kind.unit", frames: 292, slotFrames: 4, head: "GEZD GNBV GY3T QOJQ" },
  ],
  taps: [
    { tap: "gw.tap.device", inUse: true },
    { tap: "gw.tap.line", inUse: false },
  ],
  lineUp: true,
};
