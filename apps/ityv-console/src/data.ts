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

export interface Checkpoint {
  frame: number;
  seq: number;
  treeSize: number;
  timeBucket: number;
  fingerprint: string;
  root: string;
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
    paper: number;
    records: number;
    attested: number;
    withoutRecord: number;
    challenged: number;
    quarantined: number;
    visits: number;
    envelopes: number;
    stickers: number;
  };
  accepted?: number;
  rejected?: number;
  unattested?: number;
}

export interface UnitReport {
  style: string;
  unit: string;
  status: string;
  holds: Hold[];
  unitHolds: Hold[];
  boxes: string[];
  included: number;
  excluded: number;
  noRecord: number;
  chunks: number;
  scope: number | null;
  scopeProblems: string[];
  openings: { chunk: number; seq: number; outcome: string }[];
  counts: number[] | null;
  paper: number | null;
  comparison: null | { agrees: boolean; firstBelow: number | null; totalsAgree: boolean };
  complete: boolean;
  passed: boolean;
}

export interface ProgressPoint {
  slot: number;
  checkins: number;
  issued: number;
  spoiled: number;
  returned: number;
  sheetsIn: number;
  out: number | null;
}

export interface StationProgress {
  station: string;
  limit: number | null;
  firstSlot: number | null;
  lastSlot: number | null;
  ticks: number;
  suspended: boolean;
  counterfoil: boolean;
  close: string;
  holds: Hold[];
  alarms: { slot: number; alarm: string }[];
  checks: number[];
  series: ProgressPoint[];
}

export interface RecordEntry {
  code: string;
  box: string;
  seq: number;
  state: string;
  checkpoint: number | null;
}

export interface Report {
  format: string;
  error?: string;
  scenario?: string;
  pin?: string;
  pinFromBundle?: boolean;
  genesis?: { ok: boolean; error?: string; election?: string; states?: number; boxes?: number; stations?: number };
  status?: string;
  holds?: Hold[];
  countOnly?: boolean;
  receiptScan?: boolean;
  stages?: { step: string; outcome: string }[];
  publications?: { anchors: string; board: string };
  ledger?: { treeSize: number; root: string; events: number };
  checkpoints?: { covered: number; unchecked: number; valid: Checkpoint[]; findings: { frame: number; kind: string }[] };
  boxes?: BoxReport[];
  units?: UnitReport[];
  refused?: { seq: number; schema: string | null; stage: string; reason: string }[];
  progress?: StationProgress[];
  participation?: {
    complete: boolean;
    duplicates: number;
    holds: Hold[];
    stations: { station: string; set: number | null; count: number | null; observers: number | null; closed: boolean; holds: Hold[] }[];
  };
  disputes?: { list: { filing: string; type: string; box: string | null; status: string; unresolved: boolean; events: number[]; decisions: number }[] };
  records?: RecordEntry[];
}

export interface Inclusion {
  seq: number;
  included: boolean;
  checkpoint: number | null;
  checkpointFrame?: number;
  treeSize?: number;
  pathLength?: number;
  root?: string;
}

/** 10-minute slot → "HH:MM" of its start (slots count from the election
 * epoch day, PROTOCOL §5.8). */
export function slotTime(slot: number): string {
  const minutes = (slot * 10) % (24 * 60);
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

/** The day offset of a slot. */
export function slotDay(slot: number): number {
  return Math.floor((slot * 10) / (24 * 60));
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
  kind: string;
  sig: boolean;
  nonce: boolean;
  fp: boolean;
  reason: AttestReason | null;
}

export const ATTESTATION_FIXTURES: AttestationFixture[] = [
  { label: "성공", device: "BOX-HB-1", kind: "투함 스캐너", sig: true, nonce: true, fp: true, reason: null },
  { label: "실패: 서명 오류", device: "BOX-HB-1", kind: "투함 스캐너", sig: false, nonce: true, fp: true, reason: "sig" },
  { label: "실패: 도전값 다름", device: "BOX-HB-1", kind: "투함 스캐너", sig: true, nonce: false, fp: true, reason: "nonce" },
  { label: "실패: 지문 다름", device: "BOX-HB-1", kind: "투함 스캐너", sig: true, nonce: true, fp: false, reason: "fp" },
  { label: "실패: 빌드 낮음", device: "ST-HB-1-UA", kind: "카운터·가명 유닛", sig: true, nonce: true, fp: false, reason: "build" },
  { label: "실패: 시간 초과", device: "ST-HB-1-UA", kind: "카운터·가명 유닛", sig: false, nonce: false, fp: false, reason: "timeout" },
];

export interface GatewayFixture {
  session: number;
  links: { link: string; frames: number; slotFrames: number; head: string }[];
  taps: { tap: string; inUse: boolean }[];
  lineUp: boolean;
}

export const GATEWAY_FIXTURE: GatewayFixture = {
  session: 1,
  links: [
    { link: "스캐너", frames: 1168, slotFrames: 16, head: "MZXW 6YTB OI3D QMRA" },
    { link: "카운터·가명 유닛", frames: 292, slotFrames: 4, head: "GEZD GNBV GY3T QOJQ" },
  ],
  taps: [
    { tap: "장치 쪽 탭", inUse: true },
    { tap: "회선 쪽 탭", inUse: false },
  ],
  lineUp: true,
};
