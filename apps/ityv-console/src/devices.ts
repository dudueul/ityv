// 기기 화면 시제품: every screen of SCREENS.md §1–§7 in a device frame
// with a state picker, zoom (1×, 1.5×, 2×) and high contrast. The labels
// "시제품" and the pickers sit outside the frame, never on the screen.

import {
  ATTESTATION_FIXTURES,
  GATEWAY_FIXTURE,
  type IndexScenario,
  type Report,
  type SimIndex,
  fp16,
  slotTime,
} from "./data";
import { type Identity, el, icon, screen } from "./render";
import {
  CHECKIN_STATES,
  CHECKIN_STATE_LABELS,
  CLERK_STATES,
  CLERK_STATE_LABELS,
  type ScreenModel,
  VOTER_STATES,
  VOTER_STATE_LABELS,
  type VoterInput,
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
  type AppCompare,
  type ClerkState,
  type CheckinState,
  type VoterState,
} from "./screens";
import { STRINGS } from "./strings";
import { fingerprintOf, inclusion, loadBundle, verifyBundle } from "./verifier";

export interface DeviceDef {
  id: string;
  title: string;
  section: string;
  program: string;
  version: string;
  build: number;
  components: { name: string; version: string; build: number }[];
  modules: string[];
  kind: "wide" | "tall";
  states: { id: string; label: string }[];
}

export const DEVICES: DeviceDef[] = [
  {
    id: "scanner-voter",
    title: "투함 스캐너: 유권자 화면",
    section: "SCREENS §1",
    program: "ityv 투함 스캐너",
    version: "0.1.0",
    build: 1,
    components: [
      { name: "해석 유닛", version: "0.1.0", build: 1 },
      { name: "커밋먼트 유닛", version: "0.1.0", build: 1 },
      { name: "각인기 제어기", version: "0.1.0", build: 1 },
    ],
    modules: ["M-P1", "M-P2"],
    kind: "wide",
    states: VOTER_STATES.map((s) => ({ id: s, label: VOTER_STATE_LABELS[s] })),
  },
  {
    id: "scanner-clerk",
    title: "투함 스캐너: 사무원·참관인 화면",
    section: "SCREENS §2",
    program: "ityv 투함 스캐너",
    version: "0.1.0",
    build: 1,
    components: [
      { name: "해석 유닛", version: "0.1.0", build: 1 },
      { name: "커밋먼트 유닛", version: "0.1.0", build: 1 },
      { name: "호스트", version: "0.1.0", build: 1 },
    ],
    modules: ["M-P1", "M-P2"],
    kind: "tall",
    states: CLERK_STATES.map((s) => ({ id: s, label: CLERK_STATE_LABELS[s] })),
  },
  {
    id: "checkin",
    title: "확인 장치: 사무원 화면",
    section: "SCREENS §3",
    program: "ityv 확인 장치",
    version: "0.1.0",
    build: 1,
    components: [
      { name: "신원 확인 단말", version: "0.1.0", build: 1 },
      { name: "카운터·가명 유닛", version: "0.1.0", build: 1 },
    ],
    modules: ["M-UA-P1", "M-UA-P2"],
    kind: "wide",
    states: CHECKIN_STATES.map((s) => ({ id: s, label: CHECKIN_STATE_LABELS[s] })),
  },
  {
    id: "sorter",
    title: "개표소 투표지 분류기 확장",
    section: "SCREENS §4",
    program: "ityv 분류기 확장",
    version: "0.1.0",
    build: 1,
    components: [{ name: "각인 판독기", version: "0.1.0", build: 1 }],
    modules: [],
    kind: "tall",
    states: [
      { id: "agrees", label: "등식 맞음" },
      { id: "differs", label: "등식 다름" },
      { id: "imprint", label: "각인 이상" },
    ],
  },
  {
    id: "gateway",
    title: "투표소 게이트웨이",
    section: "SCREENS §5",
    program: "ityv 투표소 게이트웨이",
    version: "0.1.0",
    build: 1,
    components: [{ name: "게이트웨이", version: "0.1.0", build: 1 }],
    modules: [],
    kind: "wide",
    states: [
      { id: "up", label: "회선 연결됨" },
      { id: "down", label: "회선 끊김" },
    ],
  },
  {
    id: "observer-attest",
    title: "참관인 앱: 현장 증명 결과",
    section: "SCREENS §6.1",
    program: "ityv 참관인 앱",
    version: "0.1.0",
    build: 1,
    components: [{ name: "참관인 앱", version: "0.1.0", build: 1 }],
    modules: [],
    kind: "tall",
    states: ATTESTATION_FIXTURES.map((a, i) => ({ id: String(i), label: a.label })),
  },
  {
    id: "observer-progress",
    title: "참관인 앱: 투표 진행과 경보",
    section: "SCREENS §6.2",
    program: "ityv 참관인 앱",
    version: "0.1.0",
    build: 1,
    components: [{ name: "참관인 앱", version: "0.1.0", build: 1 }],
    modules: [],
    kind: "tall",
    states: [
      { id: "progress", label: "진행" },
      { id: "check", label: "현장 확인" },
    ],
  },
  {
    id: "voter-app",
    title: "유권자 확인 앱",
    section: "SCREENS §7",
    program: "ityv 유권자 확인 앱",
    version: "0.1.0",
    build: 1,
    components: [{ name: "유권자 확인 앱", version: "0.1.0", build: 1 }],
    modules: [],
    kind: "tall",
    states: [
      { id: "match", label: "포함·대조 같음" },
      { id: "pending", label: "포함·대조 전" },
      { id: "differ", label: "포함·대조 다름" },
      { id: "uncovered", label: "체크포인트 밖" },
      { id: "missing", label: "찾지 못함" },
    ],
  },
];

/** The prototype identity of a device: fingerprints of the program, its
 * components and the string table (a prototype value, not a release
 * manifest's image hash). */
export async function identityOf(d: DeviceDef): Promise<Identity> {
  const group = (fp: string) => fp.replace(/(.{4})/g, "$1 ").trim();
  const table = JSON.stringify(STRINGS);
  const fp32 = group(await fingerprintOf(`prototype|${d.program}|${d.version}|${d.build}|${table}`));
  const components = await Promise.all(
    d.components.map(async (c) => ({
      ...c,
      fp32: group(await fingerprintOf(`prototype-component|${d.program}|${c.name}|${c.version}|${c.build}`)),
    })),
  );
  const modules = await Promise.all(
    d.modules.map(async (m) => ({ id: m, build: 1, fp32: group(await fingerprintOf(`prototype-module|${m}`)) })),
  );
  return { program: d.program, version: d.version, build: d.build, fp32, components, modules, boots: 3 };
}

export interface DeviceParams {
  device: string;
  state: string;
  zoom: number;
  contrast: boolean;
  detail: boolean;
  sheets: number;
  chosen: number[];
  scenario: string | null;
  station: string | null;
  box: string | null;
  slot: number | null;
  slip: number;
}

export function parseParams(device: string, query: URLSearchParams): DeviceParams {
  const def = DEVICES.find((d) => d.id === device) ?? DEVICES[0]!;
  const zoom = Number(query.get("zoom") ?? "1");
  return {
    device: def.id,
    state: query.get("state") ?? def.states[0]!.id,
    zoom: [1, 1.5, 2].includes(zoom) ? zoom : 1,
    contrast: query.get("hc") === "1",
    detail: query.get("detail") === "1",
    sheets: Math.max(1, Math.min(8, Number(query.get("n") ?? "3"))),
    chosen: (query.get("chosen") ?? "")
      .split(",")
      .filter(Boolean)
      .map(Number)
      .filter((x) => x >= 1 && x <= 8),
    scenario: query.get("scenario"),
    station: query.get("station"),
    box: query.get("box"),
    slot: query.get("slot") ? Number(query.get("slot")) : null,
    slip: Number(query.get("slip") ?? "0"),
  };
}

function href(p: DeviceParams, change: Partial<DeviceParams>): string {
  const q = { ...p, ...change };
  const s = new URLSearchParams();
  s.set("state", q.state);
  if (q.zoom !== 1) s.set("zoom", String(q.zoom));
  if (q.contrast) s.set("hc", "1");
  if (q.detail) s.set("detail", "1");
  if (q.sheets !== 3) s.set("n", String(q.sheets));
  if (q.chosen.length) s.set("chosen", q.chosen.join(","));
  if (q.scenario) s.set("scenario", q.scenario);
  if (q.station) s.set("station", q.station);
  if (q.box) s.set("box", q.box);
  if (q.slot !== null) s.set("slot", String(q.slot));
  if (q.slip) s.set("slip", String(q.slip));
  return `#/devices/${q.device}?${s.toString()}`;
}

/** Report cache by scenario name. */
const reports = new Map<string, Report>();

async function reportOf(s: IndexScenario): Promise<Report> {
  const cached = reports.get(s.name);
  if (cached) return cached;
  const r = await verifyBundle(await loadBundle(s.file));
  reports.set(s.name, r);
  return r;
}

let voterTimer: number | null = null;

export async function renderDevices(root: HTMLElement, index: SimIndex | null, p: DeviceParams): Promise<void> {
  const def = DEVICES.find((d) => d.id === p.device) ?? DEVICES[0]!;
  const identity = await identityOf(def);
  const normal = index?.scenarios.filter((s) => s.group === "normal") ?? [];
  const scenario =
    normal.find((s) => s.name === p.scenario) ??
    normal.find((s) => s.name === "local-clean") ??
    normal.find((s) => s.name === "quick-clean") ??
    null;
  const election = index?.elections.find((e) => e.id === scenario?.election) ?? null;
  const needsData = ["scanner-clerk", "checkin", "sorter", "observer-progress", "voter-app"].includes(def.id);
  let report: Report | null = null;
  if (needsData && scenario) {
    root.replaceChildren(el("p", { class: "busy" }, `검증기에서 자료를 읽는 중: ${scenario.title}`));
    report = await reportOf(scenario);
  }

  const go = (change: Partial<DeviceParams>) => {
    location.hash = href(p, change);
  };
  const nav = el(
    "nav",
    { class: "device-nav", "aria-label": "기기" },
    ...DEVICES.map((d) =>
      el("a", { href: href({ ...p, device: d.id, state: d.states[0]!.id, chosen: [], detail: false }, {}), class: d.id === def.id ? "on" : "" }, d.title),
    ),
  );

  // The model of the chosen state.
  let model: ScreenModel;
  let notes: (string | Node)[] = [];
  const stationList = election?.stations ?? [];
  const withAlarms = report?.progress?.find((s) => s.alarms.length > 0)?.station;
  const station =
    stationList.find((s) => s.id === p.station) ??
    stationList.find((s) => s.id === withAlarms) ??
    stationList[0] ??
    null;
  const boxList = election?.stations.flatMap((s) => s.boxes) ?? [];
  const box = boxList.find((b) => b.id === p.box) ?? boxList[0] ?? null;
  const boxReport = report?.boxes?.find((b) => b.box === box?.id) ?? null;
  const progress = report?.progress?.find((s) => s.station === station?.id) ?? null;
  switch (def.id) {
    case "scanner-voter": {
      const input: VoterInput = { state: p.state as VoterState, sheets: p.sheets, chosen: p.chosen };
      model = voterScreen(input);
      notes = ["화면 흐름(대기 → 읽는 중 → 결정 …)은 SCREENS §1 표의 TypeScript 모델이다. 장치 펌웨어는 아직 없다(M8)."];
      break;
    }
    case "scanner-clerk": {
      const c = boxReport?.close;
      const series = progress?.series ?? [];
      const slot = series.length ? series[series.length - 1]!.slot : 0;
      model = clerkScreen({
        state: p.state as ClerkState,
        box: box?.id ?? "BOX",
        absentee: box?.absentee ?? false,
        records: c?.records ?? boxReport?.accepted ?? 0,
        challenged: c?.challenged ?? 0,
        quarantined: c?.quarantined ?? 0,
        visits: c?.visits ?? 0,
        stickers: c?.stickers ?? 0,
        slot,
        framesSent: (series.length || 1) * 16,
        chambers: ["P1", "P2"],
      });
      notes = [
        `수는 검증기가 읽은 마감 기록(${scenario?.title ?? "자료 없음"})에서 왔다. 송신 프레임 수는 슬롯당 16(PROTOCOL §5.8)으로 계산한 시연 값, 패드 잔량·저널은 시연 값이다.`,
      ];
      break;
    }
    case "checkin": {
      const last = progress?.series[progress.series.length - 1];
      model = checkinScreen({ state: p.state as CheckinState, checkins: last?.checkins ?? 0, sheets: 1 });
      notes = [
        `누적 인원은 검증기가 읽은 진행 기록(${station?.label ?? "-"})의 마지막 확인 인원이다. 교부 장수는 현재 genesis의 한계로 1장(투표지 한 장)이다. SCREENS §3의 예는 7장.`,
      ];
      break;
    }
    case "sorter": {
      if (!box) {
        model = { blocks: [], buttons: [] };
        break;
      }
      const c = boxReport?.close;
      model = sorterScreen({
        box,
        records: c?.records ?? 0,
        fallback: c?.withoutRecord ?? 0,
        unimprinted: p.state === "imprint" ? 1 : 0,
        duplicates: p.state === "imprint" ? 1 : 0,
        paperDelta: p.state === "differs" ? 1 : 0,
      });
      notes = [
        "기록 수와 비상 투입 수는 검증기가 읽은 마감 기록에서 왔다. 칸별 종이 수는 시뮬레이터가 만든 종이(시연 자료)다. '등식 다름'과 '각인 이상'은 시연용으로 한 장을 더한 상태다.",
      ];
      break;
    }
    case "gateway": {
      model = gatewayScreen(GATEWAY_FIXTURE, 3 * 144 + 108, 7, p.state === "up");
      notes = ["시연 자료(고정값): 장부에 아직 UplinkSession 이벤트가 없다(검증기 11단계 미구현). 슬롯당 프레임 수는 PROTOCOL §5.8의 값."];
      break;
    }
    case "observer-attest": {
      const a = ATTESTATION_FIXTURES[Number(p.state)] ?? ATTESTATION_FIXTURES[0]!;
      model = attestationScreen(a, fp16(identity.fp32));
      notes = ["시연 자료(고정값): 장부에 아직 DeviceAttestation이 없다(검증기 12단계 미구현). 이유 코드마다 상태 하나."];
      break;
    }
    case "observer-progress": {
      if (p.state === "check") {
        model = checkForm();
        notes = ["시제품은 현장 확인을 서명하거나 보내지 않는다. 콘솔은 읽기 전용이다(ADR-0022, ADR-0038)."];
      } else if (progress) {
        const cp = report?.checkpoints?.valid.at(-1);
        model = progressScreen({
          station: progress,
          slot: p.slot ?? progress.lastSlot ?? 0,
          mirrorFp: cp ? fp16(cp.fingerprint) : null,
        });
        notes = [
          "진행 수와 경보는 WASM 검증기의 진행 기록 단계(ityv-verify verify_progress)가 계산했다. 미러 두 곳 대조는 시제품에서 같은 번들을 쓴다.",
        ];
      } else {
        model = { blocks: [], buttons: [] };
      }
      break;
    }
    default: {
      const slips = scenario?.slips ?? [];
      const slip = slips[p.slip] ?? slips[0];
      const code = slip?.code ?? "0".repeat(128);
      let record = report?.records?.find((r) => r.code === code) ?? null;
      let included = false;
      let checkpoint: number | null = null;
      if (record && p.state !== "missing") {
        const inc = await inclusion(record.seq);
        included = inc.included && p.state !== "uncovered";
        checkpoint = inc.checkpoint;
      }
      if (p.state === "missing") record = null;
      const cp = report?.checkpoints?.valid.find((c) => c.seq === checkpoint);
      const compare: AppCompare = p.state === "match" ? "match" : p.state === "differ" ? "differ" : "pending";
      model = voterAppScreen({
        code,
        record,
        included,
        checkpoint,
        checkpointFp: cp?.fingerprint ?? null,
        status: report?.status ?? "UNVERIFIED",
        compare,
      });
      notes = [
        "포함 여부는 WASM의 ityv-ledger 포함 증명(검증한 체크포인트 root에 대해)에서 왔다. 미러 두 곳·공표 지문 대조는 시제품에 없어 '대조 같음/다름/전'을 상태로 고른다. 대조 전에는 LOG_CONSISTENT를 보이지 않는다(PROTOCOL §5.7 4항).",
      ];
    }
  }

  const frame = el("div", { class: `frame frame-${def.kind}` });
  const draw = () => {
    frame.replaceChildren(
      screen({
        model,
        identity,
        zoom: p.zoom,
        contrast: p.contrast,
        detail: p.detail,
        kind: def.kind,
        onAction: (a) => {
          if (def.id === "scanner-voter") {
            const nextState = voterNext({ state: p.state as VoterState, sheets: p.sheets, chosen: p.chosen }, a);
            go({ state: nextState.state, chosen: nextState.chosen });
          }
        },
        onCell: (n) => {
          if (def.id === "scanner-voter" && p.state === "choose") {
            const nextState = voterNext({ state: "choose", sheets: p.sheets, chosen: p.chosen }, `toggle:${n}`);
            go({ chosen: nextState.chosen });
          }
        },
        onDetail: (open) => go({ detail: open }),
      }),
    );
  };
  draw();
  if (voterTimer !== null) {
    clearTimeout(voterTimer);
    voterTimer = null;
  }
  if (def.id === "scanner-voter" && p.detail) {
    // SCREENS §0.1: opened from the voter screen, the detail view returns
    // to the screen after 10 seconds.
    voterTimer = window.setTimeout(() => go({ detail: false }), 10_000);
  }

  // Controls outside the frame.
  const picker = el(
    "div",
    { class: "picker", role: "group", "aria-label": "상태" },
    ...def.states.map((s) =>
      el("a", { href: href(p, { state: s.id, detail: false }), class: s.id === p.state ? "on" : "", "data-state": s.id }, s.label),
    ),
  );
  const zooms = el(
    "div",
    { class: "picker", role: "group", "aria-label": "확대" },
    ...[1, 1.5, 2].map((z) => el("a", { href: href(p, { zoom: z }), class: z === p.zoom ? "on" : "" }, `${z}×`)),
    el("a", { href: href(p, { contrast: !p.contrast }), class: p.contrast ? "on" : "" }, "고대비"),
    el("a", { href: href(p, { detail: !p.detail }), class: p.detail ? "on" : "" }, "소프트웨어 확인 열기"),
  );
  const extra: Node[] = [];
  let keys: Node | null = null;
  if (def.id === "scanner-voter") {
    extra.push(
      el(
        "div",
        { class: "picker", role: "group", "aria-label": "방문 장수" },
        el("span", {}, "방문의 투표지 장수"),
        ...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => el("a", { href: href(p, { sheets: n, chosen: [] }), class: n === p.sheets ? "on" : "" }, String(n))),
      ),
    );
    keys = tactile(p, go);
  }
  if (needsData && index) {
    extra.push(
      el(
        "label",
        { class: "datapick" },
        "자료(시뮬레이터 번들): ",
        (() => {
          const sel = el("select", {});
          for (const s of normal) {
            const o = el("option", { value: s.name }, s.title);
            if (s.name === scenario?.name) o.selected = true;
            sel.append(o);
          }
          sel.addEventListener("change", () => go({ scenario: sel.value, station: null, box: null, slot: null, slip: 0 }));
          return sel;
        })(),
      ),
    );
  }
  if ((def.id === "observer-progress" || def.id === "checkin") && election) {
    extra.push(
      el(
        "label",
        { class: "datapick" },
        "투표소: ",
        (() => {
          const sel = el("select", {});
          for (const s of election.stations) {
            const o = el("option", { value: s.id }, s.label);
            if (s.id === station?.id) o.selected = true;
            sel.append(o);
          }
          sel.addEventListener("change", () => go({ station: sel.value, slot: null }));
          return sel;
        })(),
      ),
    );
  }
  if (def.id === "observer-progress" && progress && progress.firstSlot !== null && progress.lastSlot !== null) {
    const range = el("input", {
      type: "range",
      min: String(progress.firstSlot),
      max: String(progress.lastSlot),
      value: String(p.slot ?? progress.lastSlot),
      "aria-label": "칸(10분 슬롯)",
    });
    range.addEventListener("change", () => go({ slot: Number(range.value) }));
    extra.push(el("label", { class: "datapick" }, `칸 ${slotTime(p.slot ?? progress.lastSlot)} `, range));
  }
  if ((def.id === "scanner-clerk" || def.id === "sorter") && election) {
    extra.push(
      el(
        "label",
        { class: "datapick" },
        "투표함: ",
        (() => {
          const sel = el("select", {});
          for (const st of election.stations) {
            for (const b of st.boxes) {
              const o = el("option", { value: b.id }, `${st.label} · ${b.label}`);
              if (b.id === box?.id) o.selected = true;
              sel.append(o);
            }
          }
          sel.addEventListener("change", () => go({ box: sel.value }));
          return sel;
        })(),
      ),
    );
  }
  if (def.id === "voter-app" && scenario) {
    extra.push(
      el(
        "label",
        { class: "datapick" },
        "쪽지(시연용 추적코드): ",
        (() => {
          const sel = el("select", {});
          scenario.slips.forEach((s, i) => {
            const o = el("option", { value: String(i) }, s.note);
            if (i === p.slip) o.selected = true;
            sel.append(o);
          });
          sel.addEventListener("change", () => go({ slip: Number(sel.value) }));
          return sel;
        })(),
      ),
    );
  }

  root.replaceChildren(
    el(
      "div",
      { class: "devices" },
      nav,
      el(
        "section",
        { class: "device" },
        el("h2", {}, def.title, el("span", { class: "proto" }, "시제품"), el("span", { class: "ref" }, def.section)),
        el("div", { class: "controls" }, picker, zooms, ...extra),
        frame,
        keys,
        el("div", { class: "notes" }, ...notes.map((n) => el("p", {}, n))),
        el(
          "p",
          { class: "notes" },
          "음성 안내는 헤드폰 단자로만 나간다(SCREENS §0.3). 시제품은 소리를 내지 않는다. 신원 줄의 지문은 시제품의 문구 표와 이름에서 계산한 값이며 릴리스 목록의 이미지 해시가 아니다.",
        ),
      ),
    ),
  );
}

/** The scanner's tactile buttons (SCREENS §0.3): insert (round), choose
 * (square), positions 1–8, software check, listen again. Outside the
 * screen; they drive the same model as the on-screen buttons. */
function tactile(p: DeviceParams, go: (c: Partial<DeviceParams>) => void): HTMLElement {
  const press = (action: string) => {
    if (action === "software") return go({ detail: !p.detail });
    if (action === "repeat") return;
    const state = p.state as VoterState;
    if (action === "insertKey") {
      if (state === "decide") return go(voterNext({ state, sheets: p.sheets, chosen: p.chosen }, "castAll"));
      if (state === "choose") return go(voterNext({ state, sheets: p.sheets, chosen: p.chosen }, "challenge"));
      return;
    }
    if (action === "chooseKey") {
      if (state === "decide") return go(voterNext({ state, sheets: p.sheets, chosen: p.chosen }, "choose"));
      return;
    }
    const m = /^pos:(\d)$/.exec(action);
    if (m) {
      const n = voterNext({ state, sheets: p.sheets, chosen: p.chosen }, `toggle:${m[1]}`);
      go({ chosen: n.chosen });
    }
  };
  const key = (label: string, shape: string, action: string, dots: string) => {
    const b = el(
      "button",
      { class: `tkey ${shape}`, "data-action": action, "aria-label": label },
      el("span", { class: "braille", "aria-hidden": "true" }, dots),
      el("span", {}, label),
    );
    b.addEventListener("click", () => press(action));
    return b;
  };
  return el(
    "div",
    { class: "tactile", role: "group", "aria-label": "촉각 단추(화면 밖)" },
    el("span", { class: "tactile-title" }, icon("info"), "촉각 단추"),
    key("넣기", "round", "insertKey", "⠿"),
    key("확인할 장 고르기", "square", "chooseKey", "⠛"),
    ...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => key(`위치 ${n}`, "small", `pos:${n}`, "⠂")),
    key("소프트웨어 확인", "small", "software", "⠎"),
    key("다시 듣기", "small", "repeat", "⠗"),
  );
}
