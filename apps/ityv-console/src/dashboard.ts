// 검증 대시보드: pick a scenario bundle or drop a bundle file; the
// browser runs the real verifier (ityv-verify through ityv-wasm, in a
// worker) and shows what it found. Nothing here computes a status: every
// status, hold, stage, checkpoint fingerprint, inclusion and refusal is
// the verifier's. The page is read-only and sends nothing anywhere.
//
// Every request gets a ticket; a result whose ticket is not the latest is
// dropped, and what is shown (file name, scenario, report) always comes
// from one result object. A scenario's metadata (expectation, injected
// text, names, demo tracking codes) is attached to a report only when the
// report's bundle hash is the one index.json records for it.
//
// The audit card shows only public information: the drawn records'
// tracking codes, boxes and comparisons, never a restricted opening (no
// bundle holds one). The beacon observation the verifier is handed is the
// simulator's fixture data and is labelled so; the viewer can verify
// without it.

import type { AuditRecord, AuditReport, Hold, IndexElection, IndexScenario, Int, Report, RollCustody, SimIndex, StationProgress, StyleAuditReport, Token, UplinkStation } from "./data";
import { bucketTime, intNum, intText, slotDay, slotTime } from "./data";
import { el, icon, rungIcon } from "./render";
import { Cancelled, MAX_BUNDLE_BYTES, VerifierClient, loadBundle, parsePin, wasmSha256 } from "./verifier";
import {
  ALARMS,
  AUDIT_EVENTS,
  AUDIT_REFUSALS,
  COMPARISON_CODES,
  DEVICE_CLASSES,
  HOLDS,
  HOLD_MEANS,
  HOLD_WORD,
  INCIDENT_KINDS,
  INCIDENT_PROBLEMS,
  LADDER,
  LEGAL_MEANS,
  LEGAL_WORD,
  LINK_PROBLEMS,
  MANIFEST_PROBLEMS,
  NOT_REACHABLE,
  OUTCOMES,
  PHASES,
  ROLL_REASONS,
  SESSION_PROBLEMS,
  STAGES,
  STEPS,
  TSA_KINDS,
} from "./vocab";

interface Result {
  ticket: number;
  /** What was verified: the file name or the scenario's file. */
  fileName: string;
  /** The scenario whose bundle hash matches the report's, if any. */
  scenario: IndexScenario | null;
  report: Report;
  elapsed: number;
  /** A copy of the bytes, to verify again under another pin. */
  bytes: ArrayBuffer;
  /** The pin given from outside, if any. */
  pin?: Uint8Array;
  /** Whether the bundle's beacon observation was handed to the verifier. */
  beacon: boolean;
}

interface SelfTestRow {
  name: string;
  expected: string;
  actual: string;
  ok: boolean;
}

interface State {
  index: SimIndex | null;
  ticket: number;
  result: Result | null;
  busy: string | null;
  /** The scenario being fetched or verified, if any. */
  pending: string | null;
  error: string | null;
  pin: string;
  station: string | null;
  lookup: { code: string; out: string };
  selftest: { rows: SelfTestRow[]; running: boolean; stopped: boolean; ticket: number } | null;
  wasm: string | null;
  /** Hand the verifier the bundle's beacon observation (fixture data). */
  beacon: boolean;
}

const st: State = {
  index: null,
  ticket: 0,
  result: null,
  busy: null,
  pending: null,
  error: null,
  pin: "",
  station: null,
  lookup: { code: "", out: "" },
  selftest: null,
  wasm: null,
  beacon: true,
};

/** The dashboard's verifier and the self-test's, separate workers. */
const client = new VerifierClient();
const testClient = new VerifierClient();

let rootEl: HTMLElement | null = null;
let active = false;
/** The self-test card now on the page; the self-test redraws only it, so
 * its progress never resets what the viewer is typing elsewhere. */
let selfEl: HTMLElement | null = null;

function rerender(): void {
  if (rootEl && active) draw(rootEl);
}

function redrawSelfTest(): void {
  if (!active || !selfEl) return;
  const fresh = selfTestCard();
  selfEl.replaceWith(fresh);
  selfEl = fresh;
}

export function renderDashboard(root: HTMLElement, index: SimIndex | null, scenario: string | null): void {
  rootEl = root;
  active = true;
  st.index = index;
  if (st.wasm === null) {
    st.wasm = "";
    void wasmSha256().then((h) => {
      st.wasm = h ?? "읽지 못함";
      rerender();
    });
  }
  if (scenario && index) {
    const s = index.scenarios.find((x) => x.name === scenario);
    const shown = st.result?.scenario?.name === s?.name && st.result?.fileName === s?.file;
    if (s && !shown && st.pending !== s.name) {
      void pick(s);
      return;
    }
  }
  draw(root);
}

/** Leaving the dashboard: stop the self-test and any verification. */
export function leaveDashboard(): void {
  active = false;
  stopSelfTest();
  if (st.busy !== null) {
    // The request in flight is abandoned; coming back starts afresh.
    st.ticket += 1;
    st.busy = null;
    st.pending = null;
  }
  client.reset();
}

function stopSelfTest(): void {
  if (st.selftest?.running) {
    st.selftest.running = false;
    st.selftest.stopped = true;
    st.selftest.ticket += 1;
  }
  testClient.reset();
}

/** Starts a new request: cancels the one in flight, clears the shown
 * result. */
function begin(busy: string, pending: string | null = null): number {
  client.reset();
  st.ticket += 1;
  st.result = null;
  st.error = null;
  st.busy = busy;
  st.pending = pending;
  st.lookup = { code: "", out: "" };
  rerender();
  return st.ticket;
}

function fail(ticket: number, e: unknown): void {
  if (ticket !== st.ticket || e instanceof Cancelled) return;
  st.result = null;
  st.busy = null;
  st.pending = null;
  st.error = String(e instanceof Error ? e.message : e);
  rerender();
}

/** The scenario of the index whose bundle hash is `hash`. */
function scenarioOf(hash: string): IndexScenario | null {
  return st.index?.scenarios.find((s) => s.sha3 === hash) ?? null;
}

async function verifyInto(ticket: number, fileName: string, bytes: ArrayBuffer, pin?: Uint8Array): Promise<void> {
  const copy = bytes.slice(0);
  const start = performance.now();
  const beacon = st.beacon;
  const report = await client.verify(bytes, pin, beacon);
  if (ticket !== st.ticket) return;
  st.result = {
    ticket,
    fileName,
    scenario: scenarioOf(report.bundleHash),
    report,
    elapsed: performance.now() - start,
    bytes: copy,
    pin,
    beacon,
  };
  st.busy = null;
  st.pending = null;
  st.error = report.error ? `번들을 읽지 못했다: ${report.error}` : null;
  rerender();
}

async function pick(s: IndexScenario): Promise<void> {
  const ticket = begin(`${s.title} 번들을 받아 검증하는 중 (${(s.bytes / 1e6).toFixed(1)} MB)…`, s.name);
  try {
    const bytes = await loadBundle(s.file);
    if (ticket !== st.ticket) return;
    await verifyInto(ticket, s.file, bytes);
  } catch (e) {
    fail(ticket, e);
  }
}

async function loadFile(f: File): Promise<void> {
  const ticket = begin(`${f.name} 검증 중…`);
  try {
    if (f.size > MAX_BUNDLE_BYTES) throw new Error(`파일이 ${MAX_BUNDLE_BYTES / 1024 / 1024} MB보다 크다`);
    const bytes = await f.arrayBuffer();
    if (ticket !== st.ticket) return;
    await verifyInto(ticket, f.name, bytes);
  } catch (e) {
    fail(ticket, e);
  }
}

async function repin(pinText: string): Promise<void> {
  const prev = st.result;
  st.pin = pinText;
  const pin = parsePin(pinText);
  if (!prev) return;
  if (!pin) {
    st.error = "핀은 16진 128자여야 한다.";
    rerender();
    return;
  }
  const ticket = begin("다른 핀으로 검증 중…");
  try {
    await verifyInto(ticket, prev.fileName, prev.bytes.slice(0), pin);
  } catch (e) {
    fail(ticket, e);
  }
}

/** Verifies the shown bundle again, with or without its beacon
 * observation, under the same pin. */
async function setBeacon(on: boolean): Promise<void> {
  st.beacon = on;
  const prev = st.result;
  if (!prev) {
    rerender();
    return;
  }
  const ticket = begin(on ? "비콘 관찰을 넘겨 다시 검증 중…" : "비콘 관찰 없이 다시 검증 중…");
  try {
    await verifyInto(ticket, prev.fileName, prev.bytes.slice(0), prev.pin);
  } catch (e) {
    fail(ticket, e);
  }
}

function holdList(holds: Hold[]): HTMLElement {
  if (holds.length === 0) return el("span", { class: "muted" }, "없음");
  return el("span", {}, holds.map((h) => `${h.code} ${h.name}`).join(", "));
}

function sameHolds(a: Hold[], b: Hold[]): boolean {
  return a.length === b.length && a.every((h, i) => h.code === b[i]?.code);
}

/** A status word with its rung's own icon. Until a pin from outside the
 * bundle was used, the badge says so and shows no check mark. */
function statusBadge(word: string, outsidePin: boolean): HTMLElement {
  return el(
    "span",
    { class: `status st-${word}`, "data-status": word },
    rungIcon(word),
    el("span", {}, word),
    outsidePin && word !== HOLD_WORD && word !== "UNVERIFIED" ? icon("ok", "바깥 핀으로 검증함") : null,
    outsidePin ? null : el("span", { class: "pinnote" }, " (번들에 든 핀으로)"),
  );
}

function outsidePin(r: Report): boolean {
  return r.pinFromBundle === false;
}

function picker(index: SimIndex | null): HTMLElement {
  const box = el("section", { class: "card picker-card" }, el("h2", {}, "시나리오"));
  if (!index) {
    box.append(
      el("p", { class: "muted" }, "시뮬레이터 번들 목록(bundles/index.json)을 찾지 못했다. `bun run dev`가 먼저 시뮬레이터를 돌린다."),
    );
  }
  const shown = st.result?.scenario?.name ?? null;
  const group = (g: "normal" | "attack", title: string) => {
    const list = index?.scenarios.filter((s) => s.group === g) ?? [];
    return el(
      "div",
      { class: "group" },
      el("h3", {}, title, el("span", { class: "muted" }, ` ${list.length}개`)),
      el(
        "ul",
        { class: "scen" },
        ...list.map((s) =>
          el(
            "li",
            {},
            el(
              "a",
              {
                href: `#/dashboard?scenario=${encodeURIComponent(s.name)}`,
                class: shown === s.name ? "on" : "",
                "data-scenario": s.name,
              },
              el("span", { class: "t" }, s.title),
              el("span", { class: "x" }, `기대: ${s.expected.status}${s.set === "full" ? " · 큰 번들" : ""}`),
            ),
          ),
        ),
      ),
    );
  };
  box.append(group("normal", "정상 선거"), group("attack", "공격·장애"));
  const input = el("input", { type: "file", accept: ".ityvb,application/octet-stream", "aria-label": "번들 파일" });
  input.addEventListener("change", () => {
    const f = input.files?.[0];
    if (f) void loadFile(f);
  });
  const drop = el(
    "div",
    { class: "drop", tabindex: "0" },
    icon("paper"),
    el(
      "span",
      {},
      `번들 파일(.ityvb, ${MAX_BUNDLE_BYTES / 1024 / 1024} MB까지)을 여기 놓거나 고르세요. 파일은 이 브라우저 밖으로 나가지 않는다. `,
    ),
    input,
  );
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const f = e.dataTransfer?.files[0];
    if (f) void loadFile(f);
  });
  box.append(drop);
  return box;
}

function pinCard(r: Report): HTMLElement {
  const input = el("input", {
    type: "text",
    placeholder: "관보에서 받은 genesis 핀(16진 128자)",
    "aria-label": "genesis 핀",
    spellcheck: "false",
  });
  input.value = st.pin;
  const btn = el("button", { class: "btn", "data-action": "repin" }, "이 핀으로 다시 검증");
  btn.addEventListener("click", () => void repin(input.value));
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "신뢰하는 genesis 핀"),
    el(
      "p",
      {},
      "검증기는 호출자가 준 핀만 믿는다. 지금 쓴 핀의 지문: ",
      el("code", {}, r.pin ?? "-"),
      r.pinFromBundle ? " (번들에 든 핀)" : r.pinEqualsBundle ? " (직접 넣은 핀, 번들에 든 핀과 같음)" : " (직접 넣은 핀, 번들에 든 핀과 다름)",
    ),
    el(
      "p",
      { class: "warnline" },
      icon("warn"),
      "번들에 든 핀은 번들과 같은 곳에서 왔다. 그 핀으로 낸 상태는 '이 번들이 스스로와 맞는다'는 뜻일 뿐이다. 실제 검증에서는 관보·위원회·지정 검증자·인쇄물처럼 다른 출처에서 받은 핀을 넣어야 한다(PROTOCOL §14, VC-005).",
    ),
    el("div", { class: "pinrow" }, input, btn),
    r.pinHex
      ? el("details", {}, el("summary", {}, "지금 쓴 핀(16진)"), el("code", { class: "fp" }, r.pinHex))
      : null,
  );
}

function ladder(r: Report): HTMLElement {
  const current = r.status ?? "UNVERIFIED";
  const held = current === HOLD_WORD;
  const outside = outsidePin(r);
  const rungs = el(
    "ol",
    { class: "ladder" },
    ...[...LADDER].reverse().map((rung) => {
      const on = rung.word === current;
      return el(
        "li",
        { class: on ? "on" : "" },
        rungIcon(rung.word),
        el("span", { class: "word" }, ` ${rung.word}`),
        on ? el("span", { class: "here" }, "← 지금 상태") : null,
        el("div", { class: "means" }, rung.means),
      );
    }),
  );
  const rung = LADDER.find((l) => l.word === current);
  return el(
    "section",
    { class: "card hero" },
    el("h2", {}, "상태"),
    el("div", { class: "hero-status", "data-testid": "status" }, statusBadge(current, outside)),
    held
      ? el("p", { class: "warnline" }, icon("warn"), HOLD_MEANS)
      : rung
        ? el("p", { class: "notmeans" }, el("strong", {}, "이 상태가 뜻하지 않는 것: "), rung.not)
        : null,
    outside ? null : el("p", { class: "warnline" }, icon("info"), "이 상태는 번들에 든 핀으로 낸 것이다. 바깥에서 받은 핀으로 다시 검증하기 전에는 확인 표시를 붙이지 않는다."),
    r.countOnly ? el("p", { class: "warnline" }, icon("warn"), "BALLOT_MARK 권한이 없거나 수령 스캔 기록이 있어 수만 맞춰 볼 수 있다.") : null,
    el("h3", {}, "상태 사다리"),
    rungs,
    el("p", { class: "notmeans" }, el("strong", {}, "아직 닿지 않는 것: "), NOT_REACHABLE),
    el(
      "div",
      { class: "side" },
      el("p", {}, rungIcon(HOLD_WORD), el("strong", {}, ` ${HOLD_WORD}`), held ? " (지금 상태)" : "", ": ", HOLD_MEANS),
      el("p", {}, rungIcon(LEGAL_WORD), el("strong", {}, ` ${LEGAL_WORD}`), ": ", LEGAL_MEANS),
    ),
  );
}

function electionBanner(r: Report): HTMLElement | null {
  const id = r.genesis?.election ?? "";
  return el(
    "section",
    { class: id.startsWith("SIM-") ? "banner" : "card wide", "data-testid": "election" },
    id.startsWith("SIM-") ? icon("warn") : icon("info"),
    el(
      "div",
      {},
      el("strong", {}, `검증한 선거: ${id || "(genesis를 받지 못함)"}`),
      id.startsWith("SIM-")
        ? el(
            "p",
            {},
            "합성 선거다. 모든 키는 공개된 고정 씨앗에서 유도한 시험 키라서 누구나 같은 서명을 만들 수 있다. 실제 선거의 증거가 아니다.",
          )
        : null,
    ),
  );
}

function expectedCard(s: IndexScenario, r: Report): HTMLElement {
  const ok = s.expected.status === r.status && sameHolds(s.expected.holds, r.holds ?? []);
  return el(
    "section",
    { class: `card expect ${ok ? "agree" : "mismatch"}`, "data-testid": "expected" },
    el(
      "h2",
      {},
      "기대와 실제",
      el("span", { class: `flag ${ok ? "ok" : "bad"}`, "data-testid": "agreement" }, icon(ok ? "ok" : "fail"), ok ? " 같음" : " 불일치"),
    ),
    el("p", { class: "muted" }, `시나리오 ${s.name}: 번들의 SHA3-512가 index.json의 값과 같아 이 설명을 붙였다.`),
    el("p", {}, el("strong", {}, "주입한 것: "), s.injected),
    el("p", {}, el("strong", {}, "검증기가 보여야 할 것: "), s.shows),
    el(
      "table",
      {},
      el("thead", {}, el("tr", {}, el("th", {}, ""), el("th", {}, "상태"), el("th", {}, "보류 사유"))),
      el(
        "tbody",
        {},
        el("tr", {}, el("th", {}, "기대(시뮬레이터)"), el("td", {}, s.expected.status), el("td", {}, holdList(s.expected.holds))),
        el("tr", {}, el("th", {}, "실제(WASM 검증기)"), el("td", {}, r.status ?? "-"), el("td", {}, holdList(r.holds ?? []))),
      ),
    ),
    ok
      ? null
      : r.audit?.bundleHasObservation && r.audit.observation === null
        ? el("p", { class: "warnline" }, icon("info"), "기대는 비콘 관찰을 넘긴 검증의 값이다. 지금은 비콘 관찰 없이 검증했으므로 감사가 끝날 수 없다.")
        : el("p", { class: "warnline" }, icon("warn"), "시뮬레이터의 기대와 검증기의 판정이 다르다. 어느 쪽이 틀렸는지 확인해야 한다."),
  );
}

function holdsCard(r: Report): HTMLElement {
  const holds = r.holds ?? [];
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "보류 사유", el("span", { class: "muted" }, ` ${holds.length}개`)),
    holds.length === 0
      ? el("p", { class: "muted" }, "보류 사유 없음.")
      : el(
          "table",
          {},
          el("thead", {}, el("tr", {}, el("th", {}, "코드"), el("th", {}, "이름"), el("th", {}, "검증기가 찾은 것"))),
          el(
            "tbody",
            {},
            ...holds.map((h) =>
              el("tr", {}, el("td", { class: "num" }, String(h.code)), el("td", {}, el("code", {}, h.name)), el("td", {}, HOLDS[h.code]?.ko ?? "")),
            ),
          ),
        ),
  );
}

function stagesCard(r: Report): HTMLElement {
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "단계"),
    el(
      "table",
      {},
      el("thead", {}, el("tr", {}, el("th", {}, "단계"), el("th", {}, "결과"))),
      el(
        "tbody",
        {},
        ...(r.stages ?? []).map((s) =>
          el(
            "tr",
            {},
            el("td", {}, STEPS[s.step] ?? s.step),
            el(
              "td",
              { class: `oc oc-${s.outcome}` },
              icon(s.outcome === "PASSED" ? "ok" : s.outcome === "FAILED" ? "fail" : "wait"),
              ` ${OUTCOMES[s.outcome] ?? s.outcome}`,
            ),
          ),
        ),
      ),
    ),
    el(
      "p",
      { class: "muted" },
      `앵커: ${r.publications?.anchors ?? "-"} · 공개원장 공표 기한: ${r.publications?.board ?? "-"} · 프레임 ${intText(r.ledger?.treeSize ?? 0)}개 · 장부 root 지문 `,
      el("code", {}, r.ledger?.root ?? "-"),
    ),
  );
}

function label(election: IndexElection | null, kind: "unit" | "style" | "station", id: string): string {
  if (!election) return id;
  const list = kind === "unit" ? election.units : kind === "style" ? election.styles : election.stations;
  return list.find((x) => x.id === id)?.label ?? id;
}

function unitsCard(r: Report, election: IndexElection | null): HTMLElement {
  const units = r.units ?? [];
  const outside = outsidePin(r);
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "보고 단위별"),
    el(
      "p",
      { class: "muted" },
      "단위별 상태는 장부 전체의 보류에서 다른 단위의 투표함이나 집계에만 있는 사유를 뺀 나머지와, 그 단위의 마감 완전성·집계 결과를 ityv-state의 상태 규칙(evaluate)에 넘긴 값이다. 장부 전체의 상태를 대신하지 않는다.",
    ),
    el(
      "div",
      { class: "scroll" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            el("th", {}, "보고 단위"),
            el("th", {}, "투표양식"),
            el("th", {}, "상태"),
            el("th", {}, "포함 기록"),
            el("th", {}, "기록 없는 투표지"),
            el("th", {}, "합계 열기"),
            el("th", {}, "열어 본 수"),
            el("th", {}, "종이 보고"),
            el("th", {}, "보류"),
          ),
        ),
        el(
          "tbody",
          {},
          ...units.map((u) => {
            const style = election?.styles.find((s) => s.id === u.style);
            // Names from the simulator's metadata only when the opened counts
            // have exactly the style's candidates plus BLANK and UNREADABLE.
            const named = style !== undefined && u.counts !== null && u.counts.length === style.candidates.length + 2;
            const counts = u.counts
              ? u.counts
                  .map((c, i) => {
                    const last = u.counts!.length - 1;
                    const name =
                      i === 0 ? "BLANK" : i === last ? "UNREADABLE" : named ? (style!.candidates[i - 1]?.name ?? `선택지 ${i}`) : `선택지 ${i}`;
                    return `${name} ${intText(c)}`;
                  })
                  .join(" · ")
              : "아직 없음";
            const opened = u.openings.length ? u.openings.map((o) => `${o.chunk}:${o.outcome}`).join(", ") : "없음";
            const paper = u.comparison
              ? u.comparison.agrees
                ? "대조 맞음"
                : `대조 다름${u.comparison.firstBelow !== null ? ` (선택지 ${intText(u.comparison.firstBelow)} 종이가 적음)` : ""}`
              : "없음";
            return el(
              "tr",
              {},
              el("td", {}, label(election, "unit", u.unit)),
              el("td", {}, label(election, "style", u.style)),
              el("td", {}, statusBadge(u.status, outside)),
              el("td", { class: "num" }, intText(u.included)),
              el("td", { class: "num" }, intText(u.noRecord)),
              el("td", {}, opened),
              el("td", { class: "small" }, counts),
              el("td", {}, paper),
              el("td", { class: "small" }, holdList(u.unitHolds)),
            );
          }),
        ),
      ),
    ),
    el(
      "p",
      { class: "muted" },
      election
        ? "보고 단위·투표양식·후보 이름은 시뮬레이터의 메타데이터(index.json, 번들 해시가 같을 때만)에서 왔으며 모두 가상이다. 열어 본 수는 신뢰기관의 합계 열기를 커밋먼트에 대해 확인한 값이며 당선이나 법적 결과를 뜻하지 않는다."
        : "이 번들에 맞는 메타데이터가 없어 식별자와 선택지 번호로만 보인다. 열어 본 수는 신뢰기관의 합계 열기를 커밋먼트에 대해 확인한 값이다.",
    ),
  );
}

function boxesCard(r: Report, election: IndexElection | null): HTMLElement {
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "투표함"),
    el(
      "div",
      { class: "scroll" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el("tr", {}, el("th", {}, "투표함"), el("th", {}, "투표소"), el("th", {}, "단계"), el("th", {}, "기록"), el("th", {}, "기록 없음"), el("th", {}, "종이"), el("th", {}, "보류")),
        ),
        el(
          "tbody",
          {},
          ...(r.boxes ?? []).map((b) =>
            el(
              "tr",
              {},
              el("td", {}, el("code", {}, b.box)),
              el("td", {}, label(election, "station", b.station ?? "")),
              el("td", {}, b.phase),
              el("td", { class: "num" }, intText(b.accepted ?? 0)),
              el("td", { class: "num" }, intText(b.close?.withoutRecord ?? 0)),
              el("td", { class: "num" }, intText(b.close?.paper)),
              el("td", { class: "small" }, holdList(b.holds)),
            ),
          ),
        ),
      ),
    ),
  );
}

/** One station's sheets outside the boxes over the day, with the limit
 * and the verifier's alarms. A single series: the title names it. Slots
 * whose sum overflowed are drawn as gaps. */
function progressChart(p: StationProgress): HTMLElement {
  const series = p.series;
  const W = 720;
  const H = 220;
  const L = 44;
  const R = 12;
  const T = 16;
  const B = 30;
  const values = series.map((x) => (x.out === null ? null : intNum(x.out)));
  const finite = values.filter((v): v is number => v !== null && Number.isFinite(v));
  const limit = intNum(p.limit);
  const max = Math.max(limit + 4, ...finite, 4);
  const min = Math.min(0, ...finite);
  const x = (i: number) => L + (i * (W - L - R)) / Math.max(1, series.length - 1);
  const y = (val: number) => T + ((max - val) * (H - T - B)) / (max - min || 1);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("class", "chart");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `밖에 있는 장수, ${slotTime(series[0]?.slot ?? 0)}부터 ${slotTime(series.at(-1)?.slot ?? 0)}까지`);
  const add = (tag: string, attrs: Record<string, string>, text?: string) => {
    const e = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text) e.textContent = text;
    svg.append(e);
    return e;
  };
  for (const g of [min, 0, Math.round(max / 2), max]) {
    add("line", { x1: String(L), x2: String(W - R), y1: String(y(g)), y2: String(y(g)), class: "grid" });
    add("text", { x: String(L - 6), y: String(y(g) + 4), class: "axis", "text-anchor": "end" }, String(g));
  }
  series.forEach((pt, i) => {
    if (i % 12 === 0) add("text", { x: String(x(i)), y: String(H - 10), class: "axis", "text-anchor": "middle" }, slotTime(pt.slot));
  });
  if (limit > 0) {
    add("line", { x1: String(L), x2: String(W - R), y1: String(y(limit)), y2: String(y(limit)), class: "limit" });
    add("text", { x: String(W - R), y: String(y(limit) - 4), class: "axis", "text-anchor": "end" }, `기준 L = ${intText(p.limit)}장`);
  }
  let d = "";
  let pen = false;
  values.forEach((val, i) => {
    if (val === null || !Number.isFinite(val)) {
      pen = false;
      return;
    }
    d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(val).toFixed(1)} `;
    pen = true;
  });
  add("path", { d: d.trim(), class: "line" });
  // A slot whose sum overflowed: a dashed band instead of a point.
  const step = (W - L - R) / Math.max(1, series.length - 1);
  values.forEach((val, i) => {
    if (val !== null && Number.isFinite(val)) return;
    add("rect", { x: String(x(i) - step / 2), y: String(T), width: String(step), height: String(H - T - B), class: "gap" });
  });
  for (const a of p.alarms) {
    const i = series.findIndex((pt) => intText(pt.slot) === intText(a.slot));
    if (i < 0) continue;
    const val = values[i];
    const cx = x(i);
    const cy = y(val === null || val === undefined || !Number.isFinite(val) ? 0 : val);
    add("path", { d: `M${cx},${cy - 12} l7,12 h-14 z`, class: "alarm-mark" });
    add("text", { x: String(cx), y: String(cy - 16), class: "alarm-label", "text-anchor": "middle" }, `${ALARMS[a.alarm] ?? a.alarm} ${slotTime(a.slot)}`);
  }
  const cross = add("line", { x1: "0", x2: "0", y1: String(T), y2: String(H - B), class: "cross", visibility: "hidden" });
  const tip = el("div", { class: "tip", hidden: "" });
  const overlay = add("rect", { x: String(L), y: String(T), width: String(W - L - R), height: String(H - T - B), class: "hit" });
  overlay.addEventListener("mousemove", (ev) => {
    const box = svg.getBoundingClientRect();
    const px = (((ev as MouseEvent).clientX - box.left) / box.width) * W;
    const i = Math.max(0, Math.min(series.length - 1, Math.round(((px - L) * (series.length - 1)) / (W - L - R))));
    const pt = series[i]!;
    cross.setAttribute("x1", String(x(i)));
    cross.setAttribute("x2", String(x(i)));
    cross.setAttribute("visibility", "visible");
    tip.hidden = false;
    tip.textContent = pt.sheetsIn === null
      ? `${slotTime(pt.slot)} 칸 · 투입 누계 합이 64비트를 넘음`
      : `${slotTime(pt.slot)} 칸 · 교부 ${intText(pt.issued)} · 투입 ${intText(pt.sheetsIn)} · 훼손 ${intText(pt.spoiled)} · 반납 ${intText(pt.returned)} · 밖에 ${intText(pt.out)}장`;
    tip.style.left = `${(x(i) / W) * 100}%`;
  });
  overlay.addEventListener("mouseleave", () => {
    cross.setAttribute("visibility", "hidden");
    tip.hidden = true;
  });
  return el("div", { class: "chartwrap" }, svg, tip);
}

function progressCard(r: Report, election: IndexElection | null): HTMLElement | null {
  const list = r.progress?.filter((p) => p.series.length > 0) ?? [];
  if (list.length === 0) return null;
  const chosen = list.find((p) => p.station === st.station) ?? list.find((p) => p.alarms.length > 0) ?? list[0]!;
  const sel = el("select", { "aria-label": "투표소" });
  for (const p of list) {
    const o = el(
      "option",
      { value: p.station },
      `${label(election, "station", p.station)}${p.alarms.length ? ` · 경보 ${p.alarms.length}` : ""}${p.suspended ? " · 경보 멈춤" : ""}${p.overflow ? " · 넘침" : ""}`,
    );
    if (p.station === chosen.station) o.selected = true;
    sel.append(o);
  }
  sel.addEventListener("change", () => {
    st.station = sel.value;
    rerender();
  });
  const table = el(
    "details",
    {},
    el("summary", {}, "표로 보기"),
    el(
      "div",
      { class: "scroll" },
      el(
        "table",
        {},
        el("thead", {}, el("tr", {}, el("th", {}, "칸"), el("th", {}, "확인"), el("th", {}, "교부"), el("th", {}, "투입"), el("th", {}, "훼손"), el("th", {}, "반납"), el("th", {}, "밖에"))),
        el(
          "tbody",
          {},
          ...chosen.series.map((pt) =>
            el(
              "tr",
              {},
              el("td", {}, `${slotDay(pt.slot)}일 ${slotTime(pt.slot)}`),
              ...[pt.checkins, pt.issued, pt.sheetsIn, pt.spoiled, pt.returned, pt.out].map((n) =>
                el("td", { class: "num" }, n === null ? "넘침" : intText(n)),
              ),
            ),
          ),
        ),
      ),
    ),
  );
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "투표 진행: 밖에 있는 장수"),
    el("label", { class: "datapick" }, "투표소: ", sel),
    progressChart(chosen),
    chosen.overflow
      ? el("p", { class: "warnline" }, icon("warn"), "이 투표소의 투입 누계 합이 64비트를 넘는 칸이 있다. 그 칸은 수를 쓰지 않고 '넘침'으로 둔다. 판정은 검증기의 보류 사유를 보라.")
      : null,
    el(
      "p",
      { class: "muted" },
      `경보(검증기): ${chosen.alarms.length ? chosen.alarms.map((a) => `${ALARMS[a.alarm] ?? a.alarm} ${slotTime(a.slot)}`).join(", ") : "없음"} · 현장 확인 프레임: ${chosen.checks.map(intText).join(", ") || "없음"}${chosen.suspended ? " · 비상 투입으로 경보 멈춤" : ""}${chosen.counterfoil ? " · 교부 번호 대조" : ""}`,
    ),
    el(
      "p",
      { class: "muted" },
      "경보와 멈춤은 검증기(verify_progress)의 판정이다. 칸별 수는 검증기가 받은 진행 기록의 값이고, 밖에 있는 장수는 ityv-state의 out_of로 계산했다(반출 장수는 넣지 않았다). 경보는 확인이 필요하다는 뜻이며 어떤 투표지도 무효가 되지 않는다.",
    ),
    table,
  );
}

/** The first 16 hex digits of a tracking code, in groups of four. */
function code16(hex: string): string {
  return hex.slice(0, 16).replace(/(.{4})/g, "$1 ").trim();
}

function phaseText(s: StyleAuditReport): string {
  if (!s.phase) return s.freeze === null ? "동결 없음" : "표본 없음";
  const word = PHASES[s.phase.kind] ?? s.phase.kind;
  return s.phase.round === null ? word : `${word} (${intNum(s.phase.round) + 1}라운드)`;
}

/** The binding checkpoint's time against the beacon publication, drawn:
 * the commit, the binding checkpoint, the last bucket the rule allows
 * (`published − margin`) and the publication. */
function timeline(a: AuditReport): HTMLElement | null {
  const c = a.commit;
  const o = a.observation;
  if (!c?.binding || !o) return null;
  const C = intNum(c.bucket);
  const B = intNum(c.binding.bucket);
  const P = intNum(o.published);
  const limit = P - intNum(a.margin);
  const lo = Math.min(C, B) - 1;
  const hi = P + 1;
  const W = 720;
  const H = 96;
  const L = 24;
  const R = 24;
  const x = (b: number) => L + ((b - lo) * (W - L - R)) / Math.max(1, hi - lo);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("class", "chart timeline");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `약정 구간 ${C}, 고정 체크포인트 구간 ${B}, 허용 한계 ${limit}, 비콘 공표 구간 ${P}`);
  const add = (tag: string, attrs: Record<string, string>, text?: string) => {
    const e = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text) e.textContent = text;
    svg.append(e);
    return e;
  };
  // Buckets after the limit: an honest witness could still sign there
  // after the publication.
  add("rect", { x: String(x(limit + 0.5)), y: "30", width: String(x(hi) - x(limit + 0.5)), height: "28", class: "late-zone" });
  add("line", { x1: String(L), x2: String(W - R), y1: "44", y2: "44", class: "grid" });
  for (let b = lo; b <= hi; b++) add("line", { x1: String(x(b)), x2: String(x(b)), y1: "40", y2: "48", class: "grid" });
  const mark = (b: number, label: string, cls: string, y: number) => {
    add("circle", { cx: String(x(b)), cy: "44", r: "6", class: cls });
    add("text", { x: String(x(b)), y: String(y), class: "axis", "text-anchor": "middle" }, label);
  };
  mark(C, `약정 ${C}`, "pt-commit", 18);
  mark(B, `고정 ${B}`, "pt-binding", B === C ? 86 : 18);
  add("line", { x1: String(x(limit)), x2: String(x(limit)), y1: "26", y2: "62", class: "limit" });
  add("text", { x: String(x(limit)), y: "76", class: "axis", "text-anchor": "middle" }, `한계 P − ${intText(a.margin)} = ${limit}`);
  mark(P, `공표 P = ${P}`, "pt-published", 18);
  return el("div", { class: "chartwrap" }, svg);
}

/** A token as text: authority, operator, kind, record frame and the
 * bucket of its latest instant. */
function tokenText(t: Token): string {
  return `${t.authority} (${t.operator}, ${TSA_KINDS[t.kind] ?? t.kind}) · 기록 프레임 ${intText(t.frame)} · 가장 늦은 순간 구간 ${intText(t.latestBucket)} (${bucketTime(t.latestBucket)})`;
}

/** The display check of ADR-0039 8 over the binding checkpoint's tokens:
 * both kinds and two operators among those recorded before the seed with
 * their latest instant before the publication bucket. */
function stampedCheck(tokens: { kind: string; operator: string; beforeSeed: boolean; beforePublication: boolean | null }[], check: (ok: boolean, text: string) => HTMLElement): HTMLElement {
  const good = tokens.filter((t) => t.beforeSeed && t.beforePublication === true);
  const gov = good.some((t) => t.kind === "Government");
  const free = good.some((t) => t.kind === "NonGovernment");
  const operators = new Set(good.map((t) => t.operator.toLowerCase())).size;
  return check(gov && free && operators >= 2, `시드 앞 프레임의 공표 구간 전 토큰: 정부 운영 ${gov ? "있음" : "없음"} · 정부 밖 ${free ? "있음" : "없음"} · 운영 주체 ${operators}`);
}

function seedInputs(a: AuditReport): HTMLElement {
  const o = a.observation;
  const c = a.commit;
  const s = a.seed;
  const toggle = el("input", { type: "checkbox", "data-action": "beacon", "aria-label": "비콘 관찰을 검증기에 넘김" });
  toggle.checked = st.beacon;
  toggle.addEventListener("change", () => void setBeacon(toggle.checked));
  const rows: HTMLElement[] = [];
  const row = (k: string, ...v: (string | Node)[]) => rows.push(el("tr", {}, el("th", {}, k), el("td", {}, ...v)));
  if (o) {
    row("비콘 관찰", `회차 ${intText(o.round)} · 공표 구간 ${intText(o.published)} (${bucketTime(o.published)})`);
    row("공표 출력", el("code", { class: "fp" }, o.outputText ?? o.outputHex));
    row("비콘 값", o.beaconValue ? el("code", { class: "fp" }, o.beaconValue) : "-", " (지정 문서·회차·출력의 라벨 붙은 SHA3-512)");
  } else {
    row("비콘 관찰", a.bundleHasObservation ? "넘기지 않음" : "번들에 없음");
  }
  if (c) {
    row("감사 약정", `프레임 ${intText(c.seq)} · 구간 ${intText(c.bucket)} (${bucketTime(c.bucket)}) · 회차 ${intText(c.beaconRound)}`);
    row("주사위 기록", el("code", { class: "fp" }, c.dice));
    row("비콘 지정", el("code", { class: "fp" }, c.beaconSource));
    row(
      "고정 체크포인트",
      c.binding
        ? el("span", {}, `순번 ${intText(c.binding.seq)} · 프레임 ${intText(c.binding.frame)} · 구간 ${intText(c.binding.bucket)} (${bucketTime(c.binding.bucket)}) · 지문 `, el("code", {}, c.binding.fingerprint))
        : "약정을 덮는 유효한 체크포인트가 없다",
    );
    if (c.binding) {
      row(
        "고정 체크포인트의 시점확인",
        c.binding.tokens.length === 0
          ? "토큰 없음"
          : el(
              "ul",
              { class: "checks", "data-testid": "binding-tokens" },
              ...c.binding.tokens.map((t) =>
                el(
                  "li",
                  {},
                  icon(t.beforeSeed && t.beforePublication === true ? "ok" : "wait"),
                  ` ${tokenText(t)} · ${t.beforeSeed ? "시드 앞 프레임" : "시드 뒤 프레임"}${t.beforePublication === null ? "" : t.beforePublication ? " · 공표 구간 전" : " · 공표 구간 이후"}`,
                ),
              ),
            ),
      );
    }
  } else {
    row("감사 약정", "받아들인 약정 없음");
  }
  row(
    "시드",
    s
      ? el("span", {}, `프레임 ${intText(s.seq)} · 지문 `, el("code", {}, s.seed), s.beaconConfirmed ? " · 관찰한 비콘 값과 같음" : " · 관찰한 비콘 값으로 확인하지 못함")
      : "받아들인 시드 없음",
  );
  const timing: HTMLElement[] = [];
  if (c?.binding && o) {
    const B = intNum(c.binding.bucket);
    const C = intNum(c.bucket);
    const P = intNum(o.published);
    const m = intNum(a.margin);
    const check = (ok: boolean, text: string) => el("li", {}, icon(ok ? "ok" : "fail"), ` ${text}`);
    timing.push(
      el(
        "ul",
        { class: "checks", "data-testid": "audit-timing" },
        check(C < P, `약정 구간 ${C} < 공표 구간 ${P}`),
        check(B >= C, `고정 체크포인트 구간 ${B} ≥ 약정 구간 ${C}`),
        check(B + m <= P, `고정 체크포인트 구간 ${B} ≤ 공표 구간 − ${m} = ${P - m} (여유 ${P - B}구간)`),
        stampedCheck(c.binding.tokens, check),
      ),
      el(
        "p",
        { class: "muted" },
        `한계 ${m}구간 = 증인의 시각 허용 1 + 정직한 시계 오차 1 + 1. 공표 뒤에 서명하는 정직한 증인은 P − 2보다 이른 구간에 서명할 수 없으므로, 고정 체크포인트가 P − ${m} 이하이면 비콘 값을 알기 전에 서명된 것이다(ADR-0036 4항). 증인만이 아니라 정부 운영과 정부 밖, 두 운영 주체의 시점확인 토큰도 시드 앞 프레임에서 그 체크포인트가 공표 구간 전에 있었음을 보여야 한다(ADR-0039 8항). 위 대조는 표시용이며 판정은 검증기의 시드 수락·거부다.`,
      ),
    );
  }
  return el(
    "div",
    {},
    a.bundleHasObservation
      ? el("label", { class: "datapick" }, toggle, " 비콘 관찰(시연용 고정 자료)을 검증기에 넘김")
      : null,
    o
      ? el(
          "p",
          { class: "warnline", "data-testid": "beacon-fixture" },
          icon("warn"),
          "시연용 고정 자료: 이 비콘 관찰(회차, 출력, 공표 구간)은 시뮬레이터가 번들에 넣은 값이다. 검증기는 비콘을 직접 받지 못하므로 호출자가 본 공표를 넘긴다. 실제 검증에서는 지정된 비콘의 공표를 직접 확인해 넣어야 한다.",
        )
      : a.bundleHasObservation
        ? el("p", { class: "warnline" }, icon("info"), "비콘 관찰 없이 검증했다. 시드를 비콘 값으로 확인할 수 없으므로 감사가 끝나지 않고, PAPER_AUDITED에 닿지 않는다(보류는 아니다).")
        : null,
    el("div", { class: "scroll" }, el("table", { class: "kv" }, el("tbody", {}, ...rows))),
    timeline(a),
    ...timing,
  );
}

function recordRows(list: AuditRecord[], withPosition: boolean): HTMLElement {
  return el(
    "div",
    { class: "scroll" },
    el(
      "table",
      {},
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          withPosition ? el("th", { class: "num" }, "순서") : null,
          el("th", {}, "추적코드 (앞 16자)"),
          el("th", {}, "투표함"),
          el("th", { class: "num" }, "열기 흔적"),
          el("th", {}, "종이 대조"),
          el("th", {}, "재구성"),
        ),
      ),
      el(
        "tbody",
        {},
        ...list.map((x) =>
          el(
            "tr",
            { class: x.comparison && x.comparison.code !== 0 ? "diff" : "" },
            withPosition ? el("td", { class: "num" }, String(intNum(x.position ?? 0) + 1)) : null,
            el("td", {}, el("code", {}, code16(x.code))),
            el("td", {}, el("code", {}, x.box ?? "-")),
            el("td", { class: "num" }, x.opened === null ? "-" : `프레임 ${intText(x.opened)}`),
            el("td", {}, x.comparison ? `${COMPARISON_CODES[x.comparison.code] ?? x.comparison.name}${x.comparison.transferMark ? " · 잉크 묻음" : ""}` : "-"),
            el("td", { class: "small" }, x.reconstruction === "NotSupplied" ? "제공 안 됨(공개 검증)" : (x.reconstruction ?? "-")),
          ),
        ),
      ),
    ),
  );
}

function styleAudit(s: StyleAuditReport, election: IndexElection | null): HTMLElement {
  const current = s.phase?.kind === "Sampling" ? intNum(s.phase.round ?? 0) : -1;
  return el(
    "div",
    { class: "style-audit", "data-style": s.style },
    el(
      "h3",
      {},
      `${label(election, "style", s.style)} `,
      el("span", { class: `flag ${s.concluded ? "ok" : s.holds.length ? "bad" : ""}`, "data-testid": "audit-phase" }, icon(s.concluded ? "ok" : "wait"), ` ${phaseText(s)}${s.concluded ? " · 감사 끝" : " · 끝나지 않음"}`),
    ),
    el(
      "p",
      { class: "muted" },
      `표본 프레임 ${intText(s.frameCount)}개 기록(${s.units.map((u) => label(election, "unit", u)).join(", ")}) · 동결 프레임 ${s.freeze === null ? "없음" : intText(s.freeze)}${s.rule ? ` · 위험 한도 ${(intNum(s.rule.riskLimitPpm) / 10000).toFixed(1)}% · 비콘 회차 ${intText(s.rule.beaconRound)}` : ""}`,
      s.frameRoot ? el("span", {}, " · 프레임 root 지문 ", el("code", {}, s.frameRoot)) : null,
    ),
    s.frameProblems.length
      ? el("p", { class: "warnline" }, icon("warn"), `동결의 프레임이 장부와 다르다: ${s.frameProblems.join(", ")}. 표본을 뽑지 않는다.`)
      : null,
    s.rounds.length
      ? el(
          "div",
          { class: "scroll" },
          el(
            "table",
            { "data-testid": "audit-rounds" },
            el(
              "thead",
              {},
              el(
                "tr",
                {},
                el("th", { class: "num" }, "라운드"),
                el("th", { class: "num" }, "누적 표본"),
                el("th", { class: "num" }, "불일치 상한"),
                el("th", { class: "num" }, "대조"),
                el("th", { class: "num" }, "불일치"),
                el("th", {}, "상태"),
              ),
            ),
            el(
              "tbody",
              {},
              ...s.rounds.map((r, i) => {
                const over = intNum(r.nonzero) > intNum(r.threshold);
                const state = over
                  ? "상한 넘음 → 확대"
                  : s.phase?.kind === "Concluded" && intNum(s.phase.round ?? -1) === i
                    ? "상한 안 · 종료"
                    : current === i
                      ? "대조 중"
                      : "";
                return el(
                  "tr",
                  { class: over ? "diff" : "" },
                  el("td", { class: "num" }, String(i + 1)),
                  el("td", { class: "num" }, `${intText(r.drawn)}${intNum(r.drawn) < intNum(r.size) ? ` (선언 ${intText(r.size)})` : ""}`),
                  el("td", { class: "num" }, intText(r.threshold)),
                  el("td", { class: "num" }, intText(r.compared)),
                  el("td", { class: "num" }, intText(r.nonzero)),
                  el("td", {}, state),
                );
              }),
            ),
          ),
        )
      : null,
    s.sample.length ? el("h4", {}, `뽑힌 기록 ${s.sample.length}개 (뽑힌 순서)`) : null,
    s.sample.length ? recordRows(s.sample, true) : null,
    s.fullComparison.length ? el("h4", {}, `전수 대조로 연 기록 ${s.fullComparison.length}개`) : null,
    s.fullComparison.length ? recordRows(s.fullComparison, false) : null,
    s.devices.length
      ? el(
          "div",
          { class: "scroll" },
          el(
            "table",
            {},
            el(
              "thead",
              {},
              el(
                "tr",
                {},
                el("th", {}, "장치(투표함)"),
                el("th", { class: "num" }, "기록"),
                el("th", { class: "num" }, "대조"),
                el("th", {}, "코드 0–6별 대조 수"),
                el("th", {}, "전수 대조"),
                el("th", {}, "발견"),
                el("th", {}, "보류"),
              ),
            ),
            el(
              "tbody",
              {},
              ...s.devices.map((d) =>
                el(
                  "tr",
                  {},
                  el("td", {}, el("code", {}, d.box)),
                  el("td", { class: "num" }, intText(d.records)),
                  el("td", { class: "num" }, intText(d.compared)),
                  el("td", { class: "small" }, d.codes.map(intText).join(" · ")),
                  el("td", {}, d.fullComparisonFrom === null ? "-" : `프레임 ${intText(d.fullComparisonFrom)}부터${d.followedUp ? " · 끝" : " · 진행 중"}`),
                  el("td", {}, d.findings.length ? d.findings.map((f) => `프레임 ${intText(f)}`).join(", ") : "-"),
                  el("td", { class: "small" }, holdList(d.holds)),
                ),
              ),
            ),
          ),
        )
      : null,
    s.handCounts.length || s.phase?.kind === "HandCount"
      ? el(
          "p",
          {},
          el("strong", {}, "수검표: "),
          s.handCounts.length ? s.handCounts.map((h) => `${label(election, "unit", h.unit)} 프레임 ${intText(h.seq)}`).join(", ") : "아직 없음",
          " · 수검표가 법적 결과이며 검증기는 그것을 기계 합계와 비교하지 않는다.",
        )
      : null,
    s.holds.length ? el("p", { class: "warnline" }, icon("warn"), "이 투표양식의 보류: ", holdList(s.holds)) : null,
  );
}

function auditCard(r: Report, election: IndexElection | null): HTMLElement | null {
  const a = r.audit;
  if (!a) return null;
  const any = a.commit !== null || a.seed !== null || a.refused.length > 0 || a.styles.some((s) => s.freeze !== null);
  const card = el(
    "section",
    { class: "card wide", "data-testid": "audit" },
    el("h2", {}, "감사", el("span", { class: "muted" }, a.passed ? " 모든 투표양식 끝" : ` ${a.styles.filter((s) => s.concluded).length}/${a.styles.length} 투표양식 끝`)),
  );
  if (!any) {
    card.append(el("p", { class: "muted" }, "이 장부에는 감사 이벤트(동결, 약정, 시드, 열기 흔적, 대조)가 없다. PAPER_AUDITED에는 모든 투표양식의 감사가 끝나야 닿는다."));
    return card;
  }
  card.append(
    el("h3", {}, "시드의 입력과 고정 체크포인트"),
    seedInputs(a),
    ...a.styles.map((s) => styleAudit(s, election)),
    el(
      "p",
      { class: "muted" },
      "표본은 공개 정보다: 누구나 장부의 시드에서 같은 기록을 다시 뽑는다(VC-046). 열린 값(선택, cast id, 난수)은 제한 등급이라 번들에도 이 화면에도 없다. 공개 검증자에게 재구성은 '제공 안 됨'이며 열기 흔적의 존재와 서명만 확인한다(§14 8항). 선언된 표본 크기가 위험 한도 공식에서 나온 값인지는 검증하지 않는다.",
    ),
  );
  if (a.refused.length) {
    card.append(
      el("h3", {}, "받지 않은 감사 이벤트"),
      el(
        "div",
        { class: "scroll" },
        el(
          "table",
          { "data-testid": "audit-refused" },
          el("thead", {}, el("tr", {}, el("th", { class: "num" }, "프레임"), el("th", {}, "이벤트"), el("th", {}, "이유"))),
          el(
            "tbody",
            {},
            ...a.refused.map((x) =>
              el("tr", {}, el("td", { class: "num" }, intText(x.seq)), el("td", {}, AUDIT_EVENTS[x.event] ?? x.event), el("td", {}, el("code", {}, x.refusal), ` ${AUDIT_REFUSALS[x.refusal] ?? ""}`)),
            ),
          ),
        ),
      ),
    );
  }
  return card;
}

/** A checkpoint's anchoring, with its tokens on hover-free text. */
function anchorCell(a: { government: boolean; nonGovernment: boolean; operators: Int; satisfied: boolean }, tokens: (Token & { inWindow: boolean })[]): HTMLElement {
  return el(
    "span",
    { title: tokens.map((t) => `${tokenText(t)}${t.inWindow ? "" : " · 창 밖"}`).join("\n") },
    icon(a.satisfied ? "ok" : "wait"),
    ` ${a.satisfied ? "충족" : "미충족"} · 정부 운영 ${a.government ? "있음" : "없음"} · 정부 밖 ${a.nonGovernment ? "있음" : "없음"} · 운영 주체 ${intText(a.operators)} · 토큰 ${tokens.length}`,
  );
}

/** One roll state's row: receipts against the quorum, the pseudonym root,
 * whether it took effect. */
function custodyRow(what: string, c: RollCustody, quorum: Int): HTMLElement {
  return el(
    "tr",
    {},
    el("th", {}, what),
    el("td", { class: "num" }, intText(c.seq)),
    el("td", { class: "num" }, intText(c.entryCount)),
    el("td", {}, `${c.custodians.length} / ${intText(quorum)}`, c.custodians.length ? ` (${c.custodians.join(", ")})` : ""),
    el("td", {}, c.pseudonymConfirmed ? "확인" : "없음"),
    el("td", { class: `oc oc-${c.effective ? "PASSED" : "NOT_RUN"}` }, icon(c.effective ? "ok" : "wait"), c.effective ? " 효력 있음" : " 효력 없음"),
  );
}

function rollCard(r: Report): HTMLElement | null {
  const roll = r.roll;
  if (!roll) return null;
  const rows: HTMLElement[] = [];
  if (roll.freeze) rows.push(custodyRow("동결", roll.freeze, roll.quorum));
  for (const a of roll.amendments) {
    rows.push(custodyRow(`변경 ${intText(a.number)} (${ROLL_REASONS[a.reason] ?? a.reason}, ${a.authority})`, a, roll.quorum));
  }
  return el(
    "section",
    { class: "card wide", "data-testid": "roll" },
    el("h2", {}, "선거인명부 보관", el("span", { class: "muted" }, ` 보관 정족수 ${intText(roll.quorum)} · 출처 추출 ${intText(roll.extracts)}개 · ${roll.complete ? "동결과 모든 변경에 효력이 있다" : "효력이 없는 명부 상태나 빠진 발췌가 있다"}`)),
    rows.length === 0
      ? el("p", { class: "muted" }, "받아들인 명부 동결이 없다. 14절 6단계는 동결과 모든 변경이 효력이 있어야 통과한다.")
      : el(
          "div",
          { class: "scroll" },
          el(
            "table",
            {},
            el("thead", {}, el("tr", {}, el("th", {}, "상태"), el("th", { class: "num" }, "프레임"), el("th", { class: "num" }, "인원"), el("th", {}, "같은 값의 영수증 / 정족수"), el("th", {}, "명부 가명 root"), el("th", {}, "효력"))),
            el("tbody", { "data-testid": "roll-rows" }, ...rows),
          ),
        ),
    roll.refused.length || roll.mismatches.length
      ? el(
          "p",
          { class: "warnline", "data-testid": "roll-refused" },
          icon("warn"),
          [
            ...roll.refused.map((x) => `프레임 ${intText(x.seq)} ${x.event}: ${x.refusal}`),
            ...roll.mismatches.map((m) => `프레임 ${intText(m.seq)} ${m.custodian}의 영수증이 명부 값과 다르다`),
          ].join(", "),
        )
      : null,
    roll.lateAmendments.length || roll.missingExtracts.length
      ? el(
          "p",
          { class: "warnline", "data-testid": "roll-incomplete" },
          icon("warn"),
          [
            ...roll.lateAmendments.map((s) => `프레임 ${intText(s)}의 변경은 투표 마감 뒤에 기록되었다`),
            ...roll.missingExtracts.map((s) => `선거일 투표소 ${s}의 주민 명부 발췌가 없다`),
          ].join(", "),
        )
      : null,
    el(
      "p",
      { class: "muted" },
      `상태는 값이 같은 서로 다른 보관 기관의 영수증이 정족수 이상이고 그 가운데 법원행정처와 행정안전부가 있으며 하나가 명부 가명 root를 실었을 때 효력이 있다(VC-108, VC-109). 동결 뒤의 변경은 사유의 출처 기관이 서명한다(VC-111). 개인 확인(VC-110)은 투표 마감 때의 명부와 비교한다(${roll.pollClose === null ? "선거일 투표소의 마감이 아직 장부에 없어 마감 프레임을 모른다" : `마감은 선거일 투표소에 처음 나타난 마감(참여 집합, 참관인 최종 확인 수, 투표함 마감 가운데 가장 이른 것), 프레임 ${intText(roll.pollClose)}`}). 이의 투표 기록은 제한 등급이라 공개 장부에는 프레임만 있다(${intText(roll.contestedFrames)}개).`,
    ),
  );
}

/** One station's row: its gateway's sessions, its links' frames and
 * objects, what was found. */
function uplinkRows(s: UplinkStation): HTMLElement[] {
  const window = s.firstSlot === null || s.lastSlot === null ? "-" : `${slotTime(s.firstSlot)}–${slotTime(s.lastSlot)} (${slotDay(s.firstSlot)}일째)`;
  const head = el(
    "tr",
    {},
    el("th", {}, s.station, el("span", { class: "muted" }, ` ${s.gateway ?? "게이트웨이 없음"}`)),
    el("td", { class: "num" }, intText(s.sessions)),
    el("td", {}, window),
    el("td", {}, s.finalSession === null ? "아직 없음" : `프레임 ${intText(s.finalSession)}`),
    el("td", { class: "num" }, intText(s.captures)),
    el("td", { class: "num" }, intText(s.wanBytes)),
    el("td", { class: `oc oc-${s.holds.length ? "FAILED" : s.finalSession === null ? "NOT_RUN" : "PASSED"}` }, icon(s.holds.length ? "warn" : s.finalSession === null ? "wait" : "ok"), s.holds.length ? ` ${holdList(s.holds).textContent}` : s.finalSession === null ? " 대기" : " 통과"),
  );
  const links = s.links.map((l) =>
    el(
      "tr",
      { class: "sub" },
      el("td", {}, `${l.kind === "box" ? "스캐너" : "카운터·가명 유닛"} ${l.device}`, el("span", { class: "muted" }, ` 링크 ${l.link.split(" ").slice(0, 2).join(" ")}`)),
      el("td", { class: "num" }, `${intText(l.frames)} + ${intText(l.catchupFrames)}`),
      el("td", {}, l.firstSlot === null || l.lastSlot === null ? "-" : `${slotTime(l.firstSlot)}–${slotTime(l.lastSlot)}`),
      el("td", {}, `객체 ${intText(l.objects)} · 장부 이벤트 포함 ${intText(l.included)}`),
      el("td", { class: "num" }, intText(l.missingSlots)),
      el("td", { class: "num" }, `${intText(l.checkedChunks)} / ${intText(l.opaqueChunks)}`),
      el(
        "td",
        {},
        l.findings.length
          ? `${l.findings.length}건: ${[...new Set(l.findings.map((f) => LINK_PROBLEMS[f.problem] ?? f.problem))].join(", ")}`
          : "없음",
      ),
    ),
  );
  return [head, ...links];
}

function connectivityCard(r: Report): HTMLElement | null {
  const c = r.connectivity;
  if (!c) return null;
  const rows = c.stations.flatMap(uplinkRows);
  const warnings: string[] = [
    ...c.manifest.map((m) => `연결 목록: ${DEVICE_CLASSES[m.class] ?? m.class}${m.port === null ? "" : ` 포트 ${m.port}`} — ${MANIFEST_PROBLEMS[m.problem] ?? m.problem}`),
    ...c.stations.flatMap((s) => s.findings.map((f) => `${s.station} 세션 ${intText(f.session)} (프레임 ${intText(f.seq)}): ${SESSION_PROBLEMS[f.problem] ?? f.problem}`)),
    ...c.stations.flatMap((s) => s.outside.map((o) => `${s.station}: 프레임 ${intText(o.seq)}의 장치 이벤트(스키마 ${intText(o.schema)}, ${o.fingerprint.split(" ").slice(0, 2).join(" ")})가 그 장치의 받은 프레임 어디에도 없다`)),
    ...c.stations.filter((s) => intNum(s.pendingLogs) > 0).map((s) => `${s.station}: 아직 어느 세션도 받지 않은 기록 ${intText(s.pendingLogs)}개`),
  ];
  const incidents = c.incidents.map((i) =>
    el(
      "li",
      {},
      icon(i.refused ? "stop" : "warn"),
      ` 프레임 ${intText(i.seq)} ${INCIDENT_KINDS[i.kind] ?? i.kind} · ${i.station ?? "선거 전체"}${i.box ? ` ${i.box}` : ""} · 슬롯 ${slotTime(i.fromSlot)}–${slotTime(i.toSlot)}`,
      i.refused
        ? ` · 받지 않음: ${INCIDENT_PROBLEMS[i.refused] ?? i.refused}`
        : ` · 전자 층 보류: ${i.boxes.join(", ") || "-"}${i.fullComparison.length ? ` · 종이 전수 대조: ${i.fullComparison.map((f) => `${f.box} ${f.compared ? "대조함" : "아직"}`).join(", ")}` : ""}`,
    ),
  );
  return el(
    "section",
    { class: "card wide", "data-testid": "connectivity" },
    el(
      "h2",
      {},
      "연결 감사",
      el("span", { class: "muted" }, ` 투표소 ${c.stations.length}곳 · ${c.complete ? "모든 게이트웨이의 final 세션을 받았다" : "final 세션이 없는 게이트웨이가 있다"}${c.holds.length ? ` · 보류 ${holdList(c.holds).textContent}` : ""}`),
    ),
    rows.length === 0
      ? el("p", { class: "muted" }, "투표소가 없다.")
      : el(
          "div",
          { class: "scroll" },
          el(
            "table",
            {},
            el(
              "thead",
              {},
              el("tr", {}, el("th", {}, "투표소 / 링크"), el("th", { class: "num" }, "세션 / 프레임(일반 + 따라잡기)"), el("th", {}, "창"), el("th", {}, "final / 객체"), el("th", { class: "num" }, "캡처 서명 / 빠진 슬롯"), el("th", { class: "num" }, "바깥 회선 바이트 / 확인한·봉인 덩어리"), el("th", {}, "판정")),
            ),
            el("tbody", { "data-testid": "connectivity-rows" }, ...rows),
          ),
        ),
    warnings.length ? el("p", { class: "warnline", "data-testid": "connectivity-findings" }, icon("warn"), warnings.join(" · ")) : null,
    incidents.length ? el("ul", { "data-testid": "connectivity-incidents" }, ...incidents) : null,
    el(
      "p",
      { class: "muted" },
      "검증기는 genesis가 고정한 연결 목록의 한 방향 규칙(VC-077), 게이트웨이 세션의 서명·순서·사슬(장치가 서명한 215바이트 머리마다 SHA3-512 사슬을 다시 계산), 프레임의 서명·슬롯 모양·오프셋·0 채움 증명(VC-078), 장치가 서명한 객체 목록이 데이터를 덮는지와 객체의 종류·장치·순서·길이(VC-079), final 세션 뒤 장부의 모든 장치 이벤트가 받은 프레임 안에 통째로 있고 그 덩어리가 다시 계산되는지(VC-080), 연결 사건(VC-083)을 확인한다. 1 MiB 프레임 자체와 봉인된 share 패키지는 공표되지 않으므로, 참관인 캡처 대조(VC-081)와 통신사 기록 대조는 장부 밖 입력이 필요하고 결과는 연결 사건으로 장부에 들어온다. 연결 목록이 실제 하드웨어인지는 분해 표본과 무선 점검(VC-082)이 확인한다.",
    ),
  );
}

function checkpointsCard(r: Report): HTMLElement {
  const c = r.checkpoints;
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "체크포인트", el("span", { class: "muted" }, ` 덮은 프레임 ${intText(c?.covered ?? 0)} / ${intText(r.ledger?.treeSize ?? 0)}`)),
    el(
      "div",
      { class: "scroll" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el("tr", {}, el("th", {}, "순번"), el("th", {}, "프레임"), el("th", {}, "구간"), el("th", {}, "트리 크기"), el("th", {}, "시점확인 앵커"), el("th", {}, "체크포인트 지문 (Base32 32자)")),
        ),
        el(
          "tbody",
          { "data-testid": "checkpoint-rows" },
          ...(c?.valid ?? []).map((v) =>
            el(
              "tr",
              {},
              el("td", { class: "num" }, intText(v.seq)),
              el("td", { class: "num" }, intText(v.frame)),
              el("td", { class: "num" }, `${intText(v.timeBucket)} (${bucketTime(v.timeBucket)})`),
              el("td", { class: "num" }, intText(v.treeSize)),
              el("td", {}, anchorCell(v.anchoring, v.tokens)),
              el("td", {}, el("code", { class: "fp" }, v.fingerprint)),
            ),
          ),
        ),
      ),
    ),
    (c?.findings.length ?? 0) > 0
      ? el("p", { class: "warnline" }, icon("warn"), `사슬이 끝난 곳: ${c!.findings.map((f) => `프레임 ${intText(f.frame)} ${f.kind}`).join(", ")} · 확인하지 않은 체크포인트 ${intText(c!.unchecked)}개`)
      : null,
    (c?.timestamps.refusals.length ?? 0) > 0
      ? el(
          "p",
          { class: "warnline", "data-testid": "timestamp-refusals" },
          icon("warn"),
          `받지 않은 시점확인 기록: ${c!.timestamps.refusals.map((x) => `프레임 ${intText(x.frame)} ${x.authority} ${x.problem}`).join(", ")}`,
        )
      : null,
    el(
      "p",
      { class: "muted" },
      `시점확인 토큰 ${intText(c?.timestamps.tokens ?? 0)}개 · 응답 없음 기록 ${intText(c?.timestamps.unanswered ?? 0)}개. 앵커는 체크포인트 구간 + 4 안의 가장 늦은 순간을 가진 정부 운영과 정부 밖, 두 운영 주체의 토큰이다(VC-115). 장부의 앵커 기한은 마지막 체크포인트로 판정한다(ADR-0039 7항). 토큰은 증인 서명을 보강하는 증거이며 기관의 시각이 참이라는 증명은 아니다.`,
    ),
    el("p", { class: "muted" }, "지문은 체크포인트 해시의 앞 20바이트를 Base32로 적은 것이다(PROTOCOL §5.7 5항). 소리 내어 읽고 공표된 값과 비교하는 대조용이며 서명 검증을 대신하지 않는다."),
  );
}

function refusedCard(r: Report): HTMLElement {
  const list = r.refused ?? [];
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "받지 않은 이벤트", el("span", { class: "muted" }, ` ${list.length}개`)),
    list.length === 0
      ? el("p", { class: "muted" }, "없음.")
      : el(
          "div",
          { class: "scroll" },
          el(
            "table",
            {},
            el("thead", {}, el("tr", {}, el("th", {}, "프레임"), el("th", {}, "스키마"), el("th", {}, "단계"), el("th", {}, "이유"))),
            el(
              "tbody",
              {},
              ...list.map((x) =>
                el("tr", {}, el("td", { class: "num" }, intText(x.seq)), el("td", {}, el("code", {}, x.schema ?? "-")), el("td", {}, STAGES[x.stage] ?? x.stage), el("td", {}, el("code", {}, x.reason))),
              ),
            ),
          ),
        ),
  );
}

function disputesCard(r: Report): HTMLElement | null {
  const list = r.disputes?.list ?? [];
  if (list.length === 0) return null;
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "분쟁"),
    el(
      "ul",
      {},
      ...list.map((d) =>
        el("li", {}, `${d.type} · ${d.box ?? "-"} · ${d.status}${d.unresolved ? " (미해결)" : ""} · 법적 결정 ${intText(d.decisions)}건 · 접수 지문 `, el("code", {}, d.filing)),
      ),
    ),
  );
}

/** Looks a tracking code up in this result's own report (which carries
 * each record's verified inclusion). */
function lookup(res: Result, code: string): string {
  const c = code.replace(/\s+/g, "").toLowerCase();
  if (c.length < 16) return "추적코드를 16자 이상 넣으세요.";
  const rec = (res.report.records ?? []).find((x) => x.code.startsWith(c));
  if (!rec) return "이 번들의 공개원장에서 그 추적코드를 찾지 못했다.";
  if (!rec.included || rec.checkpoint === null) {
    return `프레임 ${intText(rec.seq)}는 공개원장에 있지만 아직 어느 체크포인트도 덮지 않았다.`;
  }
  return `프레임 ${intText(rec.seq)} (${rec.box}, ${rec.state})가 체크포인트 ${intText(rec.checkpoint)}(트리 크기 ${intText(rec.treeSize)}, 지문 ${rec.checkpointFingerprint ?? "-"})에 포함됨: 검증한 그 체크포인트의 root에 대해 ityv-ledger가 포함 증명 ${intText(rec.pathLength)}단계를 확인했다. 누구를 찍었는지는 알 수 없다.`;
}

function lookupCard(res: Result): HTMLElement {
  const input = el("input", { type: "text", placeholder: "추적코드(16진)", "aria-label": "추적코드", spellcheck: "false" });
  input.value = st.lookup.code;
  const out = el("div", { class: "lookup-out", "aria-live": "polite", "data-testid": "lookup-out" }, st.lookup.out);
  const btn = el("button", { class: "btn", "data-action": "lookup" }, "포함 확인");
  btn.addEventListener("click", () => {
    st.lookup = { code: input.value, out: lookup(res, input.value) };
    out.textContent = st.lookup.out;
  });
  input.addEventListener("input", () => {
    st.lookup.code = input.value;
  });
  const sample = res.scenario?.slips ?? [];
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "추적코드 포함 확인"),
    el("div", { class: "pinrow" }, input, btn),
    sample.length
      ? el(
          "p",
          { class: "muted" },
          "시연용 코드: ",
          ...sample.map((s) => {
            const a = el("a", { href: "#", class: "chip" }, s.note);
            a.addEventListener("click", (e) => {
              e.preventDefault();
              input.value = s.code;
              st.lookup.code = s.code;
            });
            return a;
          }),
        )
      : null,
    out,
  );
}

async function runSelfTest(): Promise<void> {
  stopSelfTest();
  const list = st.index?.scenarios.filter((s) => s.set === "quick") ?? [];
  const ticket = (st.selftest?.ticket ?? 0) + 1;
  st.selftest = { rows: [], running: true, stopped: false, ticket };
  redrawSelfTest();
  for (const s of list) {
    if (st.selftest?.ticket !== ticket || !st.selftest.running) return;
    let row: SelfTestRow;
    try {
      const r = await testClient.verify(await loadBundle(s.file));
      const ok =
        r.bundleHash === s.sha3 && r.status === s.expected.status && sameHolds(s.expected.holds, r.holds ?? []);
      row = {
        name: s.title,
        expected: `${s.expected.status} ${s.expected.holds.map((h) => h.code).join(",")}`,
        actual: `${r.status ?? r.error ?? "-"} ${(r.holds ?? []).map((h) => h.code).join(",")}`,
        ok,
      };
    } catch (e) {
      if (e instanceof Cancelled) return;
      row = { name: s.title, expected: s.expected.status, actual: `오류: ${String(e)}`, ok: false };
    }
    if (st.selftest?.ticket !== ticket) return;
    st.selftest.rows.push(row);
    redrawSelfTest();
  }
  if (st.selftest?.ticket === ticket) {
    st.selftest.running = false;
    redrawSelfTest();
  }
}

function selfTestCard(): HTMLElement {
  const btn = el("button", { class: "btn", "data-action": "selftest" }, "빠른 시나리오 모두 자체 시험");
  btn.addEventListener("click", () => void runSelfTest());
  const t = st.selftest;
  const rows = t?.rows ?? [];
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "자체 시험"),
    el(
      "p",
      { class: "muted" },
      "시뮬레이터의 기대(index.json)와 브라우저 안 검증기의 판정을 시나리오마다 비교한다(번들 해시도 확인). 같은 비교를 Rust 테스트도 한다. 다른 쪽으로 옮기면 멈춘다.",
    ),
    btn,
    t ? el("p", { class: "muted", "data-testid": "selftest-state" }, t.running ? `진행 중 ${rows.length}개` : t.stopped ? `멈춤: 다른 쪽으로 옮겨 ${rows.length}개에서 멈췄다` : `끝 ${rows.length}개`) : null,
    rows.length
      ? el(
          "table",
          { "data-testid": "selftest" },
          el("thead", {}, el("tr", {}, el("th", {}, "시나리오"), el("th", {}, "기대"), el("th", {}, "실제"), el("th", {}, ""))),
          el(
            "tbody",
            {},
            ...rows.map((x) =>
              el(
                "tr",
                {},
                el("td", {}, x.name),
                el("td", {}, el("code", {}, x.expected)),
                el("td", {}, el("code", {}, x.actual)),
                el("td", {}, el("span", { class: `flag ${x.ok ? "ok" : "bad"}` }, icon(x.ok ? "ok" : "fail"), x.ok ? " 같음" : " 불일치")),
              ),
            ),
          ),
        )
      : null,
  );
}

function draw(root: HTMLElement): void {
  const res = st.result;
  const r = res?.report ?? null;
  const election = res?.scenario ? (st.index?.elections.find((e) => e.id === res.scenario!.election) ?? null) : null;
  const parts: (HTMLElement | null)[] = [picker(st.index)];
  if (st.busy) parts.push(el("section", { class: "card busy", "aria-live": "polite", "data-testid": "busy" }, icon("wait"), st.busy));
  if (st.error) parts.push(el("section", { class: "card warnline", "data-testid": "error" }, icon("stop"), `오류: ${st.error}`));
  if (res && r && !r.error) {
    parts.push(
      el(
        "p",
        { class: "muted result-meta", "data-testid": "result-meta" },
        `파일 ${res.fileName} · 번들 SHA3-512 ${r.bundleHash.slice(0, 24)}… · ${res.scenario ? `시나리오 ${res.scenario.name}` : "index.json에 없는 번들(시나리오 설명 없음)"} · 검증 ${(res.elapsed / 1000).toFixed(1)}초 (브라우저 안 WASM)`,
      ),
    );
    parts.push(electionBanner(r), ladder(r));
    if (res.scenario) parts.push(expectedCard(res.scenario, r));
    parts.push(pinCard(r), holdsCard(r), stagesCard(r));
    if (r.genesis?.ok) {
      parts.push(unitsCard(r, election), auditCard(r, election), progressCard(r, election), boxesCard(r, election), rollCard(r), connectivityCard(r), checkpointsCard(r), refusedCard(r), disputesCard(r), lookupCard(res));
    } else {
      parts.push(
        el("section", { class: "card warnline" }, icon("stop"), `genesis를 받지 못했다: ${r.genesis?.error ?? ""}. genesis는 전부 아니면 전무이므로 그 위의 어떤 단계도 진행하지 않았다.`),
      );
    }
  }
  selfEl = selfTestCard();
  parts.push(selfEl);
  root.replaceChildren(
    el(
      "div",
      { class: "dash" },
      el(
        "section",
        { class: "card intro" },
        el("h2", {}, "공개 검증 콘솔"),
        el(
          "p",
          {},
          "고른 번들을 이 브라우저 안에서 공개 검증기(ityv-verify를 WebAssembly로 빌드한 것)가 검증한다. 판정은 서버에 묻지 않고 브라우저 안에서 낸다. 다만 이 페이지, worker, WASM 모듈과 시나리오 목록(index.json)은 서버가 내려 준 것이라 그것들을 믿어야 한다. 서버를 믿지 않으려면 같은 소스에서 직접 빌드한 모듈의 해시와 아래 값을 대조하라. 이 콘솔은 읽기만 하며 어떤 장치에도 명령하지 않는다.",
        ),
        el(
          "p",
          { class: "muted", "data-testid": "wasm-hash" },
          "불러온 WASM 모듈의 SHA-256(브라우저 Web Crypto가 계산): ",
          el("code", { class: "fp" }, st.wasm || "계산 중…"),
        ),
        el("p", { class: "muted" }, st.index?.note ?? ""),
      ),
      ...parts.filter((x): x is HTMLElement => x !== null),
    ),
  );
}
