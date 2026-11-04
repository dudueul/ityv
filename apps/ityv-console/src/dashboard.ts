// 검증 대시보드: pick a scenario bundle or drop a bundle file; the
// browser runs the real verifier (ityv-verify through ityv-wasm, in a
// worker) and shows what it found. Nothing here computes a status: every
// status, hold, stage, checkpoint fingerprint and refusal is the
// verifier's. The page is read-only and sends nothing anywhere.

import type { Hold, IndexElection, IndexScenario, Report, SimIndex, StationProgress } from "./data";
import { slotDay, slotTime } from "./data";
import { el, icon } from "./render";
import { inclusion, lastVerified, loadBundle, parsePin, verifyBundle } from "./verifier";
import { ALARMS, HOLDS, HOLD_MEANS, HOLD_WORD, LADDER, LEGAL_MEANS, LEGAL_WORD, OUTCOMES, STAGES, STEPS } from "./vocab";

interface State {
  index: SimIndex | null;
  scenario: IndexScenario | null;
  fileName: string | null;
  bytes: ArrayBuffer | null;
  report: Report | null;
  busy: string | null;
  error: string | null;
  pin: string;
  station: string | null;
  selftest: { name: string; expected: string; actual: string; ok: boolean }[] | null;
  elapsed: number;
}

const st: State = {
  index: null,
  scenario: null,
  fileName: null,
  bytes: null,
  report: null,
  busy: null,
  error: null,
  pin: "",
  station: null,
  selftest: null,
  elapsed: 0,
};

let rootEl: HTMLElement | null = null;

function rerender(): void {
  if (rootEl) draw(rootEl);
}

export function renderDashboard(root: HTMLElement, index: SimIndex | null, scenario: string | null): void {
  rootEl = root;
  st.index = index;
  if (scenario && st.scenario?.name !== scenario && index) {
    const s = index.scenarios.find((x) => x.name === scenario);
    if (s) {
      void pick(s);
      return;
    }
  }
  draw(root);
}

async function pick(s: IndexScenario): Promise<void> {
  st.scenario = s;
  st.fileName = s.file;
  st.report = null;
  st.error = null;
  st.station = null;
  st.busy = `${s.title} 번들을 받아 검증하는 중 (${(s.bytes / 1e6).toFixed(1)} MB)…`;
  rerender();
  try {
    const bytes = await loadBundle(s.file);
    st.bytes = bytes.slice(0);
    await run(bytes);
  } catch (e) {
    st.error = String(e);
    st.busy = null;
    rerender();
  }
}

async function run(bytes: ArrayBuffer, pin?: Uint8Array): Promise<void> {
  const start = performance.now();
  st.busy = st.busy ?? "검증 중…";
  rerender();
  const report = await verifyBundle(bytes, pin, st.scenario?.name ?? st.fileName);
  st.report = report;
  st.busy = null;
  st.error = report.error ?? null;
  st.elapsed = performance.now() - start;
  rerender();
}

function holdList(holds: Hold[]): HTMLElement {
  if (holds.length === 0) return el("span", { class: "muted" }, "없음");
  return el("span", {}, holds.map((h) => `${h.code} ${h.name}`).join(", "));
}

function sameHolds(a: Hold[], b: Hold[]): boolean {
  return a.length === b.length && a.every((h, i) => h.code === b[i]?.code);
}

function statusBadge(word: string): HTMLElement {
  const iconName = word === HOLD_WORD ? "warn" : word === "UNVERIFIED" ? "wait" : "ok";
  return el("span", { class: `status st-${word}` }, icon(iconName), el("span", {}, word));
}

function picker(index: SimIndex | null): HTMLElement {
  const box = el("section", { class: "card picker-card" }, el("h2", {}, "시나리오"));
  if (!index) {
    box.append(
      el("p", { class: "muted" }, "시뮬레이터 번들 목록(bundles/index.json)을 찾지 못했다. `bun run dev`가 먼저 시뮬레이터를 돌린다."),
    );
  }
  const group = (g: "normal" | "attack", title: string) => {
    const list = index?.scenarios.filter((s) => s.group === g) ?? [];
    return el(
      "div",
      { class: "group" },
      el("h3", {}, title, el("span", { class: "muted" }, ` ${list.length}개`)),
      el(
        "ul",
        { class: "scen" },
        ...list.map((s) => {
          const a = el(
            "a",
            {
              href: `#/dashboard?scenario=${encodeURIComponent(s.name)}`,
              class: st.scenario?.name === s.name ? "on" : "",
              "data-scenario": s.name,
            },
            el("span", { class: "t" }, s.title),
            el("span", { class: "x" }, `기대: ${s.expected.status}${s.set === "full" ? " · 큰 번들" : ""}`),
          );
          return el("li", {}, a);
        }),
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
    el("span", {}, "번들 파일(.ityvb)을 여기 놓거나 고르세요. 파일은 이 브라우저 밖으로 나가지 않는다. "),
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

async function loadFile(f: File): Promise<void> {
  st.scenario = st.index?.scenarios.find((s) => s.file === f.name) ?? null;
  st.fileName = f.name;
  st.report = null;
  st.busy = `${f.name} 검증 중…`;
  rerender();
  const bytes = await f.arrayBuffer();
  st.bytes = bytes.slice(0);
  await run(bytes);
}

function pinCard(r: Report): HTMLElement {
  const input = el("input", {
    type: "text",
    placeholder: "관보에서 받은 genesis 핀(16진 128자)",
    value: st.pin,
    "aria-label": "genesis 핀",
    spellcheck: "false",
  });
  const btn = el("button", { class: "btn" }, "이 핀으로 다시 검증");
  btn.addEventListener("click", () => {
    st.pin = input.value;
    const pin = parsePin(input.value);
    if (!pin) {
      st.error = "핀은 16진 128자여야 한다.";
      rerender();
      return;
    }
    if (st.bytes) {
      st.busy = "다른 핀으로 검증 중…";
      void run(st.bytes.slice(0), pin);
    }
  });
  return el(
    "section",
    { class: "card" },
    el("h2", {}, "신뢰하는 genesis 핀"),
    el(
      "p",
      {},
      "검증기는 호출자가 준 핀만 믿는다. 지금 쓴 핀의 지문: ",
      el("code", {}, r.pin ?? "-"),
      r.pinFromBundle ? " (번들에 든 핀)" : " (직접 넣은 핀)",
    ),
    el(
      "p",
      { class: "warnline" },
      icon("warn"),
      "번들에 든 핀은 번들과 같은 곳에서 왔다. 실제 검증에서는 관보·위원회·지정 검증자·인쇄물처럼 다른 출처에서 받은 핀을 넣어야 한다(PROTOCOL §14, VC-005).",
    ),
    el("div", { class: "pinrow" }, input, btn),
  );
}

function ladder(r: Report): HTMLElement {
  const current = r.status ?? "UNVERIFIED";
  const held = current === HOLD_WORD;
  const rungs = el(
    "ol",
    { class: "ladder" },
    ...[...LADDER].reverse().map((rung) => {
      const on = rung.word === current;
      return el(
        "li",
        { class: on ? "on" : "" },
        el("span", { class: "word" }, rung.word),
        on ? el("span", { class: "here" }, icon("ok"), "지금 상태") : null,
        el("div", { class: "means" }, rung.means),
      );
    }),
  );
  const current_ = LADDER.find((l) => l.word === current);
  return el(
    "section",
    { class: "card hero" },
    el("h2", {}, "상태"),
    el("div", { class: "hero-status", "data-testid": "status" }, statusBadge(current)),
    held
      ? el("p", { class: "warnline" }, icon("warn"), HOLD_MEANS)
      : current_
        ? el("p", { class: "notmeans" }, el("strong", {}, "이 상태가 뜻하지 않는 것: "), current_.not)
        : null,
    r.countOnly ? el("p", { class: "warnline" }, icon("warn"), "BALLOT_MARK 권한이 없거나 수령 스캔 기록이 있어 수만 맞춰 볼 수 있다.") : null,
    el("h3", {}, "상태 사다리"),
    rungs,
    el(
      "div",
      { class: "side" },
      el("p", {}, el("strong", {}, HOLD_WORD), held ? " (지금 상태)" : "", ": ", HOLD_MEANS),
      el("p", {}, el("strong", {}, LEGAL_WORD), ": ", LEGAL_MEANS),
    ),
  );
}

function expectedCard(s: IndexScenario, r: Report): HTMLElement {
  const ok = s.expected.status === r.status && sameHolds(s.expected.holds, r.holds ?? []);
  return el(
    "section",
    { class: `card expect ${ok ? "agree" : "mismatch"}`, "data-testid": "expected" },
    el("h2", {}, "기대와 실제", el("span", { class: `flag ${ok ? "ok" : "bad"}`, "data-testid": "agreement" }, icon(ok ? "ok" : "fail"), ok ? " 같음" : " 불일치")),
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
    ok ? null : el("p", { class: "warnline" }, icon("warn"), "시뮬레이터의 기대와 검증기의 판정이 다르다. 어느 쪽이 틀렸는지 확인해야 한다."),
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
      `앵커: ${r.publications?.anchors ?? "-"} · 공개원장 공표 기한: ${r.publications?.board ?? "-"} · 프레임 ${r.ledger?.treeSize ?? 0}개 · 장부 root 지문 `,
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
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "보고 단위별"),
    el(
      "p",
      { class: "muted" },
      "단위별 상태는 검증기의 단계 결과를 그 단위의 투표함과 집계로 좁혀 ityv-state의 상태 규칙(evaluate)에 넘긴 값이다. 장부 전체의 상태를 대신하지 않는다.",
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
            el("th", {}, "열어 본 수 (후보별)"),
            el("th", {}, "종이 보고"),
            el("th", {}, "보류"),
          ),
        ),
        el(
          "tbody",
          {},
          ...units.map((u) => {
            const style = election?.styles.find((s) => s.id === u.style);
            const counts = u.counts
              ? u.counts
                  .map((c, i) => {
                    const m = (style?.candidates.length ?? u.counts!.length - 2) + 1;
                    const name = i === 0 ? "BLANK" : i === m ? "UNREADABLE" : (style?.candidates[i - 1]?.name ?? `후보 ${i}`);
                    return `${name} ${c}`;
                  })
                  .join(" · ")
              : "아직 없음";
            const opened = u.openings.length ? u.openings.map((o) => `${o.chunk}:${o.outcome}`).join(", ") : "없음";
            const paper = u.comparison ? (u.comparison.agrees ? "대조 맞음" : `대조 다름${u.comparison.firstBelow ? ` (후보 ${u.comparison.firstBelow} 종이가 적음)` : ""}`) : "없음";
            return el(
              "tr",
              {},
              el("td", {}, label(election, "unit", u.unit)),
              el("td", {}, label(election, "style", u.style)),
              el("td", {}, statusBadge(u.status)),
              el("td", { class: "num" }, String(u.included)),
              el("td", { class: "num" }, String(u.noRecord)),
              el("td", {}, opened),
              el("td", { class: "small" }, counts),
              el("td", {}, paper),
              el("td", { class: "small" }, holdList(u.unitHolds)),
            );
          }),
        ),
      ),
    ),
    el("p", { class: "muted" }, "후보 이름은 모두 가상이다. 열어 본 수는 신뢰기관의 합계 열기를 커밋먼트에 대해 확인한 값이며 당선이나 법적 결과를 뜻하지 않는다."),
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
              el("td", { class: "num" }, String(b.accepted ?? 0)),
              el("td", { class: "num" }, String(b.close?.withoutRecord ?? 0)),
              el("td", { class: "num" }, String(b.close?.paper ?? "-")),
              el("td", { class: "small" }, holdList(b.holds)),
            ),
          ),
        ),
      ),
    ),
  );
}

/** One station's sheets outside the boxes over the day, with the limit
 * and the verifier's alarms. A single series: the title names it. */
function progressChart(p: StationProgress): HTMLElement {
  const series = p.series;
  const W = 720;
  const H = 220;
  const L = 44;
  const R = 12;
  const T = 16;
  const B = 30;
  const values = series.map((x) => x.out ?? 0);
  const limit = p.limit ?? 0;
  const max = Math.max(limit + 4, ...values, 4);
  const min = Math.min(0, ...values);
  const x = (i: number) => L + (i * (W - L - R)) / Math.max(1, series.length - 1);
  const y = (val: number) => T + ((max - val) * (H - T - B)) / (max - min);
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
    add("text", { x: String(W - R), y: String(y(limit) - 4), class: "axis", "text-anchor": "end" }, `기준 L = ${limit}장`);
  }
  const d = series.map((pt, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(pt.out ?? 0).toFixed(1)}`).join(" ");
  add("path", { d, class: "line" });
  for (const a of p.alarms) {
    const i = series.findIndex((pt) => pt.slot === a.slot);
    if (i < 0) continue;
    const cx = x(i);
    const cy = y(series[i]!.out ?? 0);
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
    tip.textContent = `${slotTime(pt.slot)} 칸 · 교부 ${pt.issued} · 투입 ${pt.sheetsIn} · 훼손 ${pt.spoiled} · 반납 ${pt.returned} · 밖에 ${pt.out ?? "-"}장`;
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
    const o = el("option", { value: p.station }, `${label(election, "station", p.station)}${p.alarms.length ? ` · 경보 ${p.alarms.length}` : ""}${p.suspended ? " · 경보 멈춤" : ""}`);
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
              ...[pt.checkins, pt.issued, pt.sheetsIn, pt.spoiled, pt.returned, pt.out ?? 0].map((n) => el("td", { class: "num" }, String(n))),
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
    el(
      "p",
      { class: "muted" },
      `경보(검증기): ${chosen.alarms.length ? chosen.alarms.map((a) => `${ALARMS[a.alarm] ?? a.alarm} ${slotTime(a.slot)}`).join(", ") : "없음"} · 현장 확인 프레임: ${chosen.checks.join(", ") || "없음"}${chosen.suspended ? " · 비상 투입으로 경보 멈춤" : ""}${chosen.counterfoil ? " · 교부 번호 대조" : ""}`,
    ),
    el(
      "p",
      { class: "muted" },
      "경보와 멈춤은 검증기(verify_progress)의 판정이다. 칸별 수는 검증기가 받은 진행 기록의 값이고, 밖에 있는 장수는 ityv-state의 out_of로 계산했다(반출 장수는 넣지 않았다). 경보는 확인이 필요하다는 뜻이며 어떤 투표지도 무효가 되지 않는다.",
    ),
    table,
  );
}

function checkpointsCard(r: Report): HTMLElement {
  const c = r.checkpoints;
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "체크포인트", el("span", { class: "muted" }, ` 덮은 프레임 ${c?.covered ?? 0} / ${r.ledger?.treeSize ?? 0}`)),
    el(
      "div",
      { class: "scroll" },
      el(
        "table",
        {},
        el("thead", {}, el("tr", {}, el("th", {}, "순번"), el("th", {}, "프레임"), el("th", {}, "트리 크기"), el("th", {}, "체크포인트 지문 (Base32 32자)"))),
        el(
          "tbody",
          {},
          ...(c?.valid ?? []).map((v) =>
            el("tr", {}, el("td", { class: "num" }, String(v.seq)), el("td", { class: "num" }, String(v.frame)), el("td", { class: "num" }, String(v.treeSize)), el("td", {}, el("code", { class: "fp" }, v.fingerprint))),
          ),
        ),
      ),
    ),
    (c?.findings.length ?? 0) > 0
      ? el("p", { class: "warnline" }, icon("warn"), `사슬이 끝난 곳: ${c!.findings.map((f) => `프레임 ${f.frame} ${f.kind}`).join(", ")} · 확인하지 않은 체크포인트 ${c!.unchecked}개`)
      : null,
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
                el("tr", {}, el("td", { class: "num" }, String(x.seq)), el("td", {}, el("code", {}, x.schema ?? "-")), el("td", {}, STAGES[x.stage] ?? x.stage), el("td", {}, el("code", {}, x.reason))),
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
    el("ul", {}, ...list.map((d) => el("li", {}, `${d.type} · ${d.box ?? "-"} · ${d.status}${d.unresolved ? " (미해결)" : ""} · 접수 지문 `, el("code", {}, d.filing)))),
  );
}

function lookupCard(r: Report): HTMLElement {
  const input = el("input", { type: "text", placeholder: "추적코드(16진)", "aria-label": "추적코드", spellcheck: "false" });
  const out = el("div", { class: "lookup-out", "aria-live": "polite" });
  const btn = el("button", { class: "btn" }, "포함 확인");
  btn.addEventListener("click", async () => {
    const code = input.value.replace(/\s+/g, "").toLowerCase();
    const rec = (r.records ?? []).find((x) => x.code.startsWith(code) && code.length >= 16);
    if (!rec) {
      out.textContent = "이 번들의 공개원장에서 그 추적코드를 찾지 못했다.";
      return;
    }
    // The worker answers for the bundle it verified last (the self-test
    // may have verified others since): verify this one again if needed.
    const key = st.scenario?.name ?? st.fileName;
    if (lastVerified() !== key && st.bytes) await verifyBundle(st.bytes.slice(0), undefined, key);
    const inc = await inclusion(rec.seq);
    out.textContent = inc.included
      ? `프레임 ${rec.seq} (${rec.box}, ${rec.state})가 체크포인트 ${inc.checkpoint}(트리 크기 ${inc.treeSize})에 포함됨: ityv-ledger 포함 증명 ${inc.pathLength}단계를 검증한 root ${inc.root}에 대해 확인했다. 누구를 찍었는지는 알 수 없다.`
      : `프레임 ${rec.seq}는 공개원장에 있지만 아직 어느 체크포인트도 덮지 않았다.`;
  });
  const sample = st.scenario?.slips ?? [];
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
            });
            return a;
          }),
        )
      : null,
    out,
  );
}

function selfTestCard(): HTMLElement {
  const btn = el("button", { class: "btn" }, "빠른 시나리오 모두 자체 시험");
  btn.addEventListener("click", async () => {
    const list = st.index?.scenarios.filter((s) => s.set === "quick") ?? [];
    st.selftest = [];
    for (const s of list) {
      const r = await verifyBundle(await loadBundle(s.file), undefined, s.name);
      const ok = r.status === s.expected.status && sameHolds(s.expected.holds, r.holds ?? []);
      st.selftest.push({
        name: s.title,
        expected: `${s.expected.status} ${s.expected.holds.map((h) => h.code).join(",")}`,
        actual: `${r.status} ${(r.holds ?? []).map((h) => h.code).join(",")}`,
        ok,
      });
      rerender();
    }
  });
  const rows = st.selftest ?? [];
  return el(
    "section",
    { class: "card wide" },
    el("h2", {}, "자체 시험"),
    el("p", { class: "muted" }, "시뮬레이터의 기대(index.json)와 브라우저 안 검증기의 판정을 시나리오마다 비교한다. 같은 비교를 Rust 테스트도 한다."),
    btn,
    rows.length
      ? el(
          "table",
          { "data-testid": "selftest" },
          el("thead", {}, el("tr", {}, el("th", {}, "시나리오"), el("th", {}, "기대"), el("th", {}, "실제"), el("th", {}, ""))),
          el(
            "tbody",
            {},
            ...rows.map((x) =>
              el("tr", {}, el("td", {}, x.name), el("td", {}, el("code", {}, x.expected)), el("td", {}, el("code", {}, x.actual)), el("td", {}, el("span", { class: `flag ${x.ok ? "ok" : "bad"}` }, icon(x.ok ? "ok" : "fail"), x.ok ? " 같음" : " 불일치"))),
            ),
          ),
        )
      : null,
  );
}

function draw(root: HTMLElement): void {
  const r = st.report;
  const election = st.index?.elections.find((e) => e.id === st.scenario?.election) ?? null;
  const parts: (HTMLElement | null)[] = [picker(st.index)];
  if (st.busy) parts.push(el("section", { class: "card busy", "aria-live": "polite" }, icon("wait"), st.busy));
  if (st.error) parts.push(el("section", { class: "card warnline" }, icon("stop"), `오류: ${st.error}`));
  if (r && !r.error) {
    parts.push(
      el("p", { class: "muted" }, `${st.fileName ?? ""} · ${r.scenario ?? ""} · 검증 ${(st.elapsed / 1000).toFixed(1)}초 (브라우저 안 WASM)`),
    );
    parts.push(ladder(r));
    if (st.scenario) parts.push(expectedCard(st.scenario, r));
    parts.push(pinCard(r), holdsCard(r), stagesCard(r));
    if (r.genesis?.ok) {
      parts.push(unitsCard(r, election), progressCard(r, election), boxesCard(r, election), checkpointsCard(r), refusedCard(r), disputesCard(r), lookupCard(r));
    } else {
      parts.push(el("section", { class: "card warnline" }, icon("stop"), `genesis를 받지 못했다: ${r.genesis?.error ?? ""}. genesis는 전부 아니면 전무이므로 그 위의 어떤 단계도 진행하지 않았다.`));
    }
  }
  parts.push(selfTestCard());
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
          "고른 번들을 이 브라우저 안에서 실제 공개 검증기(ityv-verify를 WebAssembly로 빌드한 것)가 검증한다. 서버를 믿지 않는다. 이 콘솔은 읽기만 하며 어떤 장치에도 명령하지 않는다.",
        ),
        el("p", { class: "muted" }, st.index?.note ?? ""),
      ),
      ...parts.filter((x): x is HTMLElement => x !== null),
    ),
  );
}
