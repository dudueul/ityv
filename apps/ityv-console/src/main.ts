// ityv console: the read-only public verification dashboard and the
// device screen prototypes. Hash routes: #/dashboard[?scenario=…] and
// #/devices/<device>[?state=…&zoom=…&hc=1&detail=1].

import type { SimIndex } from "./data";
import { leaveDashboard, renderDashboard } from "./dashboard";
import { leaveDevices, parseParams, renderDevices } from "./devices";
import { el } from "./render";
import { loadIndex } from "./verifier";

let index: SimIndex | null = null;
/** Each navigation's ticket: an older render stops without drawing. */
let routeTicket = 0;

async function route(): Promise<void> {
  const main = document.getElementById("main");
  if (!main) return;
  const ticket = ++routeTicket;
  const current = () => ticket === routeTicket;
  const [path = "", query = ""] = location.hash.replace(/^#/, "").split("?");
  const q = new URLSearchParams(query);
  const parts = path.split("/").filter(Boolean);
  for (const a of document.querySelectorAll<HTMLAnchorElement>("header nav a")) {
    a.classList.toggle("on", a.dataset.route === (parts[0] ?? "dashboard"));
  }
  try {
    if (parts[0] === "devices") {
      // Leaving the dashboard stops its self-test and verification.
      leaveDashboard();
      await renderDevices(main, index, parseParams(parts[1] ?? "scanner-voter", q), current);
    } else {
      leaveDevices();
      renderDashboard(main, index, q.get("scenario"));
    }
    if (current()) document.body.dataset.ready = "1";
  } catch (e) {
    if (!current()) return;
    main.replaceChildren(el("p", { class: "card warnline" }, `오류: ${String(e instanceof Error ? e.message : e)}`));
    document.body.dataset.ready = "error";
  }
}

async function start(): Promise<void> {
  index = await loadIndex();
  window.addEventListener("hashchange", () => {
    document.body.dataset.ready = "0";
    void route();
  });
  await route();
}

void start();
