// ityv console: the read-only public verification dashboard and the
// device screen prototypes. Hash routes: #/dashboard[?scenario=…] and
// #/devices/<device>[?state=…&zoom=…&hc=1&detail=1].

import type { SimIndex } from "./data";
import { renderDashboard } from "./dashboard";
import { parseParams, renderDevices } from "./devices";
import { el } from "./render";
import { loadIndex } from "./verifier";

let index: SimIndex | null = null;

async function route(): Promise<void> {
  const main = document.getElementById("main");
  if (!main) return;
  const [path = "", query = ""] = location.hash.replace(/^#/, "").split("?");
  const q = new URLSearchParams(query);
  const parts = path.split("/").filter(Boolean);
  for (const a of document.querySelectorAll<HTMLAnchorElement>("header nav a")) {
    a.classList.toggle("on", a.dataset.route === (parts[0] ?? "dashboard"));
  }
  try {
    if (parts[0] === "devices") {
      await renderDevices(main, index, parseParams(parts[1] ?? "scanner-voter", q));
    } else {
      renderDashboard(main, index, q.get("scenario"));
    }
    document.body.dataset.ready = "1";
  } catch (e) {
    main.replaceChildren(el("p", { class: "card warnline" }, `오류: ${String(e)}`));
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
