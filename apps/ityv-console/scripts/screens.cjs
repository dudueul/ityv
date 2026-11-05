// Screen capture check (docs/ui/SCREENS.md §8): every state of every
// device prototype at 1×, 1.5× and 2×, normal and high contrast, with and
// without the software detail view. In each the identity line must be
// visible, the last row of the screen, fully drawn (not clipped) and not
// covered by anything; body text ≥ 4% and the identity line ≥ 2.5% of the
// screen height. Also: no horizontal page scroll at phone width.
// Screenshots are of the frame together with its demo legend (hatched
// values are demonstration values, not ledger values).
//
// Usage: node scripts/screens.cjs [outdir]
//   ITYV_CONSOLE_URL  a running console (default: starts `bun server.ts`)
//   BUN               the bun binary (default: bun on PATH)
// Uses the Chromium and Playwright installed on the machine; it is not a
// dependency of this package.

const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const outdir = process.argv[2] || path.join(__dirname, "..", "screens-out");
fs.mkdirSync(outdir, { recursive: true });

async function waitFor(url, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no server at ${url}`);
}

let server = null;

async function main() {
  let base = process.env.ITYV_CONSOLE_URL;
  if (!base) {
    const port = 3170 + Math.floor(Math.random() * 20);
    base = `http://127.0.0.1:${port}/`;
    server = spawn(process.env.BUN || "bun", ["server.ts"], {
      cwd: path.join(__dirname, ".."),
      env: { ...process.env, PORT: String(port) },
      stdio: "ignore",
    });
    await waitFor(base, 30000);
  }
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  await page.goto(base);
  await page.waitForFunction(() => document.body.dataset.ready === "1", null, { timeout: 60000 });

  const show = async (hash) => {
    await page.evaluate((h) => {
      document.body.dataset.ready = "0";
      // Setting the same hash fires no hashchange: re-route explicitly.
      if (location.hash === h) window.dispatchEvent(new HashChangeEvent("hashchange"));
      else location.hash = h;
    }, hash);
    await page.waitForFunction(() => document.body.dataset.ready === "1", null, { timeout: 120000 });
  };

  // Device and state ids, from the page's own picker.
  await show("#/devices/scanner-voter");
  const devices = await page.$$eval(".device-nav a", (as) => as.map((a) => a.getAttribute("href").split("?")[0].split("/").pop()));
  let checks = 0;
  const failures = [];
  for (const device of devices) {
    await show(`#/devices/${device}`);
    const states = await page.$$eval(".picker [data-state]", (as) => as.map((a) => a.dataset.state));
    for (const state of states) {
      for (const zoom of [1, 1.5, 2]) {
        for (const hc of [false, true]) {
          for (const detail of [false, true]) {
            const q = new URLSearchParams({ state });
            if (zoom !== 1) q.set("zoom", String(zoom));
            if (hc) q.set("hc", "1");
            if (detail) q.set("detail", "1");
            await show(`#/devices/${device}?${q}`);
            const r = await page.evaluate(() => {
              const scr = document.querySelector("[data-testid=screen]");
              const id = scr && scr.querySelector("[data-testid=identity-line]");
              if (!scr || !id) return { error: "no screen or identity line" };
              scr.scrollIntoView({ block: "center" });
              const s = scr.getBoundingClientRect();
              const b = id.getBoundingClientRect();
              const text = id.querySelector(".idtext");
              const covered = [];
              for (const f of [0.02, 0.25, 0.5, 0.75, 0.98]) {
                const x = b.left + b.width * f;
                const y = b.top + b.height / 2;
                const hit = document.elementFromPoint(x, y);
                if (!hit || !id.contains(hit)) covered.push(`${Math.round(x)},${Math.round(y)}:${hit ? hit.className || hit.tagName : "none"}`);
              }
              const content = scr.querySelector(".content");
              const bodySize = parseFloat(getComputedStyle(content).fontSize);
              const idSize = parseFloat(getComputedStyle(id).fontSize);
              const style = getComputedStyle(id);
              return {
                visible: b.width > 0 && b.height > 0 && style.visibility === "visible" && style.display !== "none" && Number(style.opacity) === 1,
                atBottom: Math.abs(b.bottom - s.bottom) <= 1.5 && b.left >= s.left - 0.5 && b.right <= s.right + 0.5,
                inViewport: b.top >= 0 && b.bottom <= window.innerHeight,
                clipped: text.scrollWidth > text.clientWidth + 1,
                covered,
                bodyRatio: bodySize / s.height,
                idRatio: idSize / s.height,
              };
            });
            checks++;
            const name = `${device}-${state}-z${zoom}${hc ? "-hc" : ""}${detail ? "-detail" : ""}`;
            const problems = [];
            if (r.error) problems.push(r.error);
            else {
              if (!r.visible) problems.push("identity line not visible");
              if (!r.atBottom) problems.push("identity line not the bottom row of the screen");
              if (!r.inViewport) problems.push("identity line outside the viewport");
              if (r.clipped) problems.push("identity line clipped");
              if (r.covered.length) problems.push(`identity line covered at ${r.covered.join(" ")}`);
              if (r.bodyRatio < 0.04 * zoom - 0.001) problems.push(`body text ${(r.bodyRatio * 100).toFixed(1)}% of screen height`);
              if (r.idRatio < 0.025) problems.push(`identity line ${(r.idRatio * 100).toFixed(1)}% of screen height`);
            }
            if (problems.length) failures.push(`${name}: ${problems.join("; ")}`);
            if (!detail) {
              // The frame with the legend outside it that says which values
              // (hatched) are demonstration values.
              const shot = await page.$("[data-testid=device-shot]");
              await shot.screenshot({ path: path.join(outdir, `${name}.png`) });
            }
          }
        }
      }
    }
  }

  // Phone width: no horizontal page scroll, identity line still at the
  // bottom of each screen.
  await page.setViewportSize({ width: 375, height: 800 });
  for (const hash of ["#/dashboard?scenario=quick-clean", ...devices.map((d) => `#/devices/${d}`)]) {
    await show(hash);
    if (hash.startsWith("#/dashboard")) await page.waitForSelector("[data-testid=status]", { timeout: 60000 });
    const r = await page.evaluate(() => ({
      scroll: document.scrollingElement.scrollWidth,
      width: window.innerWidth,
    }));
    checks++;
    if (r.scroll > r.width + 1) failures.push(`${hash} at 375px: page scrolls sideways (${r.scroll} > ${r.width})`);
    const name = hash.replace(/[^a-z0-9-]+/gi, "_").replace(/^_+/, "");
    await page.screenshot({ path: path.join(outdir, `phone-${name}.png`), fullPage: true });
  }

  await browser.close();
  if (server) server.kill();
  console.log(`screen checks: ${checks}, failures: ${failures.length}, page errors: ${errors.length}`);
  for (const f of failures) console.log(`FAIL ${f}`);
  for (const e of errors) console.log(`ERROR ${e}`);
  console.log(`screenshots: ${outdir}`);
  process.exit(failures.length || errors.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  if (server) server.kill();
  process.exit(1);
});
