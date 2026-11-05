// Browser checks of the dashboard's request handling and the pages' error
// paths, from the review's repros: rapid scenario switches never mix one
// scenario's metadata with another's report; metadata follows the bytes,
// not the file name; a trap in the module shows an error and the next
// request works on a fresh worker; a lookup during the self-test answers
// from the shown report and survives the self-test's redraws; the
// self-test stops on navigation; the voter app's answer does not depend on
// the self-test; an unknown device state falls back with a notice; the
// status badge shows no check until an outside pin is used; the audit card
// shows the seed's inputs, the binding checkpoint's time against the
// beacon publication (labelled fixture data), its timestamp tokens and
// each style's rounds and draws, and verifying without the beacon
// observation stays at the tally; the checkpoints card shows each
// checkpoint's anchoring and the roll card the custody of the freeze and
// each amendment against the quorum; malformed URL escapes get 400; the
// built page works under its CSP.
//
// Usage: node scripts/races.cjs
//   ITYV_CONSOLE_URL  a running dev console (default: starts `bun server.ts`)
//   ITYV_DIST_URL     a running `bun run preview` (default: starts it when
//                     dist/ exists; skipped otherwise)
//   BUN               the bun binary (default: bun on PATH)
// Uses the Chromium and Playwright installed on the machine; it is not a
// dependency of this package.

const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const here = path.join(__dirname, "..");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const failures = [];
let checks = 0;
/** Servers this run started; stopped on every exit. */
const started = [];

function check(name, ok, detail = "") {
  checks++;
  if (!ok) failures.push(`${name}${detail ? `: ${detail}` : ""}`);
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${!ok && detail ? ` (${detail})` : ""}`);
}

async function waitFor(url, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {}
    await sleep(200);
  }
  throw new Error(`no server at ${url}`);
}

/** Starts `script` on a free port of 3190–3199 (never the 3000 of a dev
 * server someone else runs). */
async function serve(script, env) {
  let port = 0;
  for (let p = 3190 + Math.floor(Math.random() * 10), n = 0; n < 10; n++, p = 3190 + ((p - 3190 + 1) % 10)) {
    const taken = await fetch(`http://127.0.0.1:${p}/`).then(() => true, () => false);
    if (!taken) {
      port = p;
      break;
    }
  }
  if (!port) throw new Error("no free port in 3190-3199");
  const base = `http://127.0.0.1:${port}/`;
  const child = spawn(process.env.BUN || "bun", [script], {
    cwd: here,
    env: { ...process.env, ...env, PORT: String(port) },
    stdio: "ignore",
  });
  await waitFor(base, 30000);
  return { base, child };
}

/** A page with error capture, a log of worker requests and CSP
 * violations. */
async function open(browser, base, hash = "#/dashboard", init = null) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1600 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => m.type() === "error" && errors.push(`console: ${m.text()}`));
  await page.addInitScript(() => {
    window.__requests = [];
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
    const post = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (m, t) {
      window.__requests.push({ type: m.type, bytes: m.bundle ? m.bundle.byteLength : 0, at: performance.now() });
      return post.call(this, m, t);
    };
  });
  if (init) await init(page);
  await page.goto(base + hash);
  await page.waitForFunction(() => document.body.dataset.ready === "1", null, { timeout: 60000 });
  return { page, errors };
}

async function go(page, hash) {
  await page.evaluate((h) => {
    document.body.dataset.ready = "0";
    if (location.hash === h) window.dispatchEvent(new HashChangeEvent("hashchange"));
    else location.hash = h;
  }, hash);
  await page.waitForFunction(() => document.body.dataset.ready === "1", null, { timeout: 60000 });
}

const statusOf = (page) => page.evaluate(() => document.querySelector("[data-testid=status] .status")?.dataset.status ?? null);

async function waitStatus(page) {
  await page.waitForSelector("[data-testid=status]", { timeout: 120000 });
}

/** Drops `bytes` as a file named `name` on the dashboard. */
async function drop(page, name, bytes) {
  await page.setInputFiles("input[type=file]", { name, mimeType: "application/octet-stream", buffer: bytes });
}

async function main() {
  let base = process.env.ITYV_CONSOLE_URL;
  if (!base) {
    const s = await serve("server.ts", {});
    base = s.base;
    started.push(s.child);
  }
  const index = await (await fetch(`${base}bundles/index.json`)).json();
  const byName = Object.fromEntries(index.scenarios.map((s) => [s.name, s]));
  const bundle = async (name) => Buffer.from(await (await fetch(`${base}bundles/${byName[name].file}`)).arrayBuffer());
  const browser = await chromium.launch();

  // 1. Rapid switches: every rendered result is one scenario's, whole.
  {
    const { page, errors } = await open(browser, base);
    await page.evaluate(() => {
      window.__seen = [];
      const snap = () => {
        const meta = document.querySelector("[data-testid=result-meta]")?.textContent ?? null;
        if (!meta) return;
        window.__seen.push({
          meta,
          status: document.querySelector("[data-testid=status] .status")?.dataset.status ?? null,
          expected: document.querySelector("[data-testid=expected] .muted")?.textContent ?? null,
        });
      };
      new MutationObserver(snap).observe(document.getElementById("main"), { childList: true, subtree: true });
    });
    for (const name of ["quick-clean", "attack-tampered-record", "quick-voting", "attack-checkpoint-fork"]) {
      await page.evaluate((n) => {
        location.hash = `#/dashboard?scenario=${n}`;
      }, name);
      await sleep(40);
    }
    await page.waitForFunction(
      () => (document.querySelector("[data-testid=result-meta]")?.textContent ?? "").includes("attack-checkpoint-fork"),
      null,
      { timeout: 120000 },
    );
    await sleep(1500);
    const seen = await page.evaluate(() => window.__seen);
    const mixed = seen.filter((x) => {
      const m = /시나리오 ([\w-]+)/.exec(x.meta);
      if (!m) return true;
      const s = byName[m[1]];
      return !s || x.status !== s.expected.status || !(x.expected ?? "").includes(s.name);
    });
    check("rapid switches never mix scenario metadata and report", seen.length > 0 && mixed.length === 0, JSON.stringify(mixed.slice(0, 2)));
    check("rapid switches end on the last scenario", (seen.at(-1)?.meta ?? "").includes("attack-checkpoint-fork"));
    check("rapid switches: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 2. Metadata follows the bytes: a renamed attack bundle gets the attack's
  // metadata; a changed byte gets none.
  {
    const { page, errors } = await open(browser, base);
    await drop(page, "quick-clean.ityvb", await bundle("attack-tampered-record"));
    await waitStatus(page);
    const meta = await page.textContent("[data-testid=result-meta]");
    const exp = (await page.textContent("[data-testid=expected]").catch(() => "")) ?? "";
    check(
      "a renamed bundle is described by its bytes, not its name",
      meta.includes("파일 quick-clean.ityvb") && meta.includes("시나리오 attack-tampered-record") && exp.includes("attack-tampered-record"),
      meta,
    );
    const changed = await bundle("quick-clean");
    changed[changed.length - 3] ^= 1;
    await drop(page, "quick-clean.ityvb", changed);
    await page.waitForFunction(() => (document.querySelector("[data-testid=result-meta]")?.textContent ?? "").includes("index.json에 없는"), null, {
      timeout: 60000,
    });
    check("a changed bundle gets no scenario metadata", (await page.$("[data-testid=expected]")) === null);
    const election = await page.textContent("[data-testid=election]");
    check("the verified election ID is shown with the synthetic banner", /검증한 선거: SIM-/.test(election) && election.includes("합성 선거"), election);
    check("metadata: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 3. A trap in the module: the worker is replaced, the error shown, the
  // report cleared; the next request works. The trap is injected into the
  // worker for one byte length (no real bundle traps the module).
  {
    const TRAP = 4321;
    const worker = fs.readFileSync(path.join(here, "public", "verify-worker.js"), "utf8");
    const trapping = `${worker}
const __run = run;
run = function (ex, data) {
  if (data.type === "verify" && data.bundle.byteLength === ${TRAP}) throw new WebAssembly.RuntimeError("unreachable (injected)");
  return __run(ex, data);
};`;
    const { page, errors } = await open(browser, base, "#/dashboard?scenario=quick-clean", (p) =>
      p.route("**/verify-worker.js", (r) => r.fulfill({ contentType: "text/javascript", body: trapping })),
    );
    await waitStatus(page);
    await drop(page, "trap.ityvb", Buffer.alloc(TRAP, 7));
    await page.waitForSelector("[data-testid=error]", { timeout: 30000 });
    const err = await page.textContent("[data-testid=error]");
    check("a trap shows an error", err.includes("unreachable"), err);
    check("a trap clears the shown report", (await page.$("[data-testid=status]")) === null);
    await go(page, "#/dashboard?scenario=attack-tampered-record");
    await waitStatus(page);
    check("after a trap the next request works", (await statusOf(page)) === byName["attack-tampered-record"].expected.status);
    // Pick, then drop the trapping file while the pick is in flight: only
    // the drop's outcome is shown.
    await go(page, "#/dashboard?scenario=quick-voting");
    await drop(page, "trap.ityvb", Buffer.alloc(TRAP, 7));
    await page.waitForSelector("[data-testid=error]", { timeout: 30000 });
    await sleep(2500);
    check("a drop during a pick: the pick's result never appears", (await page.$("[data-testid=status]")) === null);
    check("trap: only the injected errors", errors.every((e) => e.includes("unreachable")), errors.join(" | "));
    await page.close();
  }

  // 4. Lookup during the self-test; the self-test stops on navigation; the
  // voter app's answer does not depend on it.
  {
    const { page, errors } = await open(browser, base, "#/dashboard?scenario=quick-clean");
    await waitStatus(page);
    await page.click("button[data-action=selftest]");
    await sleep(200);
    await page.click(".chip");
    await page.click("button[data-action=lookup]");
    const out = await page.textContent("[data-testid=lookup-out]");
    check("a lookup answers from the shown report", out.includes("포함됨") || out.includes("덮지 않았다"), out);
    await page.waitForFunction(() => document.querySelectorAll("[data-testid=selftest] tbody tr").length >= 3, null, { timeout: 120000 });
    const kept = await page.evaluate(() => ({
      code: document.querySelector("input[aria-label=추적코드]")?.value ?? "",
      out: document.querySelector("[data-testid=lookup-out]")?.textContent ?? "",
    }));
    check("the lookup's input and answer survive the self-test", kept.code.length > 0 && kept.out === out, JSON.stringify(kept));

    await go(page, "#/devices/voter-app?state=uncovered");
    const during = await page.textContent("[data-testid=screen] .content");
    const before = await page.evaluate(() => window.__requests.filter((r) => r.type === "verify").length);
    await sleep(4000);
    const after = await page.evaluate(() => window.__requests.filter((r) => r.type === "verify").length);
    check("the self-test stops on navigation", after === before, `${before} -> ${after}`);
    await go(page, "#/devices/voter-app?state=uncovered");
    const quiet = await page.textContent("[data-testid=screen] .content");
    check("the voter app's answer does not depend on the self-test", during === quiet, `${during} / ${quiet}`);
    await go(page, "#/dashboard");
    const state = await page.textContent("[data-testid=selftest-state]").catch(() => "");
    check("a stopped self-test says it stopped", (state ?? "").includes("멈춤"), state ?? "");
    check("self-test: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 4b. The whole self-test agrees with the simulator on every quick
  // scenario (bundle hash, status, holds).
  {
    const { page, errors } = await open(browser, base);
    await page.click("button[data-action=selftest]");
    const quick = index.scenarios.filter((x) => x.set === "quick").length;
    await page.waitForFunction(() => (document.querySelector("[data-testid=selftest-state]")?.textContent ?? "").startsWith("끝"), null, {
      timeout: 300000,
    });
    const rows = await page.$$eval("[data-testid=selftest] tbody tr", (trs) => trs.map((tr) => tr.textContent));
    const bad = rows.filter((r) => !r.includes("같음"));
    check("the self-test agrees on every quick scenario", rows.length === quick && bad.length === 0, `${rows.length}/${quick} ${bad.join(" | ")}`);
    check("self-test run: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 5. The status badge: no check mark until an outside pin is used.
  {
    const { page, errors } = await open(browser, base, "#/dashboard?scenario=quick-clean");
    await waitStatus(page);
    const badge = await page.evaluate(() => {
      const b = document.querySelector("[data-testid=status]");
      return { text: b.textContent, check: !!b.querySelector(".icon-ok") };
    });
    check("under the bundle's pin the badge says so and has no check", badge.text.includes("번들에 든 핀으로") && !badge.check, JSON.stringify(badge));
    const rungs = await page.$$eval(".ladder .icon-rung", (xs) => new Set(xs.map((x) => x.getAttribute("class"))).size);
    check("every rung has its own icon", rungs === 5, String(rungs));
    const hex = await page.textContent("details code.fp");
    await page.fill("input[aria-label='genesis 핀']", hex.trim());
    await page.click("button[data-action=repin]");
    await page.waitForFunction(() => !!document.querySelector("[data-testid=status] .icon-ok"), null, { timeout: 60000 });
    const pinned = await page.textContent("[data-testid=status]");
    check("under an outside pin the badge has the check and no bundle note", !pinned.includes("번들에 든 핀으로"), pinned);
    await page.fill("input[aria-label='genesis 핀']", "ab".repeat(64));
    await page.click("button[data-action=repin]");
    await page.waitForFunction(() => (document.querySelector("[data-testid=status] .status")?.dataset.status ?? "") === "HOLD_REVIEW", null, {
      timeout: 60000,
    });
    check("a wrong outside pin holds, without a check", (await page.$("[data-testid=status] .icon-ok")) === null);
    const ladder = await page.textContent(".hero");
    check(
      "the ladder says what no machine reaches and what PAPER_AUDITED needs",
      ladder.includes("LEGAL_CERTIFIED: 기계가 닿는 상태가 아니다") && ladder.includes("비콘 공표") && ladder.includes("고정 자료"),
    );
    check("badge: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 5b. The audit card.
  {
    const word = (page) => page.evaluate(() => document.querySelector("[data-testid=status] .status")?.dataset.status ?? "");
    const { page, errors } = await open(browser, base, "#/dashboard?scenario=audit-clean");
    await waitStatus(page);
    check("an audited ledger reaches PAPER_AUDITED", (await word(page)) === "PAPER_AUDITED", await word(page));
    const card = await page.textContent("[data-testid=audit]");
    check("the audit card labels the beacon observation as fixture data", (await page.$("[data-testid=beacon-fixture]")) !== null && card.includes("시연용 고정 자료"));
    const timing = await page.$$eval("[data-testid=audit-timing] li", (xs) => xs.map((x) => !!x.querySelector(".icon-ok")));
    check("the binding checkpoint precedes the publication by the margin and both kinds stamped it before", timing.length === 4 && timing.every(Boolean), JSON.stringify(timing));
    const tokens = await page.$$eval("[data-testid=binding-tokens] li", (xs) => xs.map((x) => ({ ok: !!x.querySelector(".icon-ok"), text: x.textContent })));
    check(
      "the binding checkpoint's tokens are listed, both before the seed and the publication",
      tokens.length === 2 && tokens.every((t) => t.ok && t.text.includes("시드 앞 프레임") && t.text.includes("공표 구간 전")),
      JSON.stringify(tokens),
    );
    check("the timeline is drawn", (await page.$("[data-testid=audit] svg.timeline")) !== null);
    const styles = await page.$$eval("[data-testid=audit] .style-audit", (xs) => xs.map((x) => x.dataset.style));
    check("every style has its audit", styles.length === 2, styles.join(","));
    const heads = await page.$$eval("[data-testid=audit] .style-audit table thead", (xs) => xs.map((x) => x.textContent));
    check(
      "the drawn records show public information only",
      heads.some((h) => h.includes("추적코드")) && heads.every((h) => !h.includes("cast id") && !h.includes("난수") && !h.includes("선택지")),
    );
    await page.click("input[data-action=beacon]");
    await page.waitForFunction(() => (document.querySelector("[data-testid=status] .status")?.dataset.status ?? "") === "CRYPTO_TALLY_VERIFIED", null, { timeout: 60000 });
    check("without the beacon observation the ledger stays at the tally", (await word(page)) === "CRYPTO_TALLY_VERIFIED");
    check("without the observation the card says so", (await page.textContent("[data-testid=audit]")).includes("비콘 관찰 없이 검증했다"));
    await page.click("input[data-action=beacon]");
    await page.waitForFunction(() => (document.querySelector("[data-testid=status] .status")?.dataset.status ?? "") === "PAPER_AUDITED", null, { timeout: 60000 });
    check("with it again PAPER_AUDITED", (await word(page)) === "PAPER_AUDITED");
    await page.goto(`${base}#/dashboard?scenario=audit-escalation`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("audit-escalation"), null, { timeout: 60000 });
    const rounds = await page.$$eval("[data-testid=audit-rounds] tbody tr", (xs) => xs.map((x) => x.textContent));
    check("an escalation shows the first round exceeded and the second concluded", rounds.some((r) => r.includes("상한 넘음")) && rounds.some((r) => r.includes("종료")), rounds.join(" | "));
    await page.goto(`${base}#/dashboard?scenario=attack-seed-grinding`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("attack-seed-grinding"), null, { timeout: 60000 });
    const late = await page.$$eval("[data-testid=audit-timing] li", (xs) => xs.map((x) => !!x.querySelector(".icon-ok")));
    check("a binding checkpoint two buckets before the publication fails the margin, and its honest tokens come after", late.length === 4 && late[2] === false && late[3] === false, JSON.stringify(late));
    check("the grinding seed is refused as late", (await page.textContent("[data-testid=audit-refused]")).includes("Late"));
    await page.goto(`${base}#/dashboard?scenario=attack-binding-unstamped`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("attack-binding-unstamped"), null, { timeout: 60000 });
    const unstamped = await page.$$eval("[data-testid=audit-timing] li", (xs) => xs.map((x) => !!x.querySelector(".icon-ok")));
    check("one kind of token fails the token check only", unstamped.length === 4 && unstamped[2] === true && unstamped[3] === false, JSON.stringify(unstamped));
    check("the unstamped seed is refused", (await page.textContent("[data-testid=audit-refused]")).includes("Unstamped"));
    check("audit: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 5c. Checkpoint anchoring and roll custody.
  {
    const { page, errors } = await open(browser, base, "#/dashboard?scenario=quick-roll-amended");
    await waitStatus(page);
    const anchors = await page.$$eval("[data-testid=checkpoint-rows] tr", (xs) => xs.map((x) => x.textContent));
    check("every checkpoint of a clean ledger is anchored by both kinds", anchors.length > 0 && anchors.every((t) => t.includes("충족") && !t.includes("미충족")), anchors.join(" | "));
    const roll = await page.$$eval("[data-testid=roll-rows] tr", (xs) => xs.map((x) => x.textContent));
    check(
      "the roll card shows the freeze and the amendment in effect with three of three receipts",
      roll.length === 2 && roll.every((t) => t.includes("3 / 3") && t.includes("효력 있음")),
      roll.join(" | "),
    );
    await page.goto(`${base}#/dashboard?scenario=fault-roll-amendment-short`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("fault-roll-amendment-short"), null, { timeout: 60000 });
    const short = await page.$$eval("[data-testid=roll-rows] tr", (xs) => xs.map((x) => x.textContent));
    check("an amendment short of the quorum shows two of three and no effect", short.length === 2 && short[1].includes("2 / 3") && short[1].includes("효력 없음"), short.join(" | "));
    await page.goto(`${base}#/dashboard?scenario=quick-anchor-pending`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("quick-anchor-pending"), null, { timeout: 60000 });
    const pending = await page.$$eval("[data-testid=checkpoint-rows] tr", (xs) => xs.map((x) => x.textContent));
    check("the last checkpoint stamped by one kind is not anchored", pending.length > 0 && pending[pending.length - 1].includes("미충족"), pending.join(" | "));
    await page.goto(`${base}#/dashboard?scenario=attack-tsa-unpinned`);
    await page.waitForFunction(() => document.querySelector("[data-testid=result-meta]")?.textContent?.includes("attack-tsa-unpinned"), null, { timeout: 60000 });
    check("a refused timestamp record is listed", ((await page.textContent("[data-testid=timestamp-refusals]").catch(() => "")) ?? "").includes("TSA-GOV-SIM"));
    check("timestamps and roll: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 6. An unknown device state falls back with a notice.
  {
    const { page, errors } = await open(browser, base, "#/devices/scanner-voter?state=bogus");
    check("an unknown state shows a notice", (await page.$("[data-testid=unknown-state]")) !== null);
    check("an unknown state still draws the screen", (await page.$("[data-testid=screen]")) !== null);
    check("unknown state: no page errors", errors.length === 0, errors.join(" | "));
    await page.close();
  }

  // 7. Malformed escapes.
  {
    const r = await fetch(`${base}bundles/%E0%A4%A`);
    check("a malformed % escape gets 400", r.status === 400, String(r.status));
  }

  // 8. The built page under its CSP.
  let dist = process.env.ITYV_DIST_URL;
  if (!dist && fs.existsSync(path.join(here, "dist", "index.html"))) {
    const s = await serve("scripts/preview.ts", {});
    dist = s.base;
    started.push(s.child);
  }
  if (dist) {
    const { page, errors } = await open(browser, dist, "#/dashboard?scenario=quick-clean");
    await waitStatus(page);
    await go(page, "#/devices/observer-progress");
    await go(page, "#/devices/scanner-voter?zoom=2&hc=1");
    const csp = await page.evaluate(() => window.__csp);
    const errs = [...errors];
    const meta = await page.evaluate(() => document.querySelector("meta[http-equiv=Content-Security-Policy]")?.content ?? "");
    check("dist: the page carries its CSP", meta.includes("default-src 'self'"), meta);
    // After the violations were read: an inline script must not run.
    const enforced = await page.evaluate(async () => {
      const el = document.createElement("script");
      el.textContent = "window.__inline = 1";
      document.head.append(el);
      await new Promise((r) => setTimeout(r, 100));
      return window.__inline === undefined && window.__csp.some((v) => v.startsWith("script-src"));
    });
    check("dist: the CSP is enforced (an inline script is refused)", enforced);
    check("dist: the dashboard and devices work under the CSP", csp.length === 0 && errs.length === 0, [...csp, ...errs].join(" | "));
    await page.close();
  } else {
    console.log("skip dist (no dist/; run `bun run build`)");
  }

  await browser.close();
  for (const c of started) c.kill();
  console.log(`race checks: ${checks}, failures: ${failures.length}`);
  for (const f of failures) console.log(`FAIL ${f}`);
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  for (const c of started) c.kill();
  process.exit(1);
});
