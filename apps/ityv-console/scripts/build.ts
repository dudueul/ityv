// Static build: Bun's bundler over index.html into dist/, the page's
// Content Security Policy written into dist/index.html, then the files
// the page fetches at run time (worker, WASM verifier, bundles).

import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { CSP } from "./csp";

const root = `${import.meta.dir}/..`;
const dist = `${root}/dist`;
rmSync(dist, { recursive: true, force: true });
const result = await Bun.build({
  entrypoints: [`${root}/index.html`],
  outdir: dist,
  minify: true,
  target: "browser",
});
if (!result.success) {
  console.error(result.logs);
  process.exit(1);
}
const html = `${dist}/index.html`;
const page = readFileSync(html, "utf8");
const charset = /<meta charset="?utf-8"?\s*\/?>/i;
if (!charset.test(page) || /<script(?![^>]*\bsrc=)[^>]*>/i.test(page) || /<style/i.test(page)) {
  // The policy allows no inline script or style; a build that emits one
  // would be broken by it.
  console.error("dist/index.html: no charset <meta>, or an inline <script>/<style>");
  process.exit(1);
}
// Right after the charset, before any script or stylesheet.
writeFileSync(html, page.replace(charset, (m) => `${m}\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`));
for (const f of ["verify-worker.js", "ityv_wasm.wasm", "bundles"]) {
  const src = `${root}/public/${f}`;
  if (!existsSync(src)) {
    console.error(`missing public/${f}: run \`bun run data\` first`);
    process.exit(1);
  }
  cpSync(src, `${dist}/${f}`, { recursive: true });
}
console.log(`built ${result.outputs.length} files into dist/ (plus worker, wasm, bundles), CSP: ${CSP}`);
