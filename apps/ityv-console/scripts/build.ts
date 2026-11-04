// Static build: Bun's bundler over index.html into dist/, then the files
// the page fetches at run time (worker, WASM verifier, bundles).

import { cpSync, existsSync, rmSync } from "node:fs";

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
for (const f of ["verify-worker.js", "ityv_wasm.wasm", "bundles"]) {
  const src = `${root}/public/${f}`;
  if (!existsSync(src)) {
    console.error(`missing public/${f}: run \`bun run data\` first`);
    process.exit(1);
  }
  cpSync(src, `${dist}/${f}`, { recursive: true });
}
console.log(`built ${result.outputs.length} files into dist/ (plus worker, wasm, bundles)`);
