// Builds what the console serves but does not commit: the WASM verifier
// (cargo build -p ityv-wasm --target wasm32-unknown-unknown --release) and
// the simulator's scenario bundles (cargo run -p ityv-sim -- <outdir>).
//
// ITYV_SIM_SET=quick   the small set (CI and quick checks); default: full.
// ITYV_SIM_PROFILE     cargo profile for the simulator (default: release).

import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";

const here = import.meta.dir;
const console_ = `${here}/..`;
const workspace = `${console_}/../..`;
const target = process.env.CARGO_TARGET_DIR ?? `${workspace}/target`;
const out = `${console_}/public/bundles`;
const quick = process.env.ITYV_SIM_SET === "quick";
const profile = process.env.ITYV_SIM_PROFILE ?? "release";

function run(cmd: string[]): void {
  console.log(`$ ${cmd.join(" ")}`);
  const r = Bun.spawnSync(cmd, { cwd: workspace, stdout: "inherit", stderr: "inherit" });
  if (!r.success) {
    console.error(`failed: ${cmd.join(" ")}`);
    process.exit(1);
  }
}

run(["cargo", "build", "--locked", "-p", "ityv-wasm", "--target", "wasm32-unknown-unknown", "--release"]);
const wasm = `${target}/wasm32-unknown-unknown/release/ityv_wasm.wasm`;
if (!existsSync(wasm)) {
  console.error(`missing ${wasm}`);
  process.exit(1);
}
mkdirSync(`${console_}/public`, { recursive: true });
cpSync(wasm, `${console_}/public/ityv_wasm.wasm`);

rmSync(out, { recursive: true, force: true });
run([
  "cargo",
  "run",
  "--locked",
  ...(profile === "dev" ? [] : ["--profile", profile]),
  "-p",
  "ityv-sim",
  "--",
  ...(quick ? ["--quick"] : []),
  out,
]);
