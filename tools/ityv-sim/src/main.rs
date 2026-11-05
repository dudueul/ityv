//! `ityv-sim [--quick] <outdir>`: writes every scenario of the set as a
//! development bundle (`<name>.ityvb`) and `index.json` into `outdir`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use ityv_sim::scenarios::{Set, scenarios};
use ityv_sim::{bundle, ledger, meta};

fn main() -> ExitCode {
    let mut set = Set::Full;
    let mut out: Option<PathBuf> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--quick" => set = Set::Quick,
            "--help" | "-h" => {
                eprintln!("usage: ityv-sim [--quick] <outdir>");
                return ExitCode::SUCCESS;
            }
            other => out = Some(PathBuf::from(other)),
        }
    }
    let Some(out) = out else {
        eprintln!("usage: ityv-sim [--quick] <outdir>");
        return ExitCode::FAILURE;
    };
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("ityv-sim: cannot create {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    let start = Instant::now();
    let all = scenarios(set);
    let mut written = Vec::new();
    let mut total = 0usize;
    for s in &all {
        let t = Instant::now();
        let l = ledger(s);
        let bytes = bundle::encode(s, l);
        let file = format!("{}.ityvb", s.name);
        if let Err(e) = std::fs::write(out.join(&file), &bytes) {
            eprintln!("ityv-sim: cannot write {file}: {e}");
            return ExitCode::FAILURE;
        }
        eprintln!(
            "ityv-sim: {:<32} {:>5} frames {:>10} bytes  {:>6} ms",
            s.name,
            l.size,
            bytes.len(),
            t.elapsed().as_millis()
        );
        total += bytes.len();
        written.push((s, file, bytes.len(), ityv_sim::util::sha3_hex(&bytes)));
    }
    let index = meta::index_json(set, &written);
    if let Err(e) = std::fs::write(out.join("index.json"), index) {
        eprintln!("ityv-sim: cannot write index.json: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "ityv-sim: {} scenarios, {total} bytes, {:.1} s",
        all.len(),
        start.elapsed().as_secs_f64()
    );
    ExitCode::SUCCESS
}
