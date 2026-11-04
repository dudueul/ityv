// The page's client of the WASM verifier, which runs in a worker
// (public/verify-worker.js) so a large bundle does not freeze the page.

import type { Inclusion, Report, SimIndex } from "./data";

let worker: Worker | null = null;
let next = 1;
const waiting = new Map<number, { resolve: (text: string) => void; reject: (e: Error) => void }>();

function call(message: Record<string, unknown>, transfer: Transferable[] = []): Promise<string> {
  if (!worker) {
    worker = new Worker("./verify-worker.js");
    worker.onmessage = (event: MessageEvent<{ id: number; ok: boolean; text: string }>) => {
      const w = waiting.get(event.data.id);
      if (!w) return;
      waiting.delete(event.data.id);
      if (event.data.ok) w.resolve(event.data.text);
      else w.reject(new Error(event.data.text));
    };
  }
  const id = next++;
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject });
    worker?.postMessage({ id, ...message }, transfer);
  });
}

let lastKey: string | null = null;

/** Verifies a bundle (optionally under another pin, 64 bytes). `key`
 * names it: the worker keeps the last verified bundle for inclusion
 * proofs, and `lastVerified` says which one that is. */
export async function verifyBundle(bytes: ArrayBuffer, pin?: Uint8Array, key: string | null = null): Promise<Report> {
  lastKey = null;
  const text = await call({ type: "verify", bundle: bytes, pin }, [bytes]);
  lastKey = pin ? null : key;
  return JSON.parse(text) as Report;
}

/** The key of the bundle the worker verified last (`null` if unnamed or
 * verified under another pin). */
export function lastVerified(): string | null {
  return lastKey;
}

/** The inclusion of frame `seq` of the last verified bundle. */
export async function inclusion(seq: number): Promise<Inclusion> {
  return JSON.parse(await call({ type: "inclusion", seq })) as Inclusion;
}

/** The 32-character fingerprint of SHA3-512(`text`). */
export async function fingerprintOf(text: string): Promise<string> {
  return call({ type: "fingerprint", text });
}

export async function loadIndex(): Promise<SimIndex | null> {
  try {
    const r = await fetch("./bundles/index.json");
    if (!r.ok) return null;
    return (await r.json()) as SimIndex;
  } catch {
    return null;
  }
}

export async function loadBundle(file: string): Promise<ArrayBuffer> {
  const r = await fetch(`./bundles/${file}`);
  if (!r.ok) throw new Error(`${file}: ${r.status}`);
  return r.arrayBuffer();
}

/** Parses a 128-character hexadecimal pin. */
export function parsePin(hex: string): Uint8Array | null {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]{128}$/.test(clean)) return null;
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
