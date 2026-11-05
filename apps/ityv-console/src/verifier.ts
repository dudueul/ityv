// Clients of the WASM verifier, each with its own worker
// (public/verify-worker.js) so a large bundle does not freeze the page and
// one part of the page cannot answer another part's question.
//
// Every report carries the bundle's SHA3-512 and each record's inclusion,
// so nothing depends on which bundle a worker verified last. A trap in
// the module or a cancelled request terminates that worker; the next call
// starts a fresh one.

import type { Report, SimIndex } from "./data";

/** The largest bundle the console reads (dropped files and fetches). */
export const MAX_BUNDLE_BYTES = 256 * 1024 * 1024;

export class Cancelled extends Error {
  constructor() {
    super("cancelled");
  }
}

type Reply = { id: number; ok: boolean; text: string; trap?: boolean };

export class VerifierClient {
  private worker: Worker | null = null;
  private next = 1;
  private waiting = new Map<number, { resolve: (text: string) => void; reject: (e: Error) => void }>();

  private start(): Worker {
    if (this.worker) return this.worker;
    const w = new Worker("./verify-worker.js");
    w.onmessage = (event: MessageEvent<Reply>) => {
      const p = this.waiting.get(event.data.id);
      if (!p) return;
      this.waiting.delete(event.data.id);
      if (event.data.ok) p.resolve(event.data.text);
      else {
        // After a trap the module's state is unknown: start afresh.
        if (event.data.trap) this.reset();
        p.reject(new Error(event.data.text));
      }
    };
    w.onerror = (e) => {
      const err = new Error(`worker: ${e.message}`);
      this.reset(err);
    };
    this.worker = w;
    return w;
  }

  /** Terminates the worker and rejects everything still waiting. */
  reset(reason: Error = new Cancelled()): void {
    this.worker?.terminate();
    this.worker = null;
    const waiting = [...this.waiting.values()];
    this.waiting.clear();
    for (const w of waiting) w.reject(reason);
  }

  private call(message: Record<string, unknown>, transfer: Transferable[] = []): Promise<string> {
    const w = this.start();
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      w.postMessage({ id, ...message }, transfer);
    });
  }

  /** Verifies a bundle (optionally under another pin, 64 bytes). */
  async verify(bytes: ArrayBuffer, pin?: Uint8Array): Promise<Report> {
    if (bytes.byteLength > MAX_BUNDLE_BYTES) {
      throw new Error(`번들이 ${MAX_BUNDLE_BYTES / 1024 / 1024} MB보다 크다`);
    }
    const text = await this.call({ type: "verify", bundle: bytes, pin }, [bytes]);
    return JSON.parse(text) as Report;
  }

  /** The 32-character fingerprint of SHA3-512(`text`). */
  async fingerprint(text: string): Promise<string> {
    return this.call({ type: "fingerprint", text });
  }

  /** Whether a request is in flight. */
  busy(): boolean {
    return this.waiting.size > 0;
  }
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
  const r = await fetch(`./bundles/${encodeURIComponent(file)}`);
  if (!r.ok) throw new Error(`${file}: ${r.status}`);
  const b = await r.arrayBuffer();
  if (b.byteLength > MAX_BUNDLE_BYTES) throw new Error(`${file}: 너무 크다`);
  return b;
}

/** Parses a 128-character hexadecimal pin. */
export function parsePin(hex: string): Uint8Array | null {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]{128}$/.test(clean)) return null;
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** SHA-256 of the WASM module the page loaded, computed by the browser's
 * own Web Crypto (independent of the module). */
export async function wasmSha256(): Promise<string | null> {
  try {
    const r = await fetch("./ityv_wasm.wasm", { cache: "no-store" });
    if (!r.ok) return null;
    const d = await crypto.subtle.digest("SHA-256", await r.arrayBuffer());
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}
