// Runs the ityv-wasm verifier off the page's main thread. Plain JavaScript
// (no bundling): it only moves bytes in and JSON out of the C ABI that
// apps/ityv-wasm/src/ffi.rs documents. Pointers and lengths from the
// module are unsigned 32-bit (`>>> 0`); input buffers are freed in
// `finally`; after any trap the instance is dropped and the next request
// instantiates the module afresh (the page also replaces the worker).
let exports = null;

async function load() {
  if (exports) return exports;
  const response = await fetch(new URL("./ityv_wasm.wasm", self.location.href));
  const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
  exports = instance.exports;
  return exports;
}

function put(ex, bytes) {
  const ptr = ex.alloc(bytes.length) >>> 0;
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function result(ex, ptr) {
  const len = ex.result_len() >>> 0;
  return new TextDecoder().decode(new Uint8Array(ex.memory.buffer, ptr >>> 0, len).slice());
}

function run(ex, data) {
  if (data.type === "verify") {
    const bytes = new Uint8Array(data.bundle);
    const ptr = put(ex, bytes);
    try {
      if (data.pin) {
        const pin = put(ex, data.pin);
        try {
          return result(ex, ex.verify_bundle_pinned(ptr, bytes.length, pin));
        } finally {
          ex.dealloc(pin, 64);
        }
      }
      return result(ex, ex.verify_bundle(ptr, bytes.length));
    } finally {
      ex.dealloc(ptr, bytes.length);
    }
  }
  if (data.type === "fingerprint") {
    const bytes = new TextEncoder().encode(data.text);
    const ptr = put(ex, bytes);
    try {
      return result(ex, ex.fingerprint(ptr, bytes.length));
    } finally {
      ex.dealloc(ptr, bytes.length);
    }
  }
  throw new Error(`unknown request ${data.type}`);
}

self.onmessage = async (event) => {
  const { id } = event.data;
  let ex;
  try {
    ex = await load();
  } catch (error) {
    self.postMessage({ id, ok: false, trap: true, text: `load: ${error}` });
    return;
  }
  try {
    self.postMessage({ id, ok: true, text: run(ex, event.data) });
  } catch (error) {
    // A trap (RuntimeError) leaves the instance in an unknown state.
    exports = null;
    self.postMessage({ id, ok: false, trap: error instanceof WebAssembly.RuntimeError, text: String(error) });
  }
};
