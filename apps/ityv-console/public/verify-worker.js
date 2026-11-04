// Runs the ityv-wasm verifier off the page's main thread. Plain JavaScript
// (no bundling): it only moves bytes in and JSON out of the C ABI that
// apps/ityv-wasm/src/ffi.rs documents.
let exports = null;

async function load() {
  if (exports) return exports;
  const response = await fetch(new URL("./ityv_wasm.wasm", self.location.href));
  const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
  exports = instance.exports;
  return exports;
}

function put(ex, bytes) {
  const ptr = ex.alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function result(ex, ptr) {
  const len = ex.result_len();
  return new TextDecoder().decode(new Uint8Array(ex.memory.buffer, ptr, len).slice());
}

self.onmessage = async (event) => {
  const { id, type } = event.data;
  try {
    const ex = await load();
    let text;
    if (type === "verify") {
      const bytes = new Uint8Array(event.data.bundle);
      const ptr = put(ex, bytes);
      let out;
      if (event.data.pin) {
        const pin = put(ex, event.data.pin);
        out = ex.verify_bundle_pinned(ptr, bytes.length, pin);
        ex.dealloc(pin, 64);
      } else {
        out = ex.verify_bundle(ptr, bytes.length);
      }
      text = result(ex, out);
      ex.dealloc(ptr, bytes.length);
    } else if (type === "inclusion") {
      text = result(ex, ex.inclusion(BigInt(event.data.seq)));
    } else if (type === "fingerprint") {
      const bytes = new TextEncoder().encode(event.data.text);
      const ptr = put(ex, bytes);
      text = result(ex, ex.fingerprint(ptr, bytes.length));
      ex.dealloc(ptr, bytes.length);
    } else {
      throw new Error(`unknown request ${type}`);
    }
    self.postMessage({ id, ok: true, text });
  } catch (error) {
    self.postMessage({ id, ok: false, text: String(error) });
  }
};
