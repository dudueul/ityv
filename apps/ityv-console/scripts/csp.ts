// The built page's Content Security Policy: everything from the page's own
// origin, no inline script or style, WebAssembly compilation allowed (the
// worker instantiates the verifier), nothing sent anywhere else. Written
// into dist/index.html as a <meta> by scripts/build.ts and sent as a
// header by scripts/preview.ts (which also covers the worker).
export const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");
