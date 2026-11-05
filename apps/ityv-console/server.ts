// Development server: Bun's HTML bundler for the page (with hot reload)
// and plain files from public/ (the worker, the WASM verifier and the
// simulator bundles that scripts/data.ts wrote). Local only.

import index from "./index.html";

const root = `${import.meta.dir}/public`;

const server = Bun.serve({
  port: Number(process.env.PORT ?? "3000"),
  hostname: process.env.HOST ?? "127.0.0.1",
  development: { hmr: true, console: true },
  routes: { "/": index },
  async fetch(req: Request): Promise<Response> {
    let path: string;
    try {
      path = decodeURIComponent(new URL(req.url).pathname);
    } catch {
      // A malformed % escape.
      return new Response("bad request", { status: 400 });
    }
    if (path.includes("..") || !/^\/[\w./-]+$/.test(path)) {
      return new Response("not found", { status: 404 });
    }
    const file = Bun.file(`${root}${path}`);
    if (!(await file.exists())) return new Response("not found", { status: 404 });
    const type = path.endsWith(".wasm")
      ? "application/wasm"
      : path.endsWith(".json")
        ? "application/json"
        : path.endsWith(".js")
          ? "text/javascript"
          : "application/octet-stream";
    return new Response(file as unknown as BodyInit, { headers: { "content-type": type, "cache-control": "no-store" } });
  },
});

console.log(`ityv console: ${server.url}`);
