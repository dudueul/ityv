// Serves the built dist/ with the page's Content Security Policy as a
// header (so it also covers the worker). Local only; for checking a build.
// PORT (default 3001), HOST (default 127.0.0.1).

import { CSP } from "./csp";

const root = `${import.meta.dir}/../dist`;
const TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript",
  css: "text/css",
  wasm: "application/wasm",
  json: "application/json",
};

const server = Bun.serve({
  port: Number(process.env.PORT ?? "3001"),
  hostname: process.env.HOST ?? "127.0.0.1",
  async fetch(req: Request): Promise<Response> {
    let path: string;
    try {
      path = decodeURIComponent(new URL(req.url).pathname);
    } catch {
      return new Response("bad request", { status: 400 });
    }
    if (path === "/") path = "/index.html";
    if (path.includes("..") || !/^\/[\w./-]+$/.test(path)) return new Response("not found", { status: 404 });
    const file = Bun.file(`${root}${path}`);
    if (!(await file.exists())) return new Response("not found", { status: 404 });
    const type = TYPES[path.split(".").pop() ?? ""] ?? "application/octet-stream";
    return new Response(file as unknown as BodyInit, {
      headers: { "content-type": type, "content-security-policy": CSP, "cache-control": "no-store" },
    });
  },
});

console.log(`ityv console (dist): ${server.url}`);
