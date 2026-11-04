// The few Bun APIs this package uses, declared by hand so that the only
// development dependency stays `typescript` (no @types/bun).

declare module "bun:test" {
  interface Matchers {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toContain(expected: unknown): void;
    toBeGreaterThan(expected: number): void;
    toBeLessThanOrEqual(expected: number): void;
    toThrow(message?: string | RegExp): void;
    toBeNull(): void;
    readonly not: Matchers;
  }
  export function test(name: string, fn: () => void | Promise<void>, timeout?: number): void;
  export function describe(name: string, fn: () => void): void;
  export function expect(value: unknown): Matchers;
}

declare module "*.html" {
  const html: unknown;
  export default html;
}

interface BunFile {
  text(): Promise<string>;
  json(): Promise<unknown>;
  exists(): Promise<boolean>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

interface BunServer {
  url: URL;
  port: number;
  stop(): void;
}

interface BunSpawnResult {
  exitCode: number | null;
  success: boolean;
}

interface BunBuildOutput {
  success: boolean;
  logs: unknown[];
  outputs: { path: string }[];
}

declare const Bun: {
  file(path: string): BunFile;
  write(path: string, data: string | ArrayBuffer | Uint8Array | BunFile): Promise<number>;
  serve(options: {
    port?: number;
    hostname?: string;
    development?: boolean | { hmr?: boolean; console?: boolean };
    routes?: Record<string, unknown>;
    fetch(req: Request): Response | Promise<Response>;
  }): BunServer;
  build(options: {
    entrypoints: string[];
    outdir: string;
    minify?: boolean;
    target?: string;
    sourcemap?: string;
  }): Promise<BunBuildOutput>;
  spawnSync(cmd: string[], options?: { cwd?: string; stdout?: string; stderr?: string; env?: Record<string, string | undefined> }): BunSpawnResult;
};

interface ImportMeta {
  readonly dir: string;
}

declare const process: {
  env: Record<string, string | undefined>;
  exit(code?: number): never;
  argv: string[];
};

declare module "node:fs" {
  export function mkdirSync(path: string, options?: { recursive?: boolean }): void;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function cpSync(src: string, dest: string, options?: { recursive?: boolean }): void;
  export function existsSync(path: string): boolean;
  export function readdirSync(path: string): string[];
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string): void;
}
