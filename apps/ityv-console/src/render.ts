// Drawing: a device frame with its screen, the fixed identity line at the
// bottom that nothing covers, the "소프트웨어 확인" detail view, and the
// blocks of a screen model. Plain DOM, no framework.

import type { Block, Icon, ScreenButton, ScreenModel } from "./screens";
import { t } from "./strings";

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, val] of Object.entries(attrs)) {
    if (k === "class") e.className = val;
    // Through the CSSOM, which a style-src without 'unsafe-inline' allows.
    else if (k === "style") e.style.cssText = val;
    else e.setAttribute(k, val);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

const ICON_PATHS: Record<Icon, string> = {
  wait: '<path d="M7 3h10M7 21h10M8 3c0 6 8 6 8 9s-8 3-8 9M16 3c0 6-8 6-8 9s8 3 8 9" fill="none" stroke="currentColor" stroke-width="2"/>',
  ok: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7.5 12.5l3 3 6-7" fill="none" stroke="currentColor" stroke-width="2.4"/>',
  fail: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 8l8 8M16 8l-8 8" stroke="currentColor" stroke-width="2.4"/>',
  warn: '<path d="M12 3l10 18H2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 9v6M12 17.5v1.5" stroke="currentColor" stroke-width="2.4"/>',
  stop: '<path d="M8 2h8l6 6v8l-6 6H8l-6-6V8z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7 12h10" stroke="currentColor" stroke-width="2.6"/>',
  info: '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 10.5v6M12 7v1.5" stroke="currentColor" stroke-width="2.4"/>',
  paper: '<path d="M6 2h9l4 4v16H6z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M9 11h7M9 15h7" stroke="currentColor" stroke-width="2"/>',
  card: '<rect x="3" y="5" width="18" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7 10h4v4H7z" fill="currentColor"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2"/>',
};

export function icon(name: Icon, label?: string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", `icon icon-${name}`);
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  svg.innerHTML = ICON_PATHS[name];
  return svg;
}

/** One icon per rung of the status ladder, none of them a check mark: a
 * check is shown only beside a status verified under an outside pin. */
const RUNG_PATHS: Record<string, string> = {
  // A dashed empty circle: nothing confirmed yet.
  UNVERIFIED: '<circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="3 3"/>',
  // Two chain links: the log is one consistent chain.
  LOG_CONSISTENT:
    '<rect x="2.5" y="8.5" width="10" height="7" rx="3.5" fill="none" stroke="currentColor" stroke-width="2"/><rect x="11.5" y="8.5" width="10" height="7" rx="3.5" fill="none" stroke="currentColor" stroke-width="2"/>',
  // A ballot box with its slot: every expected box closed.
  SOURCE_COMPLETENESS_CHECKED:
    '<rect x="3" y="9" width="18" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 9V3h8v6M9 13h6" fill="none" stroke="currentColor" stroke-width="2"/>',
  // A sigma: the tally sums opened.
  CRYPTO_TALLY_VERIFIED: '<path d="M18 4H6l7 8-7 8h12" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linejoin="round"/>',
  // Paper under a magnifier: the sampled paper compared.
  PAPER_AUDITED:
    '<path d="M4 2h9l3 3v6" fill="none" stroke="currentColor" stroke-width="2"/><path d="M4 2v18h7" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16.5" cy="16" r="3.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M19 18.5l3 3" stroke="currentColor" stroke-width="2.4"/>',
  // Two pause bars in a square: held for review.
  HOLD_REVIEW:
    '<rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M9.5 8v8M14.5 8v8" stroke="currentColor" stroke-width="2.6"/>',
  // A balance: a legal decision, never a machine's status.
  LEGAL_CERTIFIED:
    '<path d="M12 3v18M7 21h10M4 7h16" fill="none" stroke="currentColor" stroke-width="2"/><path d="M4 7l-2.5 6h5zM20 7l-2.5 6h5z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
};

/** The icon of a status word; an unknown word gets the empty circle. */
export function rungIcon(word: string): SVGSVGElement {
  const known = word in RUNG_PATHS ? word : "UNVERIFIED";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", `icon icon-rung rung-${known}`);
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = RUNG_PATHS[known] ?? "";
  return svg;
}

function block(b: Block, onCell?: (n: number) => void): HTMLElement {
  const e = blockInner(b, onCell);
  if (b.demo) e.classList.add("demo");
  return e;
}

function blockInner(b: Block, onCell?: (n: number) => void): HTMLElement {
  switch (b.kind) {
    case "cells":
      return el(
        "div",
        { class: "cells" },
        ...(b.cells ?? []).map((c) => {
          const btn = el(
            "button",
            {
              class: `cell${c.selected ? " selected" : ""}`,
              "aria-pressed": String(c.selected),
              "data-cell": String(c.n),
            },
            c.selected ? icon("ok") : null,
            el("span", {}, c.text),
          );
          if (onCell) btn.addEventListener("click", () => onCell(c.n));
          else btn.disabled = true;
          return btn;
        }),
      );
    case "row":
      return el(
        "div",
        { class: "row" },
        el("span", { class: "row-label" }, b.label ?? ""),
        el("span", { class: "row-value" }, b.icon ? icon(b.icon) : null, b.value ?? ""),
      );
    case "section":
      return el("div", { class: "section" }, b.text ?? "");
    default:
      return el("div", { class: `b-${b.kind}` }, b.icon ? icon(b.icon) : null, el("span", {}, b.text ?? ""));
  }
}

function button(b: ScreenButton, onAction?: (a: string) => void): HTMLButtonElement {
  const e = el("button", { class: `sbtn ${b.shape}`, "data-action": b.action }, b.text);
  e.disabled = !b.enabled;
  if (onAction) e.addEventListener("click", () => onAction(b.action));
  return e;
}

export interface Identity {
  program: string;
  version: string;
  build: number;
  fp32: string;
  components: { name: string; version: string; build: number; fp32: string }[];
  modules: { id: string; build: number; fp32: string }[];
  boots: number;
}

export interface FrameOptions {
  model: ScreenModel;
  identity: Identity;
  zoom: number;
  contrast: boolean;
  detail: boolean;
  kind: string;
  onAction?: (a: string) => void;
  onCell?: (n: number) => void;
  onDetail?: (open: boolean) => void;
}

/** A device screen: content (scrolls when enlarged) above the fixed
 * identity line, which is the last row of the screen grid and is never
 * overlaid; the detail view opens inside the content area. */
export function screen(o: FrameOptions): HTMLElement {
  const fp16 = o.identity.fp32.split(" ").slice(0, 4).join(" ");
  const content = el("div", { class: "content", tabindex: "0" });
  if (o.detail) {
    content.append(
      el(
        "div",
        { class: "detail", role: "dialog", "aria-label": t("id.detail.title") },
        el("div", { class: "section" }, t("id.detail.title")),
        ...o.identity.components.map((c) =>
          el(
            "div",
            { class: "comp" },
            el("div", {}, t("id.detail.component", { name: c.name, version: c.version, build: c.build })),
            el("div", { class: "mono" }, t("id.detail.fp", { fp: c.fp32 })),
          ),
        ),
        ...o.identity.modules.map((m) =>
          el(
            "div",
            { class: "comp" },
            el("div", {}, t("id.detail.module", { module: m.id, build: m.build })),
            el("div", { class: "mono" }, t("id.detail.fp", { fp: m.fp32 })),
          ),
        ),
        el("div", {}, t("id.detail.boots", { count: o.identity.boots })),
        el("div", { class: "b-text" }, el("span", {}, t("id.attest"))),
        (() => {
          const c = el("button", { class: "sbtn square", "data-action": "closeDetail" }, t("id.detail.close"));
          c.addEventListener("click", () => o.onDetail?.(false));
          return c;
        })(),
      ),
    );
  } else {
    for (const b of o.model.blocks) content.append(block(b, o.onCell));
    if (o.model.buttons.length > 0) {
      content.append(el("div", { class: "buttons" }, ...o.model.buttons.map((b) => button(b, o.onAction))));
    }
  }
  const check = el("button", { class: "idcheck", "data-action": "software" }, t("id.check"));
  check.addEventListener("click", () => o.onDetail?.(!o.detail));
  const idline = el(
    "div",
    { class: "idline", "data-testid": "identity-line" },
    el(
      "span",
      { class: "idtext" },
      t("id.line", { program: o.identity.program, version: o.identity.version, build: o.identity.build, fp: fp16 }),
    ),
    check,
  );
  const s = el(
    "div",
    {
      class: `screen kind-${o.kind}${o.contrast ? " hc" : ""}`,
      style: `--zoom:${o.zoom}`,
      "data-testid": "screen",
    },
    content,
    idline,
  );
  return s;
}
