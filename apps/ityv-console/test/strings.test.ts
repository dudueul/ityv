// The fixed string table against docs/ui/SCREENS.md (§8 1항): every
// screen string SCREENS.md quotes for the implemented screens is in the
// table verbatim; none of the judgement phrases it forbids is; every slot
// is an allowed kind.

import { expect, test } from "bun:test";
import { SLOT_KINDS, STRINGS, type StringId, checkSlot, spec } from "../src/strings";

const screensMd = await Bun.file(`${import.meta.dir}/../../../docs/ui/SCREENS.md`).text();

/** Lines of the sections whose screens the prototypes implement
 * (§0.1 and §1–§7). */
function implementedLines(): string[] {
  const out: string[] = [];
  let on = false;
  for (const line of screensMd.split("\n")) {
    if (/^#{2,3} /.test(line)) {
      on = /^### 0\.1 /.test(line) || /^## [1-7]\. /.test(line) || /^### 6\.[12] /.test(line);
      continue;
    }
    if (on) out.push(line);
  }
  return out;
}

/** A line that lists what a screen must not show. */
const forbiddenLine = (line: string) => /금지|쓰지 않는다|나오지 않는 것/.test(line);

/** Quoted strings that SCREENS.md names but that are not screen text. */
const NOT_SCREEN_TEXT: Record<string, string> = {
  "연결 없음": "분류기가 연결 목록(ConnectivityManifest)에 선언하는 값이며 화면 문구가 아니다 (§4).",
  "읽는 중": "§1 표의 상태 이름을 가리킨다. 그 상태의 화면 문구는 \"읽는 중이에요. 투표지 N장\"이다.",
};

const quotes = (line: string) => [...line.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);

function required(): string[] {
  const lines = implementedLines();
  const out = new Set<string>();
  for (const line of lines) {
    if (forbiddenLine(line)) continue;
    for (const q of quotes(line)) if (!(q in NOT_SCREEN_TEXT)) out.add(q);
  }
  // §1 button labels are bold in the table rows; §0.1 names the action.
  for (const line of lines.filter((l) => l.startsWith("|"))) {
    for (const m of line.matchAll(/\*\*([^*]+)\*\*/g)) out.add(m[1]!);
  }
  out.add("소프트웨어 확인");
  // Parenthesised value lists the screens show word for word.
  for (const line of lines) {
    for (const re of [/상태\(([^)]+)\)/, /판정 선택\(([^)]+)\)/, /이유 코드\(([^)]+)\)/]) {
      const m = re.exec(line);
      if (m) for (const item of m[1]!.split(", ")) out.add(item.trim());
    }
  }
  return [...out];
}

function forbidden(): string[] {
  const out = new Set<string>();
  for (const line of screensMd.split("\n")) {
    if (!forbiddenLine(line)) continue;
    for (const q of quotes(line)) out.add(q);
  }
  return [...out];
}

const ids = Object.keys(STRINGS) as StringId[];
const rendered = new Set(ids.map((id) => spec(id)));

test("SCREENS.md yields the quoted strings of every implemented screen", () => {
  const r = required();
  // A sanity floor: §1 has 11 states, §3 ten strings, §6 eleven.
  expect(r.length).toBeGreaterThan(40);
  expect(r).toContain("투표지를 봉투째 투입구에 넣어 주세요.");
  expect(r).toContain("경보는 확인이 필요하다는 뜻이에요. 어떤 투표지도 무효가 되지 않아요.");
  expect(r).toContain("모두 넣기");
  expect(r).toContain("마감 중");
});

test("every quoted screen string is in the table verbatim", () => {
  const missing = required().filter((q) => !rendered.has(q));
  expect(missing).toEqual([]);
});

test("the identity line and the batch fill render the SCREENS.md examples", () => {
  expect(spec("id.line")).toBe("ityv 사전투표 스캐너 1.4.2 · 빌드 2071 · K7QF 2M8D R5WN Q3XA");
  expect(screensMd).toContain(`\`${spec("id.line")}\``);
  expect(spec("clerk.batch.fill")).toBe("x/64");
  expect(screensMd).toContain("`x/64`");
});

test("the table contains none of the forbidden judgement phrases", () => {
  const bad = forbidden();
  expect(bad).toContain("인증됨");
  expect(bad).toContain("귀하의 표가 집계되었습니다");
  expect(bad).toContain("확정");
  for (const phrase of [...bad, "오늘 N번째"]) {
    for (const id of ids) {
      expect(`${id}: ${spec(id)}`).not.toContain(phrase);
    }
  }
});

test("every slot is an allowed kind and every entry names its source", () => {
  // SCREENS §8 1항's kinds, and a reference to another fixed entry of the
  // table (which is itself table text, never data).
  const allowed = new Set(["정수", "식별자", "지문", "상태 어휘", "문구 표 항목"]);
  for (const id of ids) {
    const e = STRINGS[id] as { ko: string; slots?: Record<string, string>; source: string; spec?: Record<string, string> };
    const names = [...e.ko.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!);
    expect(Object.keys(e.slots ?? {}).sort()).toEqual([...new Set(names)].sort());
    for (const kind of Object.values(e.slots ?? {})) {
      expect(kind in SLOT_KINDS).toBe(true);
      expect(allowed.has(SLOT_KINDS[kind as keyof typeof SLOT_KINDS])).toBe(true);
    }
    expect(/^(SCREENS §[0-9.]+|prototype)$/.test(e.source)).toBe(true);
    if (e.source !== "prototype" && names.length > 0) {
      // Strings from SCREENS.md with slots carry the placeholders that give
      // the SCREENS.md text back, unless the specification shows only the
      // value (a position number).
      expect(e.spec !== undefined || ["voter.cell"].includes(id)).toBe(true);
    }
  }
});

test("each slot kind refuses values outside its charset", () => {
  for (const ok of ["BOX-HB-1", "ityv.scanner", "a:b/c_d", "x".repeat(64)]) expect(checkSlot("identifier", ok)).toBe(ok);
  for (const bad of ["", "김가상", "a b", "x".repeat(65), "<b>", "a\nb"]) {
    expect(() => checkSlot("identifier", bad)).toThrow();
  }
  expect(checkSlot("trackingCode", "0123abcd 0123abcd 0123abcd 0123abcd")).toContain("0123abcd");
  for (const bad of ["0123ABCD 0123abcd 0123abcd 0123abcd", "0123abcd0123abcd", "BOX-HB-1"]) {
    expect(() => checkSlot("trackingCode", bad)).toThrow();
  }
  // A reference names only a fixed entry of the table.
  expect(checkSlot("ref", spec("gw.tap.device"))).toBe(spec("gw.tap.device"));
  for (const bad of ["장치 쪽", "김가상", "BOX-HB-1"]) expect(() => checkSlot("ref", bad)).toThrow();
});

test("no slot kind can carry what a screen must never show", () => {
  const kinds = new Set(ids.flatMap((id) => Object.values((STRINGS[id] as { slots?: Record<string, string> }).slots ?? {})));
  for (const banned of ["candidate", "readResult", "ordinal", "eventTime", "pseudonym", "imprint"]) {
    expect(kinds.has(banned)).toBe(false);
  }
  for (const id of ids) {
    // "카운터·가명 유닛" is a device's name (SCREENS §3), not a pseudonym.
    const s = spec(id).replaceAll("카운터·가명 유닛", "");
    for (const word of ["BLANK", "UNREADABLE", "번째", "가명", "각인 번호"]) expect(`${id}: ${s}`).not.toContain(word);
  }
});
