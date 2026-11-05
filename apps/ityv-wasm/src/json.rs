//! A small hand-written JSON writer (no serde). Objects and arrays are
//! written in order; the caller keeps keys unique. Integers above
//! 2^53 − 1 in magnitude (beyond what a JavaScript number holds exactly)
//! are written as decimal strings.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// The largest integer a JavaScript number holds exactly.
const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// A JSON document being written.
#[derive(Debug, Default)]
pub(crate) struct Json {
    out: String,
    /// Per open container: whether it has an element yet.
    first: Vec<bool>,
}

impl Json {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn comma(&mut self) {
        if let Some(first) = self.first.last_mut() {
            if *first {
                *first = false;
            } else {
                self.out.push(',');
            }
        }
    }

    fn key(&mut self, key: &str) {
        self.comma();
        push_str(&mut self.out, key);
        self.out.push(':');
    }

    fn write_u64(&mut self, value: u64) {
        if value > MAX_SAFE {
            let _ = write!(self.out, "\"{value}\"");
        } else {
            let _ = write!(self.out, "{value}");
        }
    }

    pub(crate) fn begin_object(&mut self) {
        self.comma();
        self.out.push('{');
        self.first.push(true);
    }

    pub(crate) fn object(&mut self, key: &str) {
        self.key(key);
        self.out.push('{');
        self.first.push(true);
    }

    pub(crate) fn array(&mut self, key: &str) {
        self.key(key);
        self.out.push('[');
        self.first.push(true);
    }

    pub(crate) fn end_object(&mut self) {
        self.first.pop();
        self.out.push('}');
    }

    pub(crate) fn end_array(&mut self) {
        self.first.pop();
        self.out.push(']');
    }

    pub(crate) fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_str(&mut self.out, value);
    }

    pub(crate) fn opt_str(&mut self, key: &str, value: Option<&str>) {
        match value {
            Some(v) => self.str(key, v),
            None => self.null(key),
        }
    }

    pub(crate) fn num(&mut self, key: &str, value: u64) {
        self.key(key);
        self.write_u64(value);
    }

    pub(crate) fn int(&mut self, key: &str, value: i128) {
        self.key(key);
        if value.unsigned_abs() > u128::from(MAX_SAFE) {
            let _ = write!(self.out, "\"{value}\"");
        } else {
            let _ = write!(self.out, "{value}");
        }
    }

    pub(crate) fn opt_num(&mut self, key: &str, value: Option<u64>) {
        match value {
            Some(v) => self.num(key, v),
            None => self.null(key),
        }
    }

    pub(crate) fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
    }

    pub(crate) fn null(&mut self, key: &str) {
        self.key(key);
        self.out.push_str("null");
    }

    /// An array element that is a string.
    pub(crate) fn item_str(&mut self, value: &str) {
        self.comma();
        push_str(&mut self.out, value);
    }

    /// An array element that is a number.
    pub(crate) fn item_num(&mut self, value: u64) {
        self.comma();
        self.write_u64(value);
    }

    pub(crate) fn finish(self) -> String {
        self.out
    }
}

/// A JSON string literal; besides the mandatory escapes, U+2028 and
/// U+2029 are escaped so the output is also a valid JavaScript literal.
fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if u32::from(c) < 0x20 || u32::from(c) == 0x7f => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn writes_nested_values_with_escapes_and_large_integers_as_strings() {
        let mut j = Json::new();
        j.begin_object();
        j.str("a", "x\"y\n\u{2028}\u{1}");
        j.array("b");
        j.item_num(1);
        j.item_str("가");
        j.item_num(u64::MAX);
        j.end_array();
        j.object("c");
        j.bool("d", true);
        j.null("e");
        j.int("f", -3);
        j.int("g", -1_152_921_504_606_846_976);
        j.num("h", 9_007_199_254_740_991);
        j.num("i", 9_007_199_254_740_992);
        j.end_object();
        j.end_object();
        assert_eq!(
            j.finish(),
            "{\"a\":\"x\\\"y\\n\\u2028\\u0001\",\"b\":[1,\"가\",\"18446744073709551615\"],\
             \"c\":{\"d\":true,\"e\":null,\"f\":-3,\"g\":\"-1152921504606846976\",\
             \"h\":9007199254740991,\"i\":\"9007199254740992\"}}"
        );
    }
}
