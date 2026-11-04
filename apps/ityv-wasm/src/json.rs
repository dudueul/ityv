//! A small hand-written JSON writer (no serde). Objects and arrays are
//! written in order; the caller keeps keys unique.

use core::fmt::Write;

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
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn int(&mut self, key: &str, value: i128) {
        self.key(key);
        let _ = write!(self.out, "{value}");
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
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn finish(self) -> String {
        self.out
    }
}

fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
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
    fn writes_nested_values_with_escapes() {
        let mut j = Json::new();
        j.begin_object();
        j.str("a", "x\"y\n");
        j.array("b");
        j.item_num(1);
        j.item_str("가");
        j.end_array();
        j.object("c");
        j.bool("d", true);
        j.null("e");
        j.int("f", -3);
        j.end_object();
        j.end_object();
        assert_eq!(
            j.finish(),
            "{\"a\":\"x\\\"y\\n\",\"b\":[1,\"가\"],\"c\":{\"d\":true,\"e\":null,\"f\":-3}}"
        );
    }
}
