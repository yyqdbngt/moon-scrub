///|
/// Escape a string for JSON output. Control characters become `\u00xx`
/// escapes; printable non-ASCII characters are emitted as-is because JSON is
/// defined over Unicode text.
fn json_escape(text : String) -> String {
  let out = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i].to_int()
    match c {
      34 => out.write_string("\\\"")
      92 => out.write_string("\\\\")
      8 => out.write_string("\\b")
      12 => out.write_string("\\f")
      10 => out.write_string("\\n")
      13 => out.write_string("\\r")
      9 => out.write_string("\\t")
      _ =>
        if c < 32 {
          let hex = "0123456789abcdef"
          out.write_string("\\u00")
          out.write_char(Int::unsafe_to_char(hex[c / 16 % 16].to_int()))
          out.write_char(Int::unsafe_to_char(hex[c % 16].to_int()))
        } else {
          out.write_char(Int::unsafe_to_char(c))
        }
    }
  }
  out.to_string()
}

///|
/// Code-unit-wise lexicographic order, matching RFC 8785 (JCS) member
/// ordering. The default `Compare` on `String` is shortlex (length first),
/// which is not what canonical JSON uses.
fn lexicographic_before(a : String, b : String) -> Bool {
  let shared = if a.length() < b.length() { a.length() } else { b.length() }
  for i = 0; i < shared; i = i + 1 {
    let x = a[i].to_int()
    let y = b[i].to_int()
    if x != y {
      return x < y
    }
  }
  a.length() < b.length()
}

///|
fn sort_strings(items : Array[String]) -> Unit {
  for i = 1; i < items.length(); i = i + 1 {
    let value = items[i]
    let mut j = i
    while j > 0 && lexicographic_before(value, items[j - 1]) {
      items[j] = items[j - 1]
      j -= 1
    }
    items[j] = value
  }
}

///|
/// Serialize with deterministic member order: object keys are emitted in
/// ascending lexicographic order and number spellings are preserved through
/// the parser's `repr` so identical inputs always produce identical output.
fn write_json_value(value : Json, buf : StringBuilder) -> Unit {
  match value {
    Null => buf.write_string("null")
    True => buf.write_string("true")
    False => buf.write_string("false")
    Number(d, repr~) =>
      match repr {
        Some(spelling) => buf.write_string(spelling)
        None => buf.write_string(d.to_string())
      }
    String(s) => {
      buf.write_char(Int::unsafe_to_char(34))
      buf.write_string(json_escape(s))
      buf.write_char(Int::unsafe_to_char(34))
    }
    Array(items) => {
      buf.write_char(Int::unsafe_to_char(91))
      for i = 0; i < items.length(); i = i + 1 {
        if i > 0 {
          buf.write_char(Int::unsafe_to_char(44))
        }
        write_json_value(items[i], buf)
      }
      buf.write_char(Int::unsafe_to_char(93))
    }
    Object(map) => {
      let keys : Array[String] = []
      map.each(fn(k, _v) { keys.push(k) })
      sort_strings(keys)
      buf.write_char(Int::unsafe_to_char(123))
      for i = 0; i < keys.length(); i = i + 1 {
        if i > 0 {
          buf.write_char(Int::unsafe_to_char(44))
        }
        buf.write_char(Int::unsafe_to_char(34))
        buf.write_string(json_escape(keys[i]))
        buf.write_char(Int::unsafe_to_char(34))
        buf.write_char(Int::unsafe_to_char(58))
        if map.get(keys[i]) is Some(entry) {
          write_json_value(entry, buf)
        } else {
          buf.write_string("null")
        }
      }
      buf.write_char(Int::unsafe_to_char(125))
    }
  }
}

///|
/// Walk a parsed document, redacting every string leaf. Sensitive paths are
/// fail-closed like `redact_fields`. Returns the rebuilt value and how many
/// fields changed.
fn walk_json(
  value : Json,
  path : String,
  config : ScanConfig,
  style : RedactionStyle,
  findings : Array[JsonFinding],
  rules : Array[CustomRule],
) -> (Json, Int) {
  match value {
    String(text) => {
      let leaf : Array[Finding] = if path_is_sensitive(path) &&
        text.length() > 0 {
        [
          {
            kind: CredentialAssignment,
            start: 0,
            end: text.length(),
            confidence: High,
          },
        ]
      } else {
        scan_full(text, rules, config)
      }
      if leaf.length() == 0 {
        return (value, 0)
      }
      for finding in leaf {
        findings.push({ path, finding, })
      }
      (Json::string(redact_with_findings(text, leaf, style)), 1)
    }
    Array(items) => {
      let rebuilt : Array[Json] = []
      let mut changed = 0
      for i = 0; i < items.length(); i = i + 1 {
        let (item, count) = walk_json(
          items[i],
          path + "/" + i.to_string(),
          config,
          style,
          findings,
          rules,
        )
        rebuilt.push(item)
        changed += count
      }
      (Json::array(rebuilt), changed)
    }
    Object(map) => {
      let keys : Array[String] = []
      map.each(fn(k, _v) { keys.push(k) })
      sort_strings(keys)
      let rebuilt : Map[String, Json] = Map([])
      let mut changed = 0
      for key in keys {
        let child = map.get(key)
        let (item, count) = if child is Some(child_json) {
          walk_json(
            child_json,
            path + "/" + key,
            config,
            style,
            findings,
            rules,
          )
        } else {
          (Json::null(), 0)
        }
        rebuilt[key] = item
        changed += count
      }
      (Json::object(rebuilt), changed)
    }
    _ => (value, 0)
  }
}

///|
/// Redact a JSON document by parsing it and treating every string leaf as a
/// structured field. Malformed input fails closed: it is redacted as plain
/// text with `parsed` set to false. Output is compact and deterministic;
/// object keys are re-emitted in sorted order.

///|
/// redact_json with caller-supplied exact-value rules applied to every
/// string leaf in addition to the configured detectors.

///|
/// Distinct JSON-pointer-like paths that produced findings, sorted, so
/// callers can compare document coverage across runs without values.
pub fn JsonRedactionResult::paths(self : JsonRedactionResult) -> Array[String] {
  let out : Array[String] = []
  for item in self.findings {
    if !out.contains(item.path) {
      out.push(item.path)
    }
  }
  sort_strings(out)
  out
}

///|
pub fn redact_json_with_rules(
  text : String,
  rules : Array[CustomRule],
  config? : ScanConfig = ScanConfig::standard(),
  style? : RedactionStyle = Typed,
) -> JsonRedactionResult {
  let outcome = try @json.parse(text) catch {
    _ => None
  } noraise {
    doc => Some(doc)
  }
  match outcome {
    Some(doc) => {
      let findings : Array[JsonFinding] = []
      let (rebuilt, changed) = walk_json(
        doc, "", config, style, findings, rules,
      )
      let buf = StringBuilder()
      write_json_value(rebuilt, buf)
      {
        text: buf.to_string(),
        changed_fields: changed,
        findings,
        parsed: true,
      }
    }
    None => {
      let plain = redact_full(text, rules, config, style~)
      let findings : Array[JsonFinding] = []
      for finding in plain.findings {
        findings.push({ path: "", finding, })
      }
      {
        text: plain.text,
        changed_fields: if plain.changed {
          1
        } else {
          0
        },
        findings,
        parsed: false,
      }
    }
  }
}

///|
pub fn redact_json(
  text : String,
  config? : ScanConfig = ScanConfig::standard(),
  style? : RedactionStyle = Typed,
) -> JsonRedactionResult {
  let outcome = try @json.parse(text) catch {
    _ => None
  } noraise {
    doc => Some(doc)
  }
  match outcome {
    Some(doc) => {
      let findings : Array[JsonFinding] = []
      let (rebuilt, changed) = walk_json(doc, "", config, style, findings, [])
      let buf = StringBuilder()
      write_json_value(rebuilt, buf)
      {
        text: buf.to_string(),
        changed_fields: changed,
        findings,
        parsed: true,
      }
    }
    None => {
      let plain = redact_with_config(text, config, style~)
      let findings : Array[JsonFinding] = []
      for finding in plain.findings {
        findings.push({ path: "", finding, })
      }
      {
        text: plain.text,
        changed_fields: if plain.changed {
          1
        } else {
          0
        },
        findings,
        parsed: false,
      }
    }
  }
}
