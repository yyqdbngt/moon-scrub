///|
/// Key-value log line adapter.
///
/// Structured log lines (`k=v`, `k="v with spaces"`) need smarter
/// boundaries than the plain scanner: a quoted value can contain
/// spaces, emails, or even private key blocks, and redacting inside
/// quotes must replace the whole quoted region, not fragment it.
/// `redact_kv` scans a line as a key-value stream — top-level `k=v`
/// tokens separated by spaces, single or double quoted values —
/// redacts every value with the standard pipeline, and leaves keys
/// and structure untouched. Values the scanner missed still get the
/// identity treatment (no redaction), so normal fields pass through
/// byte-identical; findings inside quoted values are replaced in
/// place, keeping the surrounding prose for debugging.

///|
fn kv_find_value_end(text : String, start : Int) -> (Int, Bool) {
  // Returns (end index, was_quoted). Handles double quotes with a
  // backslash escape and single quotes without.
  let quote = text[start].to_int()
  if quote == 34 || quote == 39 {
    let mut i = start + 1
    while i < text.length() {
      let c = text[i].to_int()
      if quote == 34 && c == 92 && i + 1 < text.length() {
        i += 2
        continue
      }
      if c == quote {
        return (i + 1, true)
      }
      i += 1
    }
    // unterminated: treat the rest as the value
    return (text.length(), true)
  }
  let mut i = start
  while i < text.length() && text[i].to_int() != 32 {
    i += 1
  }
  (i, false)
}

///|
fn kv_split(text : String) -> Array[(Int, Int, Int, Bool)] {
  // Top-level tokens as (key_start, eq_index, value_start, value_quoted)
  // with the value end recoverable from kv_find_value_end. Tokens
  // without an equals sign are skipped (structure preserved verbatim).
  let tokens : Array[(Int, Int, Int, Bool)] = []
  let mut i = 0
  while i < text.length() {
    while i < text.length() && text[i].to_int() == 32 {
      i += 1
    }
    if i >= text.length() {
      break
    }
    let key_start = i
    let mut eq = -1
    let mut j = i
    while j < text.length() && text[j].to_int() != 32 {
      if text[j].to_int() == 61 && eq < 0 {
        eq = j
      }
      j += 1
    }
    if eq >= 0 && eq + 1 < text.length() {
      tokens.push((key_start, eq, eq + 1, false))
    }
    // skip past the value (quote-aware)
    if eq >= 0 && eq + 1 < text.length() {
      let value_start = eq + 1
      let value_end = if text[value_start].to_int() == 34 || text[value_start].to_int() == 39 {
        kv_find_value_end(text, value_start).0
      } else {
        let mut k = value_start
        while k < text.length() && text[k].to_int() != 32 {
          k += 1
        }
        k
      }
      i = value_end
    } else {
      i = j
    }
  }
  tokens
}

///|
pub fn redact_kv(
  text : String,
  config : ScanConfig,
  style~ : RedactionStyle = Typed,
) -> String {
  let tokens = kv_split(text)
  if tokens.is_empty() {
    return redact_with_config(text, config, style~).text
  }
  // Scan each value region separately; keep a rebuild plan of segments.
  let segments : Array[String] = []
  let mut cursor = 0
  for token in tokens {
    let value_start = token.2
    let value_end = if text[value_start].to_int() == 34 || text[value_start].to_int() == 39 {
      kv_find_value_end(text, value_start).0
    } else {
      let mut k = value_start
      while k < text.length() && text[k].to_int() != 32 {
        k += 1
      }
      k
    }
    // Only quoted values collapse as a whole; bare values go through
    // the normal per-finding replacement below.
    if value_end > value_start &&
      (text[value_start].to_int() == 34 || text[value_start].to_int() == 39) {
      let quote = text[value_start].to_int()
      let inner = text[value_start + 1:value_end - 1].to_owned()
      let scanned = redact_with_config(inner, config, style~).text
      if scanned != inner {
        // copy structure before the value
        segments.push(text[cursor:value_start + 1].to_owned())
        segments.push(scanned)
        // closing quote handled as part of the next segment start
        segments.push(text[value_end - 1:value_end].to_owned())
        cursor = value_end
      }
    }
  }
  if cursor == 0 {
    // nothing collapsed; fall back to the standard line redaction which
    // still catches bare values
    return redact_with_config(text, config, style~).text
  }
  // Tail after the last collapsed value: plain redaction preserves
  // bare-value findings there.
  let tail = text[cursor:].to_owned()
  segments.push(redact_with_config(tail, config, style~).text)
  let mut out = ""
  for segment in segments {
    out += segment
  }
  out
}
