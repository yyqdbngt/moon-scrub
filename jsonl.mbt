///|
/// NDJSON pipeline adapter.
///
/// Log pipelines stream newline-delimited JSON: one document per
/// line, not a single array. `redact_json_lines` applies the JSON
/// document pipeline to every line independently — per-line isolation
/// means a malformed line falls back to plain scanning without
/// touching its neighbours — and reports which line indices changed
/// so callers can route only the redacted rows. Input line count and
/// order are invariants: N lines in, N lines out, terminators
/// preserved exactly as received (including a missing final newline).

///|
pub(all) struct JsonLinesResult {
  lines : Array[String]
  changed_indices : Array[Int]
  findings : Int
  unparsed : Int
  text : String
} derive(Eq, @debug.Debug)

///|
pub extend JsonLinesResult with Eq::{equal, not_equal}

///|
pub extend JsonLinesResult with @debug.Debug::{to_repr}

///|
pub fn redact_json_lines(
  text : String,
  config? : ScanConfig = ScanConfig::standard(),
  style? : RedactionStyle = Typed,
) -> JsonLinesResult {
  let lines : Array[String] = []
  let mut current = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    if text[i].to_int() == 10 {
      lines.push(current.to_string())
      current = StringBuilder()
    } else {
      current.write_char(Int::unsafe_to_char(text[i].to_int()))
    }
  }
  let has_final_newline = text.length() > 0 && text[text.length() - 1].to_int() == 10
  let tail = current.to_string()
  if tail != "" || has_final_newline == false {
    if tail != "" {
      lines.push(tail)
    }
  }
  let out : Array[String] = []
  let changed : Array[Int] = []
  let mut findings = 0
  let mut unparsed = 0
  for index, line in lines {
    let result = redact_json(line, config~, style~)
    // A parsed line with zero findings echoes byte-identical: the
    // canonical compact form is only imposed when something actually
    // changed, so clean rows survive a roundtrip untouched.
    if result.parsed && result.findings.length() == 0 {
      out.push(line)
    } else {
      out.push(result.text)
      if result.text != line {
        changed.push(index)
      }
    }
    findings += result.findings.length()
    if !result.parsed {
      unparsed += 1
    }
  }
  // Rejoin with the original terminator convention.
  let rebuilt = StringBuilder()
  for index, line in out {
    if index > 0 {
      rebuilt.write_char('\n')
    }
    rebuilt.write_string(line)
  }
  if has_final_newline {
    rebuilt.write_char('\n')
  }
  {
    lines: out,
    changed_indices: changed,
    findings,
    unparsed,
    text: rebuilt.to_string(),
  }
}
