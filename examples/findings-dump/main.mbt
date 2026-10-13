///|
/// Deterministic corpus shared with tools/differential.py: the same
/// Lehmer generator with the same seeds produces byte-identical input
/// on both sides.
fn lcg(state : Int64) -> Int64 {
  state * 48271L % 2147483647L
}

///|
fn word(state : Int64, length : Int) -> (String, Int64) {
  let letters = "abcdefghijklmnopqrstuvwxyz"
  let buf = StringBuilder()
  let mut s = state
  for _ in 0..<length {
    s = lcg(s)
    buf.write_char(Int::unsafe_to_char(letters[(s % 26L).to_int()].to_int()))
  }
  (buf.to_string(), s)
}

///|
fn corpus() -> Array[String] {
  let lines : Array[String] = []
  let mut state = 77L
  for i = 0; i < 40; i = i + 1 {
    let (w, next) = word(state, 8)
    state = next
    let line = match i % 8 {
      0 => "mail " + w + "@example.com"
      1 => "password=" + w + "value"
      2 => "token=ghp_" + w + w + "1234"
      3 => "ip 10.0." + (i % 200).to_string() + ".7 v1.2.3.4"
      4 => "card 4111 1111 1111 1111"
      5 => "auth: Bearer " + w + w
      6 => "id 110105199001010010"
      _ => "plain " + w + " request"
    }
    lines.push(line)
  }
  lines
}

///|
fn main {
  let config = @scrub.ScanConfig::standard()
  for line in corpus() {
    let findings = @scrub.scan_with_config(line, config)
    if findings.length() == 0 {
      println("-")
    } else {
      let mut parts = ""
      for f in findings {
        parts += f.kind.to_string() +
          " " +
          f.start.to_string() +
          " " +
          f.end.to_string() +
          " " +
          f.confidence.to_string() +
          ";"
      }
      println(parts)
    }
  }
  // Second block: typed redaction of every line, printed verbatim.
  for line in corpus() {
    println("R|" + @scrub.redact_with_config(line, config).text)
  }
  // Third block: whole-line JSON documents (mixed leaves), redacted.
  for line in corpus() {
    let doc = "{\"row\": \"" + line + "\", \"note\": \"plain\"}"
    println("J|" + @scrub.redact_json(doc, config~).text)
  }
  // Fourth block: the whole corpus as one stream, chunked at 7 units.
  let mut stream = ""
  for line in corpus() {
    stream += line + "\n"
  }
  let scanner = @scrub.ChunkScanner::new(overlap=64)
  let streamed : Array[@scrub.Finding] = []
  let mut i = 0
  while i < stream.length() {
    let end = if i + 7 < stream.length() { i + 7 } else { stream.length() }
    for finding in scanner.push(stream[i:end].to_owned()) {
      streamed.push(finding)
    }
    i = end
  }
  for finding in scanner.finish() {
    streamed.push(finding)
  }
  for finding in streamed {
    println(
      "S|" +
      finding.kind.to_string() +
      " " +
      finding.start.to_string() +
      " " +
      finding.end.to_string() +
      " " +
      finding.confidence.to_string(),
    )
  }
  // Fifth block: finding diffs between each original line and a mutated
  // copy with a synthetic leak appended, plus locations in the mutated
  // copy. Exercises diff_findings, format_diff_report, locate_findings
  // and format_location against the Python reference.
  for line in corpus() {
    let mutated = line + " leak=sk-ant-synthetic0000000001"
    let before = @scrub.scan_with_config(line, config)
    let after = @scrub.scan_with_config(mutated, config)
    let diff = @scrub.diff_findings(before, after)
    let report = @scrub.format_diff_report(diff)
    if report.length() == 0 {
      println("D|-")
    } else {
      let mut parts = ""
      for k = 0; k < report.length(); k = k + 1 {
        if k > 0 {
          parts += ","
        }
        parts += report[k]
      }
      println("D|" + parts)
    }
    let located = @scrub.locate_findings(mutated, after)
    let mut marks = ""
    for k = 0; k < located.length(); k = k + 1 {
      if k > 0 {
        marks += ";"
      }
      marks += @scrub.format_location(located[k])
    }
    println("L|" + marks)
  }
  // Sixth block: key-value adaptation of each line plus a quoted
  // variant with a secret containing a space, exercising collapse.
  for line in corpus() {
    println("K|" + @scrub.redact_kv(line, config))
    let kv = "msg=\"" + line + "\" level=info"
    println("Q|" + @scrub.redact_kv(kv, config))
  }
  // Seventh block: NDJSON pipeline over the corpus with a malformed
  // line injected, exercising isolation and clean-line echo.
  let nd = StringBuilder()
  for k = 0; k < corpus().length(); k = k + 1 {
    let line = corpus()[k]
    nd.write_string("{\"row\": \"")
    nd.write_string(line)
    nd.write_string("\"}\n")
    if k == 10 {
      nd.write_string("{\"broken\": \n")
    }
  }
  let lines_result = @scrub.redact_json_lines(nd.to_string())
  let mut flat = ""
  for k = 0; k < lines_result.lines.length(); k = k + 1 {
    if k > 0 {
      flat += "\\n"
    }
    flat += lines_result.lines[k]
  }
  // the input ends with a newline, so the rebuilt text does too; the
  // flattening represents that terminator literally, like the reference
  flat += "\\n"
  println("N|" + flat)
  let mut changed_flat = ""
  for k = 0; k < lines_result.changed_indices.length(); k = k + 1 {
    if k > 0 {
      changed_flat += ","
    }
    changed_flat += lines_result.changed_indices[k].to_string()
  }
  println("C|" + changed_flat)
  // Eighth block: suppression transparency over the same probe lines.
  let probes = [
    "release v1.2.3.4 and host 10.0.0.8",
    "ref 7992739871300 paid",
    "nothing hidden here",
  ]
  let gate = {
    ..config,
    suppress_version_ipv4: true,
    require_known_card_prefix: true,
    suppress_example_domains: true,
  }
  for probe in probes {
    let entries = @scrub.explain_suppressed(probe, gate)
    if entries.length() == 0 {
      println("X|-")
      continue
    }
    let mut parts = ""
    for k = 0; k < entries.length(); k = k + 1 {
      if k > 0 {
        parts += ";"
      }
      parts += entries[k].kind.to_string() +
        " " +
        entries[k].start.to_string() +
        " " +
        entries[k].end.to_string() +
        " " +
        entries[k].reason
    }
    println("X|" + parts)
  }
}
