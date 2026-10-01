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
}
