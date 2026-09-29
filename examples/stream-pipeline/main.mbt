///|
fn main {
  let chunks = [
    "connect 10.0.0.8 user=demo@example.com pass", "word=hunter2 token=ghp_", "1234567890abcdefghij disconnect\n",
  ]
  let scanner = @scrub.ChunkScanner::new(overlap=128)
  for chunk in chunks {
    for finding in scanner.push(chunk) {
      println(
        "settled " +
        finding.kind.to_string() +
        " at " +
        finding.start.to_string() +
        "-" +
        finding.end.to_string(),
      )
    }
  }
  for finding in scanner.finish() {
    println(
      "flushed " +
      finding.kind.to_string() +
      " at " +
      finding.start.to_string() +
      "-" +
      finding.end.to_string(),
    )
  }
}
