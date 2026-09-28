///|
fn main {
  let result = @scrub.redact_batch([
    "login user=demo@example.com from 10.0.0.8", "authorization: Bearer abcdefghijklmnop",
    "payment card=4111-1111-1111-1111", "request completed in 15ms",
  ])
  for line in result.lines {
    println(line)
  }
  println("changed-lines=" + result.summary.changed_lines.to_string())
  println("findings=" + result.summary.findings.to_string())
}
