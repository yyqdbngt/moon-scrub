///|
test "batch redaction keeps line count and safe category totals" {
  let result = @moon_scrub.redact_batch([
    "login demo@example.com from 10.0.0.1", "password=not-for-logs", "request complete",
    "card 4111 1111 1111 1111",
  ])
  assert_eq(result.lines.length(), 4)
  assert_eq(result.summary.lines, 4)
  assert_eq(result.summary.changed_lines, 3)
  assert_eq(result.summary.findings, 4)
  assert_eq(result.summary.emails, 1)
  assert_eq(result.summary.ipv4s, 1)
  assert_eq(result.summary.credentials, 1)
  assert_eq(result.summary.payment_cards, 1)
  for line in result.lines {
    assert_true(@moon_scrub.verify_clean(line))
  }
}

///|
test "ten thousand log lines preserve count and deterministic totals" {
  let lines : Array[String] = []
  for i = 0; i < 10000; i = i + 1 {
    lines.push(
      if i % 4 == 0 {
        "user=demo@example.com"
      } else if i % 4 == 1 {
        "password=secret-value"
      } else if i % 4 == 2 {
        "client=192.168.10.20"
      } else {
        "ordinary message"
      },
    )
  }
  let result = @moon_scrub.redact_batch(lines)
  assert_eq(result.lines.length(), 10000)
  assert_eq(result.summary.changed_lines, 7500)
  assert_eq(result.summary.findings, 7500)
  assert_eq(result.summary.emails, 2500)
  assert_eq(result.summary.credentials, 2500)
  assert_eq(result.summary.ipv4s, 2500)
}

///|
test "batch results report which line indices changed" {
  let result = @moon_scrub.redact_batch([
    "plain request", "password=hunter2", "another plain", "mail a@b.co",
  ])
  assert_eq(result.changed_indices.length(), 2)
  assert_eq(result.changed_indices[0], 1)
  assert_eq(result.changed_indices[1], 3)
}
