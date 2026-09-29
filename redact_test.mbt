///|
test "typed redaction is deterministic and idempotent" {
  let input = "user=demo@example.com password=hunter2 ip=10.0.0.8"
  let first = @moon_scrub.redact(input)
  assert_true(first.changed)
  assert_eq(
    first.text,
    "user=[REDACTED:EMAIL] password=[REDACTED:CREDENTIAL] ip=[REDACTED:IPV4]",
  )
  let second = @moon_scrub.redact(first.text)
  assert_false(second.changed)
  assert_eq(second.text, first.text)
  assert_true(@moon_scrub.verify_clean(first.text))
}

///|
test "marker style uses a constant replacement" {
  assert_eq(
    @moon_scrub.redact("email a@b.co", style=@moon_scrub.Marker).text,
    "email [REDACTED]",
  )
}

///|
test "last4 style retains only a small suffix" {
  let result = @moon_scrub.redact(
    "card=4111111111111111",
    style=@moon_scrub.PreserveLast4,
  )
  assert_eq(result.text, "card=[REDACTED:PAYMENT_CARD:*1111]")
  assert_true(@moon_scrub.verify_clean(result.text))
}

///|
test "clean input is returned unchanged" {
  let result = @moon_scrub.redact("request completed in 15ms")
  assert_false(result.changed)
  assert_eq(result.findings.length(), 0)
}

///|
test "overlapping credential and token detectors produce one replacement" {
  let result = @moon_scrub.redact(
    "api_key=sk-1234567890abcdef",
    policy=@moon_scrub.ScanPolicy::secrets_only(),
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(result.text, "api_key=[REDACTED:ACCESS_TOKEN]")
}
