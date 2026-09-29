///|
test "ipv4 embedded in version-like tokens is suppressed" {
  let findings = @moon_scrub.scan("upgraded to v1.2.3.4 and build 2.0.0.1rc1")
  assert_eq(findings.length(), 0)
  // The same literals outside a word remain findings.
  let plain = @moon_scrub.scan("connect 1.2.3.4 now")
  assert_eq(plain.length(), 1)
  assert_eq(plain[0].kind, @moon_scrub.Ipv4)
}

///|
test "trailing period after an ipv4 is not treated as a version suffix" {
  let findings = @moon_scrub.scan("peer 10.0.0.8. next hop down")
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.Ipv4)
}

///|
test "luhn-valid numbers outside known card networks are suppressed" {
  assert_eq(@moon_scrub.scan("order 1234567890123452 shipped").length(), 0)
  // Known networks keep passing: Visa, Amex.
  let visa = @moon_scrub.scan("card 4111111111111111")
  assert_eq(visa.length(), 1)
  let amex = @moon_scrub.scan("card 378282246310005")
  assert_eq(amex.length(), 1)
}

///|
test "card prefix suppression can be relaxed for recall" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    require_known_card_prefix: false,
  }
  let findings = @moon_scrub.scan_with_config(
    "order 1234567890123452 shipped", config,
  )
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.PaymentCard)
}

///|
test "version ipv4 suppression can be relaxed too" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    suppress_version_ipv4: false,
  }
  let findings = @moon_scrub.scan_with_config("upgraded to v1.2.3.4", config)
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.Ipv4)
}

///|
test "preserve-last4 redaction is idempotent for bearer values" {
  let input = "authorization: Bearer abcdefghijklmnop"
  let first = @moon_scrub.redact(input, style=@moon_scrub.PreserveLast4)
  assert_true(first.changed)
  let second = @moon_scrub.redact(first.text, style=@moon_scrub.PreserveLast4)
  assert_false(second.changed)
  assert_eq(second.text, first.text)
}

///|
test "marker-aware scanning keeps repeated typed redaction stable" {
  let once = @moon_scrub.redact(
    "password=hunter2 token=ghp_1234567890abcdefghij",
  )
  let twice = @moon_scrub.redact(once.text)
  assert_eq(twice.text, once.text)
  assert_false(twice.changed)
}
