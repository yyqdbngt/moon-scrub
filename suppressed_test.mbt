///|
fn suppressed_config() -> @moon_scrub.ScanConfig {
  {
    ..@moon_scrub.ScanConfig::standard(),
    suppress_version_ipv4: true,
    require_known_card_prefix: true,
    suppress_example_domains: true,
  }
}

///|
test "suppressed attributes version-shaped ipv4" {
  let text = "release v1.2.3.4 and host 10.0.0.8"
  let suppressed = @moon_scrub.explain_suppressed(text, suppressed_config())
  assert_eq(suppressed.length(), 1)
  assert_eq(suppressed[0].kind, @moon_scrub.Ipv4)
  assert_true(suppressed[0].reason.contains("suppress_version_ipv4"))
  // and the kept scan really does not contain it
  let kept = @moon_scrub.scan_with_config(text, suppressed_config())
  assert_eq(kept.length(), 1)
  assert_eq(kept[0].kind, @moon_scrub.Ipv4)
}

///|
test "suppressed attributes unknown-network luhn numbers" {
  let text = "ref 7992739871300 paid"
  let suppressed = @moon_scrub.explain_suppressed(text, suppressed_config())
  assert_eq(suppressed.length(), 1)
  assert_eq(suppressed[0].kind, @moon_scrub.PaymentCard)
  assert_true(suppressed[0].reason.contains("require_known_card_prefix"))
}

///|
test "suppressed attributes documentation email domains" {
  let text = "contact user@example.com or ops@real.example"
  let suppressed = @moon_scrub.explain_suppressed(text, suppressed_config())
  let mut saw_email = false
  for entry in suppressed {
    if entry.kind == @moon_scrub.Email {
      saw_email = true
      assert_true(entry.reason.contains("suppress_example_domains"))
    }
  }
  assert_true(saw_email)
}

///|
test "suppressed is empty for clean text" {
  let suppressed = @moon_scrub.explain_suppressed(
    "plain text with nothing",
    suppressed_config(),
  )
  assert_eq(suppressed.length(), 0)
}

///|
test "suppressed offsets slice to the candidate" {
  let text = "build v10.0.0.1 ok"
  let suppressed = @moon_scrub.explain_suppressed(text, suppressed_config())
  assert_eq(suppressed.length(), 1)
  assert_eq(
    text[suppressed[0].start:suppressed[0].end].to_owned(),
    "10.0.0.1",
  )
}
