///|
test "entropy report bands structural tokens low" {
  let text = "mail demo@example.com id 110105199001010010"
  let report = @moon_scrub.entropy_report(text, @moon_scrub.ScanConfig::standard())
  assert_eq(report.finding_count, 2)
  assert_eq(report.very_high, 0)
  assert_eq(report.high, 0)
  assert_eq(report.low + report.medium, 2)
  for entry in report.entries {
    assert_true(entry.entropy >= 0.0 && entry.entropy <= 7.0)
  }
  assert_false(report.needs_review())
}

///|
test "entropy report flags random material" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    detect_high_entropy: true,
  }
  let text = "key c2VjcmV0IHRleHQgd2l0aCBzcGFjZXMgYW5kIG1vcmU= here"
  let report = @moon_scrub.entropy_report(text, config)
  assert_true(report.finding_count >= 1)
  let mut saw_high = false
  for entry in report.entries {
    if entry.band == "very-high" || entry.band == "high" {
      saw_high = true
    }
  }
  assert_true(saw_high)
  assert_true(report.needs_review())
}

///|
test "entropy report counts sensitive density" {
  let text = "user=demo@example.com plain padding here"
  let report = @moon_scrub.entropy_report(text, @moon_scrub.ScanConfig::standard())
  assert_eq(report.text_units, text.length())
  assert_eq(report.sensitive_chars, 16)
  let density = report.density_per_kilo()
  assert_eq(density, 400.0)
}

///|
test "entropy report of clean text is empty" {
  let report = @moon_scrub.entropy_report(
    "nothing interesting at all",
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(report.finding_count, 0)
  assert_eq(report.sensitive_chars, 0)
  assert_eq(report.density_per_kilo(), 0.0)
  assert_false(report.needs_review())
}
