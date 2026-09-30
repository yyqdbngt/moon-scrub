///|
test "high-entropy runs are flagged when the family is on" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    detect_high_entropy: true,
  }
  let input = "key ZkSBvrjn9Wvgfygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2 done"
  let findings = @moon_scrub.scan_with_config(input, config)
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.HighEntropySecret)
  assert_eq(findings[0].confidence, @moon_scrub.Medium)
}

///|
test "english prose and base64-encoded prose stay below the bar" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    detect_high_entropy: true,
  }
  assert_eq(
    @moon_scrub.scan_with_config(
      "note thequickbrownfoxjumpsoverthelazydogandrunsfarawa end", config,
    ).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config(
      "blob SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgZW50cm9weQ== end", config,
    ).length(),
    0,
  )
}

///|
test "high-entropy detection is opt-in" {
  assert_eq(
    @moon_scrub.scan_with_config(
      "key ZkSBvrjn9Wvgfygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2",
      @moon_scrub.ScanConfig::standard(),
    ).length(),
    0,
  )
}
