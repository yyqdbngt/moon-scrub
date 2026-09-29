///|
test "e164 numbers are medium findings when the family is enabled" {
  let config = { ..@moon_scrub.ScanConfig::standard(), detect_phone: true, }
  let found = @moon_scrub.scan_with_config("call +8613800138000 now", config)
  assert_eq(found.length(), 1)
  assert_eq(found[0].kind, @moon_scrub.Phone)
  assert_eq(found[0].confidence, @moon_scrub.Medium)
  let us = @moon_scrub.scan_with_config("fax +12125550123", config)
  assert_eq(us.length(), 1)
}

///|
test "phone detection is opt-in and rejects short runs" {
  assert_eq(
    @moon_scrub.scan_with_config(
      "+8613800138000",
      @moon_scrub.ScanConfig::standard(),
    ).length(),
    0,
  )
  let config = { ..@moon_scrub.ScanConfig::standard(), detect_phone: true, }
  assert_eq(@moon_scrub.scan_with_config("ref +1234567", config).length(), 0)
  assert_eq(
    @moon_scrub.scan_with_config("zero +0123456789", config).length(),
    0,
  )
}
