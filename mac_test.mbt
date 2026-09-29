///|
test "mac addresses in both separator styles are medium-confidence findings" {
  let config = @moon_scrub.ScanConfig::standard()
  let colon = @moon_scrub.scan_with_config("nic 02:00:5e:10:00:03 up", config)
  assert_eq(colon.length(), 1)
  assert_eq(colon[0].kind, @moon_scrub.MacAddress)
  assert_eq(colon[0].confidence, @moon_scrub.Medium)
  let hyphen = @moon_scrub.scan_with_config(
    "ap dc-a6-32-0f-88-01 joined", config,
  )
  assert_eq(hyphen.length(), 1)
}

///|
test "partial or mixed-separator runs are not mac addresses" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config("id 02:00:5e three groups", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config("mix 02:00-5e:10-00:03 x", config).length(),
    0,
  )
  // UUID-shaped hex is not a MAC address; with the UUID family enabled it
  // is reported once, as a UUID.
  let traced = @moon_scrub.scan_with_config(
    "req 550e8400-e29b-41d4-a716-446655440000", config,
  )
  assert_eq(traced.length(), 1)
  assert_eq(traced[0].kind, @moon_scrub.Uuid)
}
