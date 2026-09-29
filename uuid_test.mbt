///|
test "canonical and uppercase uuids are medium findings" {
  let config = @moon_scrub.ScanConfig::standard()
  let a = @moon_scrub.scan_with_config(
    "id 550e8400-e29b-41d4-a716-446655440000 x", config,
  )
  assert_eq(a.length(), 1)
  assert_eq(a[0].kind, @moon_scrub.Uuid)
  assert_eq(a[0].confidence, @moon_scrub.Medium)
  let b = @moon_scrub.scan_with_config(
    "id A1B2C3D4-E5F6-4789-8ABC-DEF012345678 x", config,
  )
  assert_eq(b.length(), 1)
}

///|
test "uuid-like strings with wrong group lengths are ignored" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config("x 550e8400-e29b-41d4-a716 x", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config(
      "x 550e8400e29b41d4a716446655440000 no-hyphens", config,
    ).length(),
    0,
  )
  // A leading hyphen is an ordinary separator (request-id style); only hex
  // characters on the boundary suppress the match.
  let prefixed = @moon_scrub.scan_with_config(
    "x-550e8400-e29b-41d4-a716-446655440000",
    config,
  )
  assert_eq(prefixed.length(), 1)
  assert_eq(prefixed[0].kind, @moon_scrub.Uuid)
  assert_eq(
    @moon_scrub.scan_with_config(
      "z550e8400-e29b-41d4-a716-446655440000", config,
    ).length(),
    0,
  )
}
