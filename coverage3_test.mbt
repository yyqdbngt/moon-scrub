///|
test "coverage batch: mac tally through the batch pipeline" {
  let result = @moon_scrub.redact_batch_with_config(
    ["nic 02:00:5e:10:00:03"],
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(result.summary.mac_addresses, 1)
}

///|
test "coverage credentials: truncated footers fall to end of text" {
  // A certificate block with no END marker at all consumes the whole tail.
  let cut = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAg only"
  let found = @moon_scrub.scan_with_config(
    cut,
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(found.length(), 1)
  assert_eq(found[0].end, cut.length())
}

///|
test "coverage identifiers: degenerate colon runs and short groups" {
  let config = @moon_scrub.ScanConfig::standard()
  for sample in ["x 1:::2", "x 1:2:3:4:5:6:7:8:9", "x 1:2:3:4:5:6:7:8:9:1:2"] {
    assert_eq(@moon_scrub.scan_with_config(sample, config).length(), 0)
  }
}

///|
test "coverage identifiers: thirty-day month boundary on resident ids" {
  let found = @moon_scrub.scan_with_config(
    "id 110105200004300019",
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(found.length(), 1)
}

///|
test "coverage json: backslash control keys null members and prefix ordering" {
  let result = @moon_scrub.redact_json(
    "{\"a\": \"pass\\\\slash\", \"ab\": \"ctrl\\u0001x\", \"n\": null}",
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"a\":\"pass\\\\slash\",\"ab\":\"ctrl\\u0001x\",\"n\":null}",
  )
}

///|
test "coverage tokens: non-ascii directly before a prefix" {
  let found = @moon_scrub.scan_with_config(
    "中文ghp_1234567890abcdefghij",
    @moon_scrub.ScanConfig::secrets_only(),
  )
  assert_eq(found.length(), 1)
}
