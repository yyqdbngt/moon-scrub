///|
test "batch tally counts private keys custom secrets and entropy" {
  let pem = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
  let hot = { ..@moon_scrub.ScanConfig::standard(), detect_high_entropy: true, }
  let result = @moon_scrub.redact_batch_with_config(
    [
      "key " + pem,
      "plain note only",
      "blob ZkSBvrjn9Wvgfygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2",
    ],
    hot,
  )
  assert_eq(result.summary.private_keys, 1)
  assert_eq(result.summary.high_entropy_secrets, 1)
  // CustomSecret tally runs through scan_full-backed redaction.
  let rules : Array[@moon_scrub.CustomRule] = [
    @moon_scrub.CustomRule::{ label: "t", value: "internal-42", },
  ]
  let scanned = @moon_scrub.scan_full(
    "tenant=internal-42",
    rules,
    @moon_scrub.ScanConfig::secrets_only(),
  )
  assert_eq(scanned.length(), 1)
  assert_eq(scanned[0].kind, @moon_scrub.CustomSecret)
}

///|
test "truncated pem footers fall back to end of text" {
  // No END marker at all: the whole tail is the finding.
  let truncated = "-----BEGIN PRIVATE KEY-----\nMIIEvQ never closed"
  let found = @moon_scrub.scan(
    truncated,
    policy=@moon_scrub.ScanPolicy::secrets_only(),
  )
  assert_eq(found.length(), 1)
  assert_eq(found[0].end, truncated.length())
}

///|
test "leap-day resident ids and invalid ipv6 edges" {
  // 2000 is a leap year, so 02-29 is a valid birth date.
  let leap = @moon_scrub.scan_with_config(
    "id 110105200002290013",
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(leap.length(), 1)
  let config = @moon_scrub.ScanConfig::standard()
  // Empty group, five-digit group, and trailing-colon runs all reject.
  assert_eq(@moon_scrub.scan_with_config("x 1::2:3:4::5", config).length(), 0)
  assert_eq(@moon_scrub.scan_with_config("x 12345::6", config).length(), 0)
  assert_eq(
    @moon_scrub.scan_with_config("x 1:2:3:4:5:6:7:", config).length(),
    0,
  )
}

///|
test "json escape handles quotes prefixes booleans and null members" {
  let result = @moon_scrub.redact_json(
    "{\"b\": \"password=hunter2\", \"a\": \"quoted\\\"inner\"}",
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"a\":\"quoted\\\"inner\",\"b\":\"password=[REDACTED:CREDENTIAL]\"}",
  )
  let flags = @moon_scrub.redact_json(
    "{\"on\": false, \"off\": null, \"n\": 1}",
  )
  assert_eq(flags.text, "{\"n\":1,\"off\":null,\"on\":false}")
}

///|
test "short values under preserve-last4 use the plain typed marker" {
  let result = @moon_scrub.redact(
    "password=abc",
    style=@moon_scrub.PreserveLast4,
  )
  assert_eq(result.text, "password=[REDACTED:CREDENTIAL]")
}

///|
test "verify_clean_with_config passes clean text and unicode scans skip buckets" {
  assert_true(
    @moon_scrub.verify_clean_with_config(
      "ordinary 中文日志 line",
      @moon_scrub.ScanConfig::standard(),
    ),
  )
  assert_eq(
    @moon_scrub.scan_with_config(
      "中文 context token=ghp_1234567890abcdefghij 尾",
      @moon_scrub.ScanConfig::secrets_only(),
    ).length(),
    1,
  )
}
