///|
test "shape rules match constrained alphabets with length windows" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_patterns: [
      @moon_scrub.PatternRule::{
        prefix: "txn_",
        chars: @moon_scrub.HexLower,
        min_length: 20,
        max_length: 24,
      },
    ],
  }
  let input = "ref txn_3f9a2c81d07b4e5591 ok"
  let findings = @moon_scrub.scan_with_config(input, config)
  assert_eq(findings.length(), 1)
  assert_eq(
    input[findings[0].start:findings[0].end].to_owned(),
    "txn_3f9a2c81d07b4e5591",
  )
}

///|
test "shape rules reject wrong alphabet and out-of-window lengths" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_patterns: [
      @moon_scrub.PatternRule::{
        prefix: "acct-",
        chars: @moon_scrub.Digits,
        min_length: 12,
        max_length: 16,
      },
    ],
  }
  // A letter terminates the digit run; the twelve-plus units before it
  // sit inside the window and are a legitimate match.
  let truncated = @moon_scrub.scan_with_config("x acct-12345678a9", config)
  assert_eq(truncated.length(), 1)
  assert_eq(truncated[0].kind, @moon_scrub.AccessToken)
  // Too short.
  assert_eq(@moon_scrub.scan_with_config("x acct-123", config).length(), 0)
  // Past max: the run continues beyond the window.
  assert_eq(
    @moon_scrub.scan_with_config("x acct-1234567890123456789", config).length(),
    0,
  )
  // Uppercase hex is outside HexLower.
  assert_eq(
    @moon_scrub.scan_with_config("x txn_3F9A", {
      ..config,
      extra_patterns: [
        @moon_scrub.PatternRule::{
          prefix: "txn_",
          chars: @moon_scrub.HexLower,
          min_length: 8,
          max_length: 12,
        },
      ],
    }).length(),
    0,
  )
}
