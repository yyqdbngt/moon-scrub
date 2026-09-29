///|
test "wider service token families are detected" {
  let samples = [
    ("gitlab", "ci_token=glpat-abcdefghijklmnop", "glpat-abcdefghijklmnop"),
    (
      "slack-user", "xoxb-123456789012-123456789012-abcdefghij", "xoxb-123456789012-123456789012-abcdefghij",
    ),
    (
      "google", "key = AIzaSyA1234567890abcdefghij", "AIzaSyA1234567890abcdefghij",
    ),
    ("aws-temp", "creds ASIAIOSFODNN7EXAMPLE end", "ASIAIOSFODNN7EXAMPLE"),
    ("stripe", "sk_live_abcdefghijklmnopqrst", "sk_live_abcdefghijklmnopqrst"),
    (
      "anthropic", "sk-ant-api03-abcdefghijklmnop", "sk-ant-api03-abcdefghijklmnop",
    ),
    (
      "sendgrid", "mail SG.abcdefghijklmnop.qrstuvwxyz", "SG.abcdefghijklmnop.qrstuvwxyz",
    ),
    ("doppler", "dop_v1_abcdefghijklmnopqrst", "dop_v1_abcdefghijklmnopqrst"),
  ]
  for pair in samples {
    let findings = @moon_scrub.scan(
      pair.1,
      policy=@moon_scrub.ScanPolicy::secrets_only(),
    )
    assert_eq(findings.length(), 1)
    assert_eq(findings[0].kind, @moon_scrub.AccessToken)
    assert_eq(pair.1[findings[0].start:findings[0].end].to_owned(), pair.2)
  }
}

///|
test "short prefixed runs stay undetected" {
  assert_eq(
    @moon_scrub.scan(
      "key=AIza123 end",
      policy=@moon_scrub.ScanPolicy::secrets_only(),
    ).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan(
      "key=sk-abc end",
      policy=@moon_scrub.ScanPolicy::secrets_only(),
    ).length(),
    0,
  )
}

///|
test "detector families can be switched off one by one" {
  let input = "token=ghp_1234567890abcdefghij password=hunter2 mail demo@example.com"
  let no_tokens = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    detect_access_token: false,
  }
  let findings = @moon_scrub.scan_with_config(input, no_tokens)
  // The prefixed-token detector is off, but `token=` and `password=` are both
  // sensitive assignments, so both values are reported as credentials.
  assert_eq(findings.length(), 2)
  assert_eq(findings[0].kind, @moon_scrub.CredentialAssignment)
  assert_eq(findings[1].kind, @moon_scrub.CredentialAssignment)
  let only_tokens = {
    ..@moon_scrub.ScanConfig::standard(),
    detect_bearer: false,
    detect_jwt: false,
    detect_private_key: false,
    detect_url_credential: false,
    detect_assignment: false,
    detect_email: false,
    detect_ipv4: false,
    detect_payment_card: false,
  }
  let tokens = @moon_scrub.scan_with_config(input, only_tokens)
  assert_eq(tokens.length(), 1)
  assert_eq(tokens[0].kind, @moon_scrub.AccessToken)
}

///|
test "extra prefixed-token rules extend the built-in set" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_prefixes: [
      @moon_scrub.TokenPrefixRule::{ prefix: "corp_", min_length: 16, },
    ],
  }
  let hit = @moon_scrub.scan_with_config(
    "session corp_abcdefgh1234 done", config,
  )
  assert_eq(hit.length(), 1)
  assert_eq(hit[0].kind, @moon_scrub.AccessToken)
  assert_eq(
    "session corp_abcdefgh1234 done"[hit[0].start:hit[0].end].to_owned(),
    "corp_abcdefgh1234",
  )
  // Below the configured minimum the rule stays silent.
  assert_eq(
    @moon_scrub.scan_with_config("session corp_abc done", config).length(),
    0,
  )
}

///|
test "degenerate custom prefix rules are ignored" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_prefixes: [
      @moon_scrub.TokenPrefixRule::{ prefix: "x", min_length: 40, },
      @moon_scrub.TokenPrefixRule::{ prefix: "longprefix", min_length: 3, },
    ],
  }
  assert_eq(
    @moon_scrub.scan_with_config(
      "xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA token=ghp_1234567890abcdefghij",
      config,
    ).length(),
    1,
  )
}

///|
test "redact_full combines configuration with exact-value rules" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_prefixes: [
      @moon_scrub.TokenPrefixRule::{ prefix: "corp_", min_length: 16, },
    ],
  }
  let rules = [
    @moon_scrub.CustomRule::{ label: "tenant", value: "internal-42", },
  ]
  let result = @moon_scrub.redact_full(
    "corp_abcdefgh1234 tenant=internal-42 ok", rules, config,
  )
  assert_eq(
    result.text,
    "[REDACTED:ACCESS_TOKEN] tenant=[REDACTED:CUSTOM_SECRET] ok",
  )
}
