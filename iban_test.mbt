///|
test "iban detects known-valid numbers across countries" {
  let config = @moon_scrub.ScanConfig::standard()
  let samples = [
    ("invoice DE89370400440532013000 paid", "DE89370400440532013000"),
    ("GB29NWBK60161331926819 out", "GB29NWBK60161331926819"),
    ("FR1420041010050500013M02606 ok", "FR1420041010050500013M02606"),
    ("NL91ABNA0417164300", "NL91ABNA0417164300"),
    ("ES9121000418450200051332", "ES9121000418450200051332"),
    ("IT60X0542811101000000123456", "IT60X0542811101000000123456"),
    ("BE68539007547034", "BE68539007547034"),
    ("AT611904300234573201", "AT611904300234573201"),
    ("CH9300762011623852957", "CH9300762011623852957"),
    ("SE3550000000054910000003", "SE3550000000054910000003"),
    ("IE29AIBK93115212345678", "IE29AIBK93115212345678"),
    ("NO9386011117947", "NO9386011117947"),
  ]
  for sample in samples {
    let findings = @moon_scrub.scan_with_config(sample.0, config)
    assert_eq(findings.length(), 1)
    assert_eq(findings[0].kind, @moon_scrub.Iban)
    assert_eq(findings[0].confidence, @moon_scrub.High)
    let span = @moon_scrub.redact_with_config(sample.0, config).text
    // The redacted text must carry the IBAN marker.
    assert_true(span.contains("[REDACTED:IBAN]"))
  }
}

///|
test "iban offsets match the literal" {
  let text = "pay to DE89370400440532013000 today"
  let findings = @moon_scrub.scan_with_config(text, @moon_scrub.ScanConfig::standard())
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].start, 7)
  assert_eq(findings[0].end, 29)
  assert_eq(
    text[findings[0].start:findings[0].end].to_owned(),
    "DE89370400440532013000",
  )
}

///|
test "iban rejects bad checksums and wrong lengths" {
  let config = @moon_scrub.ScanConfig::standard()
  let rejects = [
    // last digit flipped
    "DE89370400440532013001",
    // GB with a flipped check digit
    "GB29NWBK60161331926810",
    // DE expects 22, this is 18
    "DE8937040044053201",
    // unlisted country with plausible shape
    "US12345678901234567890",
    // FR length mismatch
    "FR1420041010050500013M0260",
  ]
  for sample in rejects {
    let findings = @moon_scrub.scan_with_config(sample, config)
    assert_eq(findings.length(), 0)
  }
}

///|
test "iban ignores lowercase and glued runs" {
  let config = @moon_scrub.ScanConfig::standard()
  // lowercase form is not detected
  assert_eq(
    @moon_scrub.scan_with_config("de89370400440532013000", config).length(),
    0,
  )
  // glued to a longer uppercase alnum run: no boundary, no finding
  assert_eq(
    @moon_scrub.scan_with_config(
      "REFABCDE89370400440532013000X",
      config,
    ).length(),
    0,
  )
}

///|
test "iban honours family switches" {
  let secrets = @moon_scrub.ScanConfig::secrets_only()
  assert_eq(
    @moon_scrub.scan_with_config("DE89370400440532013000", secrets).length(),
    0,
  )
  let pii = @moon_scrub.ScanConfig::pii_only()
  assert_eq(
    @moon_scrub.scan_with_config("DE89370400440532013000", pii).length(),
    1,
  )
}

///|
test "iban redaction is idempotent" {
  let text = "acct DE89370400440532013000 please"
  let config = @moon_scrub.ScanConfig::standard()
  let once = @moon_scrub.redact_with_config(text, config).text
  let twice = @moon_scrub.redact_with_config(once, config).text
  assert_eq(once, twice)
  assert_true(once.contains("[REDACTED:IBAN]"))
  assert_false(once.contains("DE89"))
}

///|
test "batch summary counts ibans" {
  let result = @moon_scrub.redact_batch_with_config(
    [
    "DE89370400440532013000",
    "plain line",
    "GB29NWBK60161331926819",
    ],
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(result.summary.ibans, 2)
  assert_eq(result.summary.findings, 2)
}
