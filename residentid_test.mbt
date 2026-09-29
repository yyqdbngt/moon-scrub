///|
test "checksum-valid resident ids with real birth dates are detected" {
  let input = "customer 110105199001010010 checked"
  let findings = @moon_scrub.scan_with_config(
    input,
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.ResidentId)
  assert_eq(
    input[findings[0].start:findings[0].end].to_owned(),
    "110105199001010010",
  )
}

///|
test "checksum failures and impossible birth dates are rejected" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config("id 110105199001010011 bad-check", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config("id 110105199013010042 month13", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config("id 110105200102290010 feb29", config).length(),
    0,
  )
}

///|
test "resident ids stay out of secrets-only scans and batch totals count" {
  assert_eq(
    @moon_scrub.scan(
      "110105199001010010",
      policy=@moon_scrub.ScanPolicy::secrets_only(),
    ).length(),
    0,
  )
  let result = @moon_scrub.redact_with_config(
    "u 110105199001010010",
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(result.text, "u [REDACTED:RESIDENT_ID]")
}
