///|
test "basic auth header values are credentials" {
  let config = @moon_scrub.ScanConfig::standard()
  let found = @moon_scrub.scan_with_config(
    "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=", config,
  )
  assert_eq(found.length(), 1)
  assert_eq(found[0].kind, @moon_scrub.CredentialAssignment)
  assert_eq(found[0].confidence, @moon_scrub.High)
}

///|
test "short or already-redacted basic values stay quiet" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config("Authorization: Basic c2hvcnQ=", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config(
      "Authorization: Basic [REDACTED:CREDENTIAL] done", config,
    ).length(),
    0,
  )
}
