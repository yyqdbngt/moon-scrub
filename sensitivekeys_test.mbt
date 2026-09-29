///|
test "extended key names are treated as credential assignments" {
  let config = @moon_scrub.ScanConfig::secrets_only()
  let samples = [
    "account_key = long-value-here", "SharedAccessKey=keh1u2fh93nc92j", "passphrase: my-door-passphrase",
    "refresh_token=abc123def456ghi789", "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  ]
  for sample in samples {
    let findings = @moon_scrub.scan_with_config(sample, config)
    assert_eq(findings.length(), 1)
    assert_eq(findings[0].kind, @moon_scrub.CredentialAssignment)
  }
}

///|
test "unrelated similar keys stay quiet" {
  let config = @moon_scrub.ScanConfig::secrets_only()
  assert_eq(@moon_scrub.scan_with_config("keyboard=qwerty", config).length(), 0)
  assert_eq(
    @moon_scrub.scan_with_config("token_bucket=10/s", config).length(),
    0,
  )
}
