///|
test "ssh public key lines are flagged as public key material" {
  let config = @moon_scrub.ScanConfig::standard()
  let body = "AAAAC3NzaC1lZDI1NTE5AAAAIB8Qm4a1G5fz0OqYzKxBf5xDgrMV9NqBZQ4XwP" +
    "x9kJkLmNoPqRsTuVwXyZaBcD4E5F6G7H8"
  let input = "deploy ssh-ed25519 " + body + " ops@host"
  let findings = @moon_scrub.scan_with_config(input, config)
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.PublicKey)
  assert_eq(
    input[findings[0].start:findings[0].end].to_owned(),
    "ssh-ed25519 " + body,
  )
}

///|
test "short or bare ssh key words are not public keys" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config("stub ssh-rsa AAAAB3Nza short", config).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config("docs ssh-ed25519 algorithm", config).length(),
    0,
  )
}
