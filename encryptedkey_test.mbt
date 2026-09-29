///|
test "encrypted pkcs8 private key blocks are detected" {
  let pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIHjME4GCSqGSIb3DQEFDTBBMC0GCSqGSIb3DQEF\n-----END ENCRYPTED PRIVATE KEY-----"
  let findings = @moon_scrub.scan(pem, policy=@moon_scrub.ScanPolicy::secrets_only())
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.PrivateKey)
}
