///|
test "pem certificate blocks report as public key material" {
  let config = @moon_scrub.ScanConfig::standard()
  let pem = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUX+abc123fake456def789ghi012\n-----END CERTIFICATE-----"
  let findings = @moon_scrub.scan_with_config("tls " + pem + " ok", config)
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.PublicKey)
  let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIHhMIGQAgEAMDkx\n-----END CERTIFICATE REQUEST-----"
  let csr_findings = @moon_scrub.scan_with_config(csr, config)
  assert_eq(csr_findings.length(), 1)
  assert_eq(csr_findings[0].kind, @moon_scrub.PublicKey)
}
