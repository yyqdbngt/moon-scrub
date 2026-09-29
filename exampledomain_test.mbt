///|
test "example-domain emails can be suppressed for test-suite logs" {
  let config = {
    ..@moon_scrub.ScanConfig::standard(),
    suppress_example_domains: true,
  }
  let findings = @moon_scrub.scan_with_config(
    "mail demo@example.com real user@corp.internal", config,
  )
  assert_eq(findings.length(), 1)
  assert_eq(
    "mail demo@example.com real user@corp.internal"[findings[0].start:findings[0].end].to_owned(),
    "user@corp.internal",
  )
}

///|
test "suppression is opt-in and default scans keep example domains" {
  assert_eq(@moon_scrub.scan("demo@example.com").length(), 1)
}
