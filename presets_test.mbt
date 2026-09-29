///|
test "pii_only skips credentials but keeps identifier families" {
  let config = @moon_scrub.ScanConfig::pii_only()
  let input = "password=hunter2 token=ghp_1234567890abcdefghij mail demo@example.com ip 10.0.0.8"
  let findings = @moon_scrub.scan_with_config(input, config)
  assert_eq(findings.length(), 2)
  assert_eq(findings[0].kind, @moon_scrub.Email)
  assert_eq(findings[1].kind, @moon_scrub.Ipv4)
}

///|
test "pii_only still reports resident ids and mac addresses" {
  let config = @moon_scrub.ScanConfig::pii_only()
  let findings = @moon_scrub.scan_with_config(
    "id 110105199001010010 nic 02:00:5e:10:00:03", config,
  )
  assert_eq(findings.length(), 2)
  assert_eq(findings[0].kind, @moon_scrub.ResidentId)
  assert_eq(findings[1].kind, @moon_scrub.MacAddress)
}
