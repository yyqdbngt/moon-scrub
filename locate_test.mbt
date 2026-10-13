///|
test "locate maps single-line offsets" {
  let text = "mail demo@example.com done"
  let findings = @moon_scrub.scan_with_config(
    text,
    @moon_scrub.ScanConfig::standard(),
  )
  let located = @moon_scrub.locate_findings(text, findings)
  assert_eq(located.length(), 1)
  assert_eq(located[0].line, 1)
  assert_eq(located[0].column, 6)
  assert_eq(located[0].finding.kind, @moon_scrub.Email)
}

///|
test "locate walks multiple lines" {
  let text = "first clean\nsecond demo@example.com here\nthird 10.0.0.8"
  let findings = @moon_scrub.scan_with_config(
    text,
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(findings.length(), 2)
  let located = @moon_scrub.locate_findings(text, findings)
  assert_eq(located[0].line, 2)
  assert_eq(located[0].column, 8)
  assert_eq(located[1].line, 3)
  assert_eq(located[1].column, 7)
}

///|
test "locate handles unsorted input and stays stable" {
  let text = "ip 10.0.0.8\nmail demo@example.com"
  let findings = @moon_scrub.scan_with_config(
    text,
    @moon_scrub.ScanConfig::standard(),
  )
  let reversed : Array[@moon_scrub.Finding] = []
  for i = findings.length() - 1; i >= 0; i = i - 1 {
    reversed.push(findings[i])
  }
  let located = @moon_scrub.locate_findings(text, reversed)
  assert_eq(located.length(), 2)
  assert_eq(located[0].line, 1)
  assert_eq(located[1].line, 2)
}

///|
test "locate reports the start line for spanning findings" {
  let text = "begin\n-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----\nend"
  let findings = @moon_scrub.scan_with_config(
    text,
    @moon_scrub.ScanConfig::standard(),
  )
  assert_true(findings.length() >= 1)
  let located = @moon_scrub.locate_findings(text, findings)
  assert_eq(located[0].line, 2)
  assert_eq(located[0].column, 1)
}

///|
test "format location renders the annotation form" {
  let text = "user=demo@example.com"
  let findings = @moon_scrub.scan_with_config(
    text,
    @moon_scrub.ScanConfig::standard(),
  )
  let located = @moon_scrub.locate_findings(text, findings)
  assert_eq(
    @moon_scrub.format_location(located[0]),
    "line 1, col 6: EMAIL (HIGH)",
  )
}
