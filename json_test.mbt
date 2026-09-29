///|
test "json string leaves are scanned with deterministic sorted output" {
  let input = "{\"user\": {\"name\": \"Ada\", \"email\": \"ada@example.com\"}, \"hits\": [{\"ip\": \"10.0.0.7\"}, {\"ip\": \"192.168.0.2\"}], \"config\": {\"password\": \"hunter2\"}, \"port\": 5432, \"ok\": true, \"note\": null}"
  let result = @moon_scrub.redact_json(input)
  assert_true(result.parsed)
  assert_eq(result.changed_fields, 4)
  assert_eq(result.findings.length(), 4)
  assert_eq(result.findings[0].path, "/config/password")
  assert_eq(result.findings[0].finding.kind, @moon_scrub.CredentialAssignment)
  assert_eq(result.findings[1].path, "/hits/0/ip")
  assert_eq(result.findings[1].finding.kind, @moon_scrub.Ipv4)
  assert_eq(result.findings[2].path, "/hits/1/ip")
  assert_eq(result.findings[3].path, "/user/email")
  assert_eq(
    result.text,
    "{\"config\":{\"password\":\"[REDACTED:CREDENTIAL]\"},\"hits\":[{\"ip\":\"[REDACTED:IPV4]\"},{\"ip\":\"[REDACTED:IPV4]\"}],\"note\":null,\"ok\":true,\"port\":5432,\"user\":{\"email\":\"[REDACTED:EMAIL]\",\"name\":\"Ada\"}}",
  )
}

///|
test "json output is byte-identical across runs" {
  let input = "{\"b\": \"demo@example.com\", \"a\": \"demo@example.com\"}"
  let first = @moon_scrub.redact_json(input)
  let second = @moon_scrub.redact_json(input)
  assert_eq(first.text, second.text)
  assert_eq(first.findings, second.findings)
}

///|
test "numbers are canonicalized deterministically" {
  let result = @moon_scrub.redact_json(
    "{\"ratio\": 5432.50, \"big\": 1e3, \"nobody\": \"x@example.com\"}",
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"big\":1000,\"nobody\":\"[REDACTED:EMAIL]\",\"ratio\":5432.5}",
  )
}

///|
test "malformed json fails closed to plain text scanning" {
  let result = @moon_scrub.redact_json("password=hunter2 {not json")
  assert_false(result.parsed)
  assert_eq(result.changed_fields, 1)
  assert_eq(result.text, "password=[REDACTED:CREDENTIAL] {not json")
}

///|
test "json scanning honours custom configuration" {
  let secrets_only = @moon_scrub.ScanConfig::secrets_only()
  let result = @moon_scrub.redact_json(
    "{\"email\": \"demo@example.com\", \"api_key\": \"corp-secret-value\"}",
    config=secrets_only,
  )
  assert_true(result.parsed)
  // The sensitive path still fails closed; the email stays untouched.
  assert_eq(result.changed_fields, 1)
  assert_eq(
    result.text,
    "{\"api_key\":\"[REDACTED:CREDENTIAL]\",\"email\":\"demo@example.com\"}",
  )
}

///|
test "unicode content passes through unharmed" {
  let result = @moon_scrub.redact_json(
    "{\"msg\": \"中文日志 with password=lace value\"}",
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"msg\":\"中文日志 with password=[REDACTED:CREDENTIAL] value\"}",
  )
}
