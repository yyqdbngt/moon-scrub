///|
test "known access token prefixes are detected without storing values" {
  let input = "token=ghp_1234567890abcdefghij"
  let findings = scan(input, policy=ScanPolicy::secrets_only())
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, AccessToken)
  assert_eq(
    input[findings[0].start:findings[0].end].to_owned(),
    "ghp_1234567890abcdefghij",
  )
}

///|
test "bearer and jwt are high confidence" {
  let bearer = scan(
    "Authorization: Bearer abcdefghijklmnop",
    policy=ScanPolicy::secrets_only(),
  )
  assert_eq(bearer.length(), 1)
  assert_eq(bearer[0].kind, BearerToken)
  let jwt = scan(
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
    policy=ScanPolicy::secrets_only(),
  )
  assert_eq(jwt.length(), 1)
  assert_eq(jwt[0].kind, Jwt)
}

///|
test "email ipv4 and luhn-valid cards are detected" {
  let input = "mail demo@example.com ip 192.168.1.20 card 4111-1111-1111-1111"
  let findings = scan(input)
  assert_eq(findings.length(), 3)
  assert_eq(findings[0].kind, Email)
  assert_eq(findings[1].kind, Ipv4)
  assert_eq(findings[2].kind, PaymentCard)
}

///|
test "invalid ipv4 and invalid card are not reported" {
  assert_eq(scan("999.1.1.1 and 4111-1111-1111-1112").length(), 0)
}

///|
test "secrets-only policy leaves ordinary identifiers alone" {
  let findings = scan(
    "demo@example.com 10.0.0.1 4111111111111111",
    policy=ScanPolicy::secrets_only(),
  )
  assert_eq(findings.length(), 0)
}

///|
test "quoted and unquoted credential assignments redact only values" {
  let input = "password=hello secret: \"world value\" next=yes"
  let findings = scan(input, policy=ScanPolicy::secrets_only())
  assert_eq(findings.length(), 2)
  assert_eq(input[findings[0].start:findings[0].end].to_owned(), "hello")
  assert_eq(input[findings[1].start:findings[1].end].to_owned(), "world value")
}
