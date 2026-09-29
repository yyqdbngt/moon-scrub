///|
test "findings_summary counts kinds in deterministic name order" {
  let input = "mail a@example.com b@example.com ip 10.0.0.8 token=ghp_1234567890abcdefghij"
  let rows = @moon_scrub.findings_summary(input)
  assert_eq(rows.length(), 3)
  assert_eq(rows[0].kind, @moon_scrub.AccessToken)
  assert_eq(rows[0].count, 1)
  assert_eq(rows[1].kind, @moon_scrub.Email)
  assert_eq(rows[1].count, 2)
  assert_eq(rows[2].kind, @moon_scrub.Ipv4)
  assert_eq(rows[2].count, 1)
}

///|
test "findings_summary is empty for clean input" {
  assert_eq(@moon_scrub.findings_summary("plain request").length(), 0)
}
