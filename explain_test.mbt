///|
test "explain reports offsets and confidence without values" {
  let lines = @moon_scrub.explain("mail demo@example.com ip 10.0.0.8")
  assert_eq(lines.length(), 2)
  assert_eq(lines[0], "EMAIL 5-21 HIGH")
  assert_eq(lines[1], "IPV4 25-33 MEDIUM")
}

///|
test "explain of clean input is empty" {
  assert_eq(@moon_scrub.explain("plain request").length(), 0)
}
