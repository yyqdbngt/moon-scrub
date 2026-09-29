///|
test "confidence names round trip through explain" {
  assert_eq(@moon_scrub.High.to_string(), "HIGH")
  assert_eq(@moon_scrub.Medium.to_string(), "MEDIUM")
  let lines = @moon_scrub.explain("ip 10.0.0.8")
  assert_eq(lines[0], "IPV4 3-11 MEDIUM")
}
