///|
test "explain_json emits a machine-readable value-free report" {
  let report = @moon_scrub.explain_json("mail demo@example.com ip 10.0.0.8")
  assert_eq(
    report, "[{\"confidence\":\"HIGH\",\"end\":21,\"kind\":\"EMAIL\",\"start\":5},{\"confidence\":\"MEDIUM\",\"end\":33,\"kind\":\"IPV4\",\"start\":25}]",
  )
}

///|
test "explain_json of clean input is an empty array" {
  assert_eq(@moon_scrub.explain_json("plain"), "[]")
}
