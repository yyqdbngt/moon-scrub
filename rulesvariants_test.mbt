///|
test "verify_clean_with_rules honors exact-value rules" {
  let rules = [
    @moon_scrub.CustomRule::{ label: "tenant", value: "internal-42", },
  ]
  assert_false(@moon_scrub.verify_clean_with_rules("tenant=internal-42", rules))
  assert_true(@moon_scrub.verify_clean_with_rules("tenant=public-1", rules))
}

///|
test "redact_json_with_rules redacts custom values inside leaves" {
  let rules = [
    @moon_scrub.CustomRule::{ label: "tenant", value: "internal-42", },
  ]
  let result = @moon_scrub.redact_json_with_rules(
    "{\"tenant\": \"internal-42\", \"ok\": \"fine\"}", rules,
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"ok\":\"fine\",\"tenant\":\"[REDACTED:CUSTOM_SECRET]\"}",
  )
}

///|
test "redact_json_with_rules fails closed on malformed json" {
  let rules = [
    @moon_scrub.CustomRule::{ label: "tenant", value: "internal-42", },
  ]
  let result = @moon_scrub.redact_json_with_rules(
    "tenant=internal-42 {bad", rules,
  )
  assert_false(result.parsed)
  assert_eq(result.text, "tenant=[REDACTED:CUSTOM_SECRET] {bad")
}
