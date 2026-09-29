///|
test "kept literals are spared while neighbours redact" {
  let result = @moon_scrub.redact_except("lb 10.0.0.1 db 10.0.0.2", ["10.0.0.1"])
  assert_eq(result.text, "lb 10.0.0.1 db [REDACTED:IPV4]")
  assert_eq(result.findings.length(), 1)
}

///|
test "overlapping findings inside a kept literal are all dropped" {
  let input = "secret=hunter2 token=corp-abcdefgh1234"
  let result = @moon_scrub.redact_except(input, ["corp-abcdefgh1234"])
  assert_eq(result.findings.length(), 1)
  assert_eq(result.text, "secret=[REDACTED:CREDENTIAL] token=corp-abcdefgh1234")
}

///|
test "short keep values cannot neuter detectors" {
  let result = @moon_scrub.redact_except("ip 10.0.0.1", ["1.0."])
  assert_eq(result.text, "ip [REDACTED:IPV4]")
}
