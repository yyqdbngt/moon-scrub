///|
test "redact_kv collapses quoted secrets whole" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "msg=\"token ghp_1234567890abcdefghij inside\" user=7"
  let out = @moon_scrub.redact_kv(line, config)
  assert_true(out.contains("msg=\"token [REDACTED:ACCESS_TOKEN] inside\""))
  assert_false(out.contains("ghp_"))
  assert_true(out.contains("user=7"))
}

///|
test "redact_kv handles escaped quotes" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "say=\"she said \\\"demo@example.com\\\" ok\" ip=10.0.0.8"
  let out = @moon_scrub.redact_kv(line, config)
  assert_true(out.contains("[REDACTED:EMAIL]"))
  assert_true(out.contains("ip=[REDACTED:IPV4]"))
  assert_false(out.contains("demo@example.com"))
}

///|
test "redact_kv passes clean lines byte-identical" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "level=info ts=1712345678 msg=\"all quiet\" retries=3"
  assert_eq(@moon_scrub.redact_kv(line, config), line)
}

///|
test "redact_kv leaves keys and structure intact" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "password=hunter2 host=db.example.net port=5432"
  let out = @moon_scrub.redact_kv(line, config)
  assert_true(out.contains("password=[REDACTED:CREDENTIAL]"))
  assert_true(out.contains("host="))
  assert_true(out.contains("port=5432"))
  assert_false(out.contains("hunter2"))
}

///|
test "redact_kv unterminated quote still redacts to the end" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "dump=\"ghp_1234567890abcdefghij"
  let out = @moon_scrub.redact_kv(line, config)
  assert_false(out.contains("ghp_1234567890abcdefghij"))
  assert_true(out.contains("[REDACTED:ACCESS_TOKEN]"))
}

///|
test "redact_kv idempotence" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "msg=\"mail demo@example.com soon\" n=1"
  let once = @moon_scrub.redact_kv(line, config)
  let twice = @moon_scrub.redact_kv(once, config)
  assert_eq(once, twice)
}

///|
test "redact_kv honours preserve-last4 style" {
  let config = @moon_scrub.ScanConfig::standard()
  let line = "card=\"4111111111111111\" keep=yes"
  let out = @moon_scrub.redact_kv(line, config, style=@moon_scrub.PreserveLast4)
  assert_false(out.contains("4111111111111111"))
  assert_true(out.contains("1111"))
  assert_true(out.contains("keep=yes"))
}
