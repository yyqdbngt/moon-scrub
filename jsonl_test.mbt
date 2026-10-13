///|
test "jsonl redacts line by line with isolation" {
  let input = "{\"msg\": \"mail demo@example.com\"}\nnot json token=ghp_1234567890abcdefghij\n{\"n\": 1}"
  let result = @moon_scrub.redact_json_lines(input)
  assert_eq(result.lines.length(), 3)
  assert_eq(result.changed_indices.length(), 2)
  assert_eq(result.changed_indices[0], 0)
  assert_eq(result.changed_indices[1], 1)
  assert_true(result.lines[0].contains("[REDACTED:EMAIL]"))
  assert_true(result.lines[1].contains("[REDACTED:ACCESS_TOKEN]"))
  assert_eq(result.lines[2], "{\"n\": 1}")
  assert_eq(result.unparsed, 1)
  assert_eq(result.findings, 2)
}

///|
test "jsonl preserves line count and terminator" {
  let input = "{\"a\": 1}\n{\"b\": 2}\n"
  let result = @moon_scrub.redact_json_lines(input)
  assert_eq(result.lines.length(), 2)
  let text = result.text
  // exactly one trailing newline, byte-identical clean roundtrip
  assert_eq(text, input)
  assert_eq(result.changed_indices.length(), 0)
}

///|
test "jsonl keeps missing final newline missing" {
  let input = "{\"a\": \"x@y.org\"}\n{\"b\": 2}"
  let result = @moon_scrub.redact_json_lines(input)
  assert_false(result.text.ends_with("\n"))
  assert_eq(result.lines.length(), 2)
}

///|
test "jsonl malformed lines fall back without touching neighbours" {
  let input = "{\"ok\": \"a@b.co\"}\n{\"broken\": \n{\"ok2\": \"c@d.org\"}"
  let result = @moon_scrub.redact_json_lines(input)
  assert_eq(result.lines.length(), 3)
  assert_eq(result.unparsed, 1)
  assert_true(result.lines[0].contains("[REDACTED:EMAIL]"))
  assert_true(result.lines[2].contains("[REDACTED:EMAIL]"))
  // the broken line still had its plain-text finding redacted
  assert_false(result.lines[1].contains("a@b.co"))
}

///|
test "jsonl empty input stays empty" {
  let result = @moon_scrub.redact_json_lines("")
  assert_eq(result.lines.length(), 0)
  assert_eq(result.text, "")
}

///|
test "jsonl honours config and style" {
  let input = "{\"password\": \"hunter2\"}\n"
  let out = @moon_scrub.redact_json_lines(
    input,
    config=@moon_scrub.ScanConfig::secrets_only(),
  )
  assert_true(out.lines[0].contains("[REDACTED:CREDENTIAL]"))
  assert_eq(out.changed_indices.length(), 1)
}
