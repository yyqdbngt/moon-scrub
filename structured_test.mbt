///|
test "sensitive structured paths fail closed even for opaque values" {
  let result = redact_fields([
    StructuredField::{ path: "user.name", value: "Ada", },
    StructuredField::{
      path: "config.password",
      value: "correct horse battery staple",
    },
    StructuredField::{ path: "/request/client", value: "10.0.0.7", },
  ])
  assert_eq(result.fields.length(), 3)
  assert_eq(result.changed_fields, 2)
  assert_eq(result.findings, 2)
  assert_eq(result.fields[0].value, "Ada")
  assert_eq(result.fields[1].value, "[REDACTED:CREDENTIAL]")
  assert_true(result.fields[1].sensitive_path)
  assert_eq(result.fields[2].value, "[REDACTED:IPV4]")
}

///|
test "empty sensitive fields stay empty" {
  let result = redact_fields([StructuredField::{ path: "secret", value: "", }])
  assert_eq(result.changed_fields, 0)
  assert_eq(result.fields[0].value, "")
}

///|
test "custom exact rules redact values without copying labels into output" {
  let rules = [CustomRule::{ label: "tenant-code", value: "internal-42", }]
  let result = redact_with_rules("tenant=internal-42 status=ok", rules)
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].kind, CustomSecret)
  assert_eq(result.text, "tenant=[REDACTED:CUSTOM_SECRET] status=ok")
  assert_false(result.text.contains("tenant-code"))
}

///|
test "short custom values are ignored to reduce broad false positives" {
  let result = redact_with_rules("id=abc", [
    CustomRule::{ label: "id", value: "abc", },
  ])
  assert_false(result.changed)
}

///|
test "private key blocks and URL passwords are removed" {
  let private_key = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
  let key_result = redact(private_key)
  assert_eq(key_result.findings.length(), 1)
  assert_eq(key_result.findings[0].kind, PrivateKey)
  assert_eq(key_result.text, "[REDACTED:PRIVATE_KEY]")
  let url = redact("postgres://alice:s3cret@db.example/app")
  assert_eq(url.text, "postgres://[REDACTED:URL_CREDENTIAL]@db.example/app")
}
