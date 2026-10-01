///|
test "resident id accepts thirty-day months" {
  let findings = @moon_scrub.scan_with_config(
    "id 110105199004010016",
    @moon_scrub.ScanConfig::standard(),
  )
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.ResidentId)
}

///|
test "pattern rules exercise every character class" {
  let config = {
    ..@moon_scrub.ScanConfig::secrets_only(),
    extra_patterns: [
      @moon_scrub.PatternRule::{
        prefix: "hex_",
        chars: @moon_scrub.HexAny,
        min_length: 16,
        max_length: 20,
      },
      @moon_scrub.PatternRule::{
        prefix: "rnd_",
        chars: @moon_scrub.AlnumUndash,
        min_length: 16,
        max_length: 20,
      },
      @moon_scrub.PatternRule::{
        prefix: "b64_",
        chars: @moon_scrub.Base64Url,
        min_length: 16,
        max_length: 20,
      },
    ],
  }
  let hex = @moon_scrub.scan_with_config("x hex_3F9A2C81D07B4E55", config)
  assert_eq(hex.length(), 1)
  let rnd = @moon_scrub.scan_with_config("x rnd_Ab3-XYZ_789-Qrs4", config)
  assert_eq(rnd.length(), 1)
  let b64 = @moon_scrub.scan_with_config("x b64_Ab-Cd_Ef9=Gh1=", config)
  assert_eq(b64.length(), 1)
}

///|
test "json escaping passes control characters through escaped" {
  let result = @moon_scrub.redact_json(
    "{\"msg\": \"password=hunter2\", \"note\": \"tab\\there\"}",
  )
  assert_true(result.parsed)
  assert_eq(
    result.text,
    "{\"msg\":\"password=[REDACTED:CREDENTIAL]\",\"note\":\"tab\\there\"}",
  )
}
