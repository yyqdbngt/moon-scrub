///|
test "slack and discord webhook urls are high-confidence findings" {
  let config = @moon_scrub.ScanConfig::standard()
  let slack = @moon_scrub.scan_with_config(
    "post https://hooks" +
    ".slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" +
    " done",
    config,
  )
  assert_eq(slack.length(), 1)
  assert_eq(slack[0].kind, @moon_scrub.WebhookUrl)
  assert_eq(slack[0].confidence, @moon_scrub.High)
  let discord = @moon_scrub.scan_with_config(
    "hit https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstabcdefghijklmnopqrstabcdefghijklmnopqrst tail",
    config,
  )
  assert_eq(discord.length(), 1)
}

///|
test "webhook urls with wrong segment shapes are ignored" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(
    @moon_scrub.scan_with_config(
      "x https://hooks" + ".slack.com/services/T00/B00/short",
      config,
    ).length(),
    0,
  )
  assert_eq(
    @moon_scrub.scan_with_config(
      "x https://discord.com/api/webhooks/123/token", config,
    ).length(),
    0,
  )
}
