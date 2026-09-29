///|
test "ethereum and bech32 wallet shapes are medium findings" {
  let config = @moon_scrub.ScanConfig::standard()
  let eth = @moon_scrub.scan_with_config(
    "pay 0x71C7656EC7ab88b098defB751B7401B5f6d8976F now",
    config,
  )
  assert_eq(eth.length(), 1)
  assert_eq(eth[0].kind, @moon_scrub.WalletAddress)
  let bech = @moon_scrub.scan_with_config(
    "to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 ok",
    config,
  )
  assert_eq(bech.length(), 1)
}

///|
test "plain hex and short bech32 prefixes are not wallets" {
  let config = @moon_scrub.ScanConfig::standard()
  assert_eq(@moon_scrub.scan_with_config("flag 0xdeadbeef set", config).length(), 0)
  assert_eq(@moon_scrub.scan_with_config("ref bc1q short", config).length(), 0)
  // 0x followed by 39 hex characters is just a number literal shape.
  assert_eq(
    @moon_scrub.scan_with_config("n 0x71C7656EC7ab88b098defB751B7401B5f6d8976", config).length(),
    0,
  )
}
