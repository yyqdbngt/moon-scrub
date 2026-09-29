///|
test "full and compressed ipv6 literals validate" {
  let config = @moon_scrub.ScanConfig::standard()
  let full = @moon_scrub.scan_with_config(
    "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up", config,
  )
  assert_eq(full.length(), 1)
  assert_eq(full[0].kind, @moon_scrub.Ipv6)
  let compressed = @moon_scrub.scan_with_config(
    "link fe80::1ff:fe23:4567:890a", config,
  )
  assert_eq(compressed.length(), 1)
  assert_eq(compressed[0].confidence, @moon_scrub.Medium)
  let loopback = @moon_scrub.scan_with_config("host ::1", config)
  assert_eq(loopback.length(), 1)
}

///|
test "colon runs that are not addresses are rejected" {
  let config = @moon_scrub.ScanConfig::standard()
  // Timestamps, seven-group runs, double compression, five-digit groups.
  assert_eq(@moon_scrub.scan_with_config("at 12:34:56", config).length(), 0)
  assert_eq(@moon_scrub.scan_with_config("x 1:2:3:4:5:6:7", config).length(), 0)
  assert_eq(@moon_scrub.scan_with_config("x 1::2::3", config).length(), 0)
  assert_eq(@moon_scrub.scan_with_config("x 12345::6", config).length(), 0)
  // MAC addresses are two-char groups and never parse as IPv6.
  assert_eq(
    @moon_scrub.scan_with_config("nic 02:00:5e:10:00:03", config).length(),
    1,
  )
}
