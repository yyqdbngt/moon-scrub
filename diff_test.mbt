///|
fn diff_findings_of(text : String) -> Array[@moon_scrub.Finding] {
  @moon_scrub.scan_with_config(text, @moon_scrub.ScanConfig::standard())
}

///|
test "diff finds no movement between identical scans" {
  let text = "mail demo@example.com ip 10.0.0.8"
  let diff = @moon_scrub.diff_findings(diff_findings_of(text), diff_findings_of(text))
  assert_eq(diff.added.length(), 0)
  assert_eq(diff.removed.length(), 0)
  assert_eq(diff.unchanged, 2)
}

///|
test "diff flags a newly introduced secret" {
  let baseline = diff_findings_of("mail demo@example.com from home")
  let changed = diff_findings_of(
    "mail demo@example.com token=ghp_1234567890abcdefghij from home",
  )
  let diff = @moon_scrub.diff_findings(baseline, changed)
  assert_eq(diff.added.length(), 1)
  assert_eq(diff.added[0].kind, @moon_scrub.AccessToken)
  assert_eq(diff.removed.length(), 0)
  let report = @moon_scrub.format_diff_report(diff)
  assert_eq(report.length(), 1)
  assert_true(report[0].starts_with("+ ACCESS_TOKEN"))
}

///|
test "diff flags a cleaned-up secret as removed" {
  let baseline = diff_findings_of(
    "mail demo@example.com token=ghp_1234567890abcdefghij",
  )
  let changed = diff_findings_of("mail demo@example.com")
  let diff = @moon_scrub.diff_findings(baseline, changed)
  assert_eq(diff.removed.length(), 1)
  assert_eq(diff.removed[0].kind, @moon_scrub.AccessToken)
  assert_eq(diff.added.length(), 0)
  let report = @moon_scrub.format_diff_report(diff)
  assert_true(report[0].starts_with("- ACCESS_TOKEN"))
}

///|
test "diff is position sensitive by design" {
  let baseline = diff_findings_of("ip 10.0.0.8 end")
  let changed = diff_findings_of("prefix padding ip 10.0.0.8 end")
  let diff = @moon_scrub.diff_findings(baseline, changed)
  // Same address, new offsets: one removal, one addition, nothing held
  // in common — a gate must see movement, not hide it.
  assert_eq(diff.added.length(), 1)
  assert_eq(diff.removed.length(), 1)
  assert_eq(diff.unchanged, 0)
}

///|
test "diff is order independent" {
  let text = "mail a@b.co ip 10.0.0.8 mac 02:00:5e:10:00:03"
  let forward = diff_findings_of(text)
  let reversed : Array[@moon_scrub.Finding] = []
  for i = forward.length() - 1; i >= 0; i = i - 1 {
    reversed.push(forward[i])
  }
  let diff = @moon_scrub.diff_findings(forward, reversed)
  assert_eq(diff.added.length(), 0)
  assert_eq(diff.removed.length(), 0)
  assert_eq(diff.unchanged, 3)
}

///|
test "diff gate recipe catches a leak before merge" {
  // The documented CI recipe: fail the build when anything was added.
  let baseline = diff_findings_of("clean log line")
  let candidate = diff_findings_of(
    "clean log line with sk-live-1234567890abcdef inside",
  )
  let diff = @moon_scrub.diff_findings(baseline, candidate)
  let gate_open = diff.added.length() == 0
  assert_false(gate_open)
}
