///|
fn collect_chunked(
  corpus : String,
  chunk_size : Int,
  overlap : Int,
) -> Array[@moon_scrub.Finding] {
  let scanner = @moon_scrub.ChunkScanner::new(overlap~)
  let collected : Array[@moon_scrub.Finding] = []
  let mut i = 0
  while i < corpus.length() {
    let end = if i + chunk_size < corpus.length() {
      i + chunk_size
    } else {
      corpus.length()
    }
    for finding in scanner.push(corpus[i:end].to_owned()) {
      collected.push(finding)
    }
    i = end
  }
  for finding in scanner.finish() {
    collected.push(finding)
  }
  collected
}

///|
test "chunked scanning matches whole-text scanning across chunk sizes" {
  let corpus = "user=demo@example.com auth: Bearer abcdefghijklmnop ip=10.0.0.8\npassword=hunter2 token=ghp_1234567890abcdefghij plain log line\ncard 4111-1111-1111-1111 jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature url postgres://alice:s3cret@db.example/app\n"
  let expected = @moon_scrub.scan(corpus)
  for size in [1, 3, 17, 64, 257, 1024, 4096] {
    let actual = collect_chunked(corpus, size, 8192)
    assert_eq(actual.length(), expected.length())
    for i = 0; i < expected.length(); i = i + 1 {
      assert_eq(actual[i], expected[i])
    }
  }
}

///|
test "secrets split across chunk boundaries are detected" {
  let scanner = @moon_scrub.ChunkScanner::new(overlap=64)
  assert_eq(scanner.push("log line token=ghp_").length(), 0)
  assert_eq(scanner.push("1234567890abcdefghij tail").length(), 0)
  let findings = scanner.finish()
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.AccessToken)
  assert_eq(findings[0].start, 15)
  assert_eq(findings[0].end, 39)
}

///|
test "findings settle early once enough tail data exists" {
  let scanner = @moon_scrub.ChunkScanner::new(overlap=64)
  let padding = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  assert_eq(padding.length(), 53)
  let early = scanner.push("pad ip=10.0.0.8 password=hunter2 " + padding)
  // The IPv4 ends more than 64 code units before the stream end, so it is
  // already settled; the credential is still within the tail window.
  assert_eq(early.length(), 1)
  assert_eq(early[0].kind, @moon_scrub.Ipv4)
  assert_eq(early[0].start, 7)
  assert_eq(early[0].end, 15)
  let rest = scanner.finish()
  assert_eq(rest.length(), 1)
  assert_eq(rest[0].kind, @moon_scrub.CredentialAssignment)
  assert_eq(rest[0].start, 25)
  assert_eq(rest[0].end, 32)
}

///|
test "push after finish is ignored" {
  let scanner = @moon_scrub.ChunkScanner::new(overlap=64)
  ignore(scanner.push("token=ghp_1234567890abcdefghij"))
  assert_eq(scanner.finish().length(), 1)
  assert_eq(scanner.push("token=ghp_1234567890abcdefghij").length(), 0)
  assert_eq(scanner.finish().length(), 0)
}

///|
test "chunked scanning accepts custom configurations" {
  let config = @moon_scrub.ScanConfig::secrets_only()
  let scanner = @moon_scrub.ChunkScanner::new(config~, overlap=64)
  ignore(scanner.push("mail demo@example.com token=ghp_1234567890abcdefghij"))
  let findings = scanner.finish()
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].kind, @moon_scrub.AccessToken)
}

///|
test "push_lines matches per-line pushes" {
  let lines = [
    "login demo@example.com", "auth: Bearer abcdefghijklmnop", "plain line",
  ]
  let batched = @moon_scrub.ChunkScanner::new(overlap=16)
  let from_batch = batched.push_lines(lines)
  let tail = batched.finish()
  let per_line = @moon_scrub.ChunkScanner::new(overlap=16)
  let collected : Array[@moon_scrub.Finding] = []
  for line in lines {
    let chunk = line + "\n"
    for finding in per_line.push(chunk) {
      collected.push(finding)
    }
  }
  for finding in per_line.finish() {
    collected.push(finding)
  }
  assert_eq(from_batch.length() + tail.length(), collected.length())
  let mut offset = 0
  for finding in from_batch {
    assert_eq(finding, collected[offset])
    offset += 1
  }
  for finding in tail {
    assert_eq(finding, collected[offset])
    offset += 1
  }
}

///|
/// Deterministic Lehmer generator for property-style corpora.
fn prop_lcg(state : Int64) -> Int64 {
  state * 48271L % 2147483647L
}

///|
/// Build a mixed corpus from a seed: alternating filler words, planted
/// emails, credentials, tokens, cards, and version-shaped noise that must
/// stay suppressed even under chunking.
fn prop_corpus(seed : Int64, lines : Int) -> String {
  let letters = "abcdefghijklmnopqrstuvwxyz"
  let buf = StringBuilder()
  let mut state = seed
  for i = 0; i < lines; i = i + 1 {
    state = prop_lcg(state)
    let word = StringBuilder()
    for _ in 0..<10 {
      state = prop_lcg(state)
      word.write_char(
        Int::unsafe_to_char(letters[(state % 26L).to_int()].to_int()),
      )
    }
    let w = word.to_string()
    buf.write_string(
      match i % 6 {
        0 => "mail " + w + "@example.com\n"
        1 => "password=" + w + "value\n"
        2 => "token=ghp_" + w + w + "1234\n"
        3 => "card 4111 1111 1111 1111 ver v1.2.3.4\n"
        4 => "ip 10.0." + (i % 200).to_string() + ".7 note\n"
        _ => "plain " + w + " request\n"
      },
    )
  }
  buf.to_string()
}

///|
test "chunked scanning equals whole scanning on generated corpora" {
  for seed in [7L, 99L, 12345L] {
    let corpus = prop_corpus(seed, 60)
    let expected = @moon_scrub.scan(corpus)
    assert_true(expected.length() > 10)
    for size in [1, 5, 23, 97, 512, 4096] {
      let scanner = @moon_scrub.ChunkScanner::new(overlap=256)
      let actual : Array[@moon_scrub.Finding] = []
      let mut i = 0
      while i < corpus.length() {
        let end = if i + size < corpus.length() {
          i + size
        } else {
          corpus.length()
        }
        for finding in scanner.push(corpus[i:end].to_owned()) {
          actual.push(finding)
        }
        i = end
      }
      for finding in scanner.finish() {
        actual.push(finding)
      }
      assert_eq(actual.length(), expected.length())
      for k = 0; k < expected.length(); k = k + 1 {
        assert_eq(actual[k], expected[k])
      }
    }
  }
}
