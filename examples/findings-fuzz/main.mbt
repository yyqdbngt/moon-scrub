///|
/// Fuzz differential partner of tools/differential.py --fuzz: reads two
/// integers (seed and line count) from the moon run argument tail and
/// prints one findings line per generated input, using the identical
/// Lehmer generator and template table.
fn lcg2(state : Int64) -> Int64 {
  state * 48271L % 2147483647L
}

///|
fn word2(state : Int64, length : Int) -> (String, Int64) {
  let letters = "abcdefghijklmnopqrstuvwxyz"
  let buf = StringBuilder()
  let mut s = state
  for _ in 0..<length {
    s = lcg2(s)
    buf.write_char(Int::unsafe_to_char(letters[(s % 26L).to_int()].to_int()))
  }
  (buf.to_string(), s)
}

///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    println("usage: findings-fuzz <seed> <lines>")
    return
  }
  let seed = try @string.parse_int(args[args.length() - 2], base=10) catch {
    _ => -1
  } noraise {
    v => v
  }
  let count = try @string.parse_int(args[args.length() - 1], base=10) catch {
    _ => -1
  } noraise {
    v => v
  }
  if seed < 0 || count < 0 {
    println("usage: findings-fuzz <seed> <lines>")
    return
  }
  let seed_val = seed
  let count_val = count
  let config = @scrub.ScanConfig::standard()
  let mut state = seed_val.to_int64()
  for i = 0; i < count_val; i = i + 1 {
    state = lcg2(state)
    if state % 4L == 0L {
      let (w, next) = word2(state, 10)
      state = next
      println("-")
      ignore(w)
      continue
    }
    let slot = state % 7L
    let mut line = ""
    if slot == 0L {
      let (w, next) = word2(state, 7)
      state = next
      line = "ghp_" + w + "abcdefghij"
    } else if slot == 1L {
      let (w, next) = word2(state, 7)
      state = next
      line = "password=" + w
    } else if slot == 2L {
      let (w, next) = word2(state, 7)
      state = next
      line = "mail " + w + "@example.com"
    } else if slot == 3L {
      let (a, s1) = word2(state, 7)
      let (b, s2) = word2(s1, 7)
      state = s2
      line = "ip 10.0." + a + "." + b
    } else if slot == 4L {
      let (w, next) = word2(state, 7)
      state = next
      line = "token=xoxb-" + w + "-1234567890"
    } else if slot == 5L {
      let (a, s1) = word2(state, 7)
      let (b, s2) = word2(s1, 7)
      state = s2
      line = "bearer " + a + b
    } else {
      let (w, next) = word2(state, 7)
      state = next
      line = "id 1101051990010100" + w
    }
    let findings = @scrub.scan_with_config(line, config)
    if findings.length() == 0 {
      println("-")
    } else {
      let mut parts = ""
      for f in findings {
        parts += f.kind.to_string() +
          " " +
          f.start.to_string() +
          " " +
          f.end.to_string() +
          " " +
          f.confidence.to_string() +
          ";"
      }
      println(parts)
    }
  }
}
