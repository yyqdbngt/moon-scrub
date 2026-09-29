///|
/// Deterministic Lehmer generator; Int64 keeps the multiplication from
/// overflowing 32-bit workspaces.
fn lcg_next(state : Int64) -> Int64 {
  state * 48271L % 2147483647L
}

///|
fn make_word(state : Int64, length : Int) -> (String, Int64) {
  let letters = "abcdefghijklmnopqrstuvwxyz"
  let buf = StringBuilder()
  let mut s = state
  for _ in 0..<length {
    s = lcg_next(s)
    buf.write_char(Int::unsafe_to_char(letters[(s % 26L).to_int()].to_int()))
  }
  (buf.to_string(), s)
}

///|
/// Synthetic log corpus: mostly plain lines, every tenth line carries one
/// planted finding cycling through the detector families. Fully
/// deterministic for a given line count.
fn make_corpus(lines : Int) -> (Array[String], Int) {
  let mut state = 20260929L
  let corpus : Array[String] = []
  let mut bytes = 0
  for i = 0; i < lines; i = i + 1 {
    let line = if i % 10 == 0 {
      let (word, next) = make_word(state, 6)
      state = next
      match i % 50 {
        0 => "login user=" + word + "@example.com ok"
        10 => "password=" + word + "value"
        20 => "client " + word + " 10.0.0." + (i % 200 + 1).to_string()
        30 => "authorization: Bearer " + word + word + "tail"
        _ => "token=ghp_" + word + word + "12345678"
      }
    } else {
      let (w1, s1) = make_word(state, 7)
      let (w2, s2) = make_word(s1, 5)
      state = s2
      "request " + w1 + " handler=" + w2 + " status=200"
    }
    bytes += line.length() + 1
    corpus.push(line)
  }
  (corpus, bytes)
}

///|
/// Mill a fill corpus for the linearity gate: every seventh line plants a
/// credential, the rest is plain padding.
fn make_fill_corpus(lines : Int) -> Array[String] {
  let corpus : Array[String] = []
  for i = 0; i < lines; i = i + 1 {
    let (word, _) = make_word(101L + i.to_int64(), 40)
    if i % 7 == 0 {
      corpus.push("password=" + word + " tail")
    } else {
      corpus.push("plain " + word + " done")
    }
  }
  corpus
}

///|
fn time_pass_micros(corpus : Array[String]) -> Double {
  let start = @mbench.monotonic_clock_start()
  let result = @scrub.redact_batch(corpus)
  let micros = @mbench.monotonic_clock_end(start)
  if result.lines.length() != corpus.length() {
    abort("corpus line count changed during redaction")
  }
  micros
}

///|
fn main {
  let lines = 20000
  let (corpus, bytes) = make_corpus(lines)
  let iterations = 20
  // Warm up caches and code paths before timing.
  ignore(@scrub.redact_batch(corpus))
  let start = @mbench.monotonic_clock_start()
  let mut total_findings = 0
  for _ in 0..<iterations {
    let result = @scrub.redact_batch(corpus)
    total_findings += result.summary.findings
  }
  // The clock reports microseconds.
  let micros = @mbench.monotonic_clock_end(start)
  let total_bytes = bytes * iterations
  println("lines=" + lines.to_string())
  println("corpus-bytes=" + bytes.to_string())
  println("iterations=" + iterations.to_string())
  println("total-bytes=" + total_bytes.to_string())
  println("micros=" + micros.to_string())
  if micros > 0.0 {
    let seconds = micros / 1000000.0
    let mbps = total_bytes.to_double() / (1024.0 * 1024.0) / seconds
    let us_per_line = micros / (lines * iterations).to_double()
    println("throughput-mbps=" + mbps.to_string())
    println("us-per-line=" + us_per_line.to_string())
  } else {
    println("throughput-mbps=n/a (clock unavailable)")
  }
  println("findings-per-pass=" + (total_findings / iterations).to_string())
  // Linearity gate: an 8x input must not cost more than 8x the time (with a
  // generous constant). Quadratic rescanning, the classic streaming-scanner
  // regression, fails this immediately. Clock-less targets skip the check.
  let small = time_pass_micros(make_fill_corpus(20000))
  let large = time_pass_micros(make_fill_corpus(160000))
  println("linear-small-micros=" + small.to_string())
  println("linear-large-micros=" + large.to_string())
  if small > 0.0 && large > small * 64.0 {
    abort("redaction cost grew superlinearly with input size")
  }
}
