///|
/// Shannon entropy over a candidate run, in bits per character.
fn shannon_entropy(text : String, start : Int, end : Int) -> Double {
  let buckets : Array[Int] = []
  for _ in 0..<128 {
    buckets.push(0)
  }
  let mut total = 0
  for k = start; k < end; k = k + 1 {
    let c = text[k].to_int()
    if c < 128 {
      buckets[c] += 1
      total += 1
    }
  }
  if total == 0 {
    return 0.0
  }
  let mut bits = 0.0
  for count in buckets {
    if count > 0 {
      let p = count.to_double() / total.to_double()
      bits -= p * @math.log2(p)
    }
  }
  bits
}

///|
fn is_entropy_char(c : Int) -> Bool {
  is_ascii_alnum(c) || c == 43 || c == 47 || c == 61 || c == 45 || c == 95
}

///|
/// High-entropy secret detection, opt-in: runs of at least 40
/// credential-alphabet characters whose Shannon entropy reaches 4.75
/// bits per character. Realistic English (about 4.5) and base64-encoded
/// prose (about 4.7) stay below the bar; generated keys and secrets sit
/// above it. Reported at medium confidence — entropy is evidence, not
/// proof.
fn scan_high_entropy(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_entropy_char(text[i].to_int()) {
      let start = i
      while i < text.length() && is_entropy_char(text[i].to_int()) {
        i += 1
      }
      if i - start >= 40 && shannon_entropy(text, start, i) >= 4.75 {
        push_finding(out, HighEntropySecret, start, i, Medium)
      }
    } else {
      i += 1
    }
  }
}
