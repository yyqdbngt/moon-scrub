///|
fn is_ascii_letter(c : Int) -> Bool {
  (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
}

///|
fn is_ascii_digit(c : Int) -> Bool {
  c >= 48 && c <= 57
}

///|
fn is_ascii_alnum(c : Int) -> Bool {
  is_ascii_letter(c) || is_ascii_digit(c)
}

///|
fn is_token_char(c : Int) -> Bool {
  is_ascii_alnum(c) || c == 45 || c == 46 || c == 95
}

///|
fn is_base64url(c : Int) -> Bool {
  is_ascii_alnum(c) || c == 45 || c == 95 || c == 61
}

///|
fn is_email_local(c : Int) -> Bool {
  is_ascii_alnum(c) ||
  c == 33 ||
  c == 35 ||
  c == 36 ||
  c == 37 ||
  c == 38 ||
  c == 39 ||
  c == 42 ||
  c == 43 ||
  c == 45 ||
  c == 46 ||
  c == 47 ||
  c == 63 ||
  c == 94 ||
  c == 95 ||
  c == 96 ||
  c == 123 ||
  c == 124 ||
  c == 125 ||
  c == 126
}

///|
/// Character-wise prefix test with no intermediate allocation; this sits on
/// the hottest scanning path.
fn starts_at(text : String, at : Int, prefix : String) -> Bool {
  if at < 0 || at + prefix.length() > text.length() {
    return false
  }
  for k = 0; k < prefix.length(); k = k + 1 {
    if text[at + k] != prefix[k] {
      return false
    }
  }
  true
}

///|
fn ascii_lower(text : String) -> String {
  let out = StringBuilder()
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i].to_int()
    out.write_char(
      Int::unsafe_to_char(if c >= 65 && c <= 90 { c + 32 } else { c }),
    )
  }
  out.to_string()
}

///|
fn trim_value_end(text : String, start : Int) -> Int {
  let mut end = start
  while end < text.length() {
    let c = text[end].to_int()
    if c == 32 ||
      c == 9 ||
      c == 10 ||
      c == 13 ||
      c == 44 ||
      c == 59 ||
      c == 34 ||
      c == 39 ||
      c == 125 ||
      c == 93 {
      break
    }
    end += 1
  }
  end
}
