///|
fn push_finding(
  out : Array[Finding],
  kind : SensitiveKind,
  start : Int,
  end : Int,
  confidence : Confidence,
) -> Unit {
  if start >= 0 && end > start {
    out.push({ kind, start, end, confidence, })
  }
}

///|
fn scan_prefixed_tokens(text : String, out : Array[Finding]) -> Unit {
  let prefixes = [
    "ghp_", "gho_", "ghs_", "github_pat_", "sk-", "xoxb-", "xoxp-", "AKIA",
  ]
  for i = 0; i < text.length(); i = i + 1 {
    for prefix in prefixes {
      if starts_at(text, i, prefix) {
        let mut end = i + prefix.length()
        while end < text.length() && is_token_char(text[end].to_int()) {
          end += 1
        }
        let minimum = if prefix == "AKIA" { 20 } else { prefix.length() + 8 }
        if end - i >= minimum {
          push_finding(out, AccessToken, i, end, High)
        }
      }
    }
  }
}

///|
fn scan_bearer(text : String, out : Array[Finding]) -> Unit {
  let lower = ascii_lower(text)
  for i = 0; i + 7 < text.length(); i = i + 1 {
    if starts_at(lower, i, "bearer ") {
      let start = i + 7
      let end = trim_value_end(text, start)
      if end - start >= 8 {
        push_finding(out, BearerToken, start, end, High)
      }
    }
  }
}

///|
fn scan_jwt(text : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 12 < text.length(); i = i + 1 {
    if starts_at(text, i, "eyJ") {
      let mut end = i
      let mut dots = 0
      while end < text.length() {
        let c = text[end].to_int()
        if c == 46 {
          dots += 1
          end += 1
        } else if is_base64url(c) {
          end += 1
        } else {
          break
        }
      }
      if dots == 2 && end - i >= 16 {
        push_finding(out, Jwt, i, end, High)
      }
    }
  }
}

///|
fn scan_private_keys(text : String, out : Array[Finding]) -> Unit {
  let begins = [
    "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
  ]
  for i = 0; i < text.length(); i = i + 1 {
    for begin in begins {
      if starts_at(text, i, begin) {
        let mut end = i + begin.length()
        let marker = "-----END"
        while end < text.length() && !starts_at(text, end, marker) {
          end += 1
        }
        if end < text.length() {
          while end < text.length() &&
                text[end].to_int() != 10 &&
                text[end].to_int() != 13 {
            end += 1
          }
        } else {
          end = text.length()
        }
        push_finding(out, PrivateKey, i, end, High)
      }
    }
  }
}

///|
fn scan_url_credentials(text : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 3 < text.length(); i = i + 1 {
    if starts_at(text, i, "://") {
      let authority_start = i + 3
      let mut at = authority_start
      let mut colon = -1
      while at < text.length() &&
            text[at].to_int() != 47 &&
            text[at].to_int() != 32 &&
            text[at].to_int() != 9 {
        if text[at].to_int() == 58 && colon < 0 {
          colon = at
        }
        if text[at].to_int() == 64 {
          break
        }
        at += 1
      }
      if at < text.length() &&
        text[at].to_int() == 64 &&
        colon > authority_start &&
        colon + 1 < at {
        push_finding(out, UrlCredential, authority_start, at, High)
      }
    }
  }
}

///|
fn sensitive_key(key : String) -> Bool {
  let k = ascii_lower(key)
  k == "password" ||
  k == "passwd" ||
  k == "pwd" ||
  k == "secret" ||
  k == "token" ||
  k == "api_key" ||
  k == "apikey" ||
  k == "private_key" ||
  k == "authorization" ||
  k == "client_secret"
}

///|
fn scan_assignments(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_ascii_letter(text[i].to_int()) || text[i].to_int() == 95 {
      let key_start = i
      while i < text.length() &&
            (
              is_ascii_alnum(text[i].to_int()) ||
              text[i].to_int() == 95 ||
              text[i].to_int() == 45
            ) {
        i += 1
      }
      let key = text[key_start:i].to_owned()
      let mut sep = i
      while sep < text.length() &&
            (text[sep].to_int() == 32 || text[sep].to_int() == 9) {
        sep += 1
      }
      if sensitive_key(key) &&
        sep < text.length() &&
        (text[sep].to_int() == 61 || text[sep].to_int() == 58) {
        let mut start = sep + 1
        while start < text.length() &&
              (text[start].to_int() == 32 || text[start].to_int() == 9) {
          start += 1
        }
        if ascii_lower(key) == "authorization" &&
          starts_at(ascii_lower(text), start, "bearer ") {
          i = start + 7
        } else if starts_at(text, start, "[REDACTED") {
          i = start + 9
        } else if start < text.length() &&
          (text[start].to_int() == 34 || text[start].to_int() == 39) {
          let quote = text[start].to_int()
          start += 1
          let mut end = start
          while end < text.length() && text[end].to_int() != quote {
            end += 1
          }
          push_finding(out, CredentialAssignment, start, end, High)
        } else {
          push_finding(
            out,
            CredentialAssignment,
            start,
            trim_value_end(text, start),
            High,
          )
        }
      }
    } else {
      i += 1
    }
  }
}

///|
fn scan_emails(text : String, out : Array[Finding]) -> Unit {
  for at = 1; at + 3 < text.length(); at = at + 1 {
    if text[at].to_int() == 64 {
      let mut start = at
      while start > 0 && is_email_local(text[start - 1].to_int()) {
        start -= 1
      }
      let mut end = at + 1
      while end < text.length() &&
            (
              is_ascii_alnum(text[end].to_int()) ||
              text[end].to_int() == 45 ||
              text[end].to_int() == 46
            ) {
        end += 1
      }
      let domain = text[at + 1:end].to_owned()
      if start < at &&
        domain.length() >= 3 &&
        domain.contains(".") &&
        !domain.has_prefix(".") &&
        !domain.has_suffix(".") {
        push_finding(out, Email, start, end, High)
      }
    }
  }
}

///|
fn ipv4_octet(text : String, start : Int, end : Int) -> Bool {
  if end <= start || end - start > 3 {
    return false
  }
  let mut value = 0
  for i = start; i < end; i = i + 1 {
    if !is_ascii_digit(text[i].to_int()) {
      return false
    }
    value = value * 10 + text[i].to_int() - 48
  }
  value <= 255
}

///|
fn scan_ipv4(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_ascii_digit(text[i].to_int()) &&
      (i == 0 || !is_ascii_digit(text[i - 1].to_int())) {
      let start = i
      let mut part_start = i
      let mut parts = 0
      while i < text.length() &&
            (is_ascii_digit(text[i].to_int()) || text[i].to_int() == 46) {
        if text[i].to_int() == 46 {
          if !ipv4_octet(text, part_start, i) {
            break
          }
          parts += 1
          i += 1
          part_start = i
        } else {
          i += 1
        }
      }
      if parts == 3 && ipv4_octet(text, part_start, i) {
        push_finding(out, Ipv4, start, i, Medium)
      }
    }
    i += 1
  }
}

///|
fn luhn_valid(digits : Array[Int]) -> Bool {
  if digits.length() < 13 || digits.length() > 19 {
    return false
  }
  let mut sum = 0
  let mut alternate = false
  for k = digits.length() - 1; k >= 0; k = k - 1 {
    let mut value = digits[k]
    if alternate {
      value *= 2
      if value > 9 {
        value -= 9
      }
    }
    sum += value
    alternate = !alternate
  }
  sum % 10 == 0
}

///|
fn scan_cards(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_ascii_digit(text[i].to_int()) &&
      (i == 0 || !is_ascii_digit(text[i - 1].to_int())) {
      let start = i
      let digits : Array[Int] = []
      let mut end = i
      while end < text.length() {
        let c = text[end].to_int()
        if is_ascii_digit(c) {
          digits.push(c - 48)
          end += 1
        } else if (c == 32 || c == 45) && digits.length() > 0 {
          end += 1
        } else {
          break
        }
      }
      while end > start &&
            (text[end - 1].to_int() == 32 || text[end - 1].to_int() == 45) {
        end -= 1
      }
      if luhn_valid(digits) {
        push_finding(out, PaymentCard, start, end, High)
      }
      i = if end > i { end } else { i + 1 }
    } else {
      i += 1
    }
  }
}

///|
fn sort_findings(items : Array[Finding]) -> Unit {
  for i = 1; i < items.length(); i = i + 1 {
    let value = items[i]
    let mut j = i
    while j > 0 &&
          (
            items[j - 1].start > value.start ||
            (items[j - 1].start == value.start && items[j - 1].end < value.end)
          ) {
      items[j] = items[j - 1]
      j -= 1
    }
    items[j] = value
  }
}

///|
fn non_overlapping(items : Array[Finding]) -> Array[Finding] {
  sort_findings(items)
  let out : Array[Finding] = []
  for item in items {
    if out.length() == 0 || item.start >= out[out.length() - 1].end {
      out.push(item)
    }
  }
  out
}

///|
/// Scan text without retaining sensitive values in the returned findings.
pub fn scan(
  text : String,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> Array[Finding] {
  let out : Array[Finding] = []
  scan_prefixed_tokens(text, out)
  scan_bearer(text, out)
  scan_jwt(text, out)
  scan_private_keys(text, out)
  scan_url_credentials(text, out)
  scan_assignments(text, out)
  if policy.detect_email {
    scan_emails(text, out)
  }
  if policy.detect_ipv4 {
    scan_ipv4(text, out)
  }
  if policy.detect_payment_card {
    scan_cards(text, out)
  }
  non_overlapping(out)
}

///|
/// Add caller-known exact secrets to the built-in detector set. The returned
/// findings do not carry rule labels or values. Empty and very short values are
/// deliberately ignored.
pub fn scan_with_rules(
  text : String,
  rules : Array[CustomRule],
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> Array[Finding] {
  let out = scan(text, policy~)
  for rule in rules {
    if rule.value.length() >= 4 {
      let mut i = 0
      while i + rule.value.length() <= text.length() {
        if starts_at(text, i, rule.value) {
          push_finding(out, CustomSecret, i, i + rule.value.length(), High)
          i += rule.value.length()
        } else {
          i += 1
        }
      }
    }
  }
  non_overlapping(out)
}
