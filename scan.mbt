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
/// Recognized service token prefixes with per-family minimum total lengths.
/// All samples in tests are synthetic; real credentials never appear here.
fn builtin_token_specs() -> Array[TokenPrefixRule] {
  [
    { prefix: "github_pat_", min_length: 22, },
    { prefix: "sk-ant-", min_length: 15, },
    { prefix: "sk_live_", min_length: 16, },
    { prefix: "rk_live_", min_length: 16, },
    { prefix: "pk_live_", min_length: 16, },
    { prefix: "dop_v1_", min_length: 15, },
    { prefix: "dop_v2_", min_length: 15, },
    { prefix: "shpat_", min_length: 14, },
    { prefix: "shpca_", min_length: 14, },
    { prefix: "shppa_", min_length: 14, },
    { prefix: "ghp_", min_length: 12, },
    { prefix: "gho_", min_length: 12, },
    { prefix: "ghu_", min_length: 12, },
    { prefix: "ghs_", min_length: 12, },
    { prefix: "ghr_", min_length: 12, },
    { prefix: "gha_", min_length: 12, },
    { prefix: "xoxb-", min_length: 13, },
    { prefix: "xoxp-", min_length: 13, },
    { prefix: "xoxc-", min_length: 13, },
    { prefix: "xoxa-", min_length: 13, },
    { prefix: "xoxr-", min_length: 13, },
    { prefix: "glpat-", min_length: 14, },
    { prefix: "npm_", min_length: 12, },
    { prefix: "AIza", min_length: 20, },
    { prefix: "AKIA", min_length: 20, },
    { prefix: "ASIA", min_length: 20, },
    { prefix: "SG.", min_length: 20, },
    { prefix: "sk-", min_length: 11, },
  ]
}

///|
fn rule_first(rule : TokenPrefixRule) -> Int {
  rule.prefix[0].to_int()
}

///|
/// Bucket the rules by first character so the scan loop only compares a
/// position against candidates that can match at all.
fn bucket_specs(
  specs : Array[TokenPrefixRule],
) -> Array[Array[TokenPrefixRule]] {
  let buckets : Array[Array[TokenPrefixRule]] = []
  for _ in 0..<256 {
    buckets.push([])
  }
  for spec in specs {
    if spec.prefix.length() >= 2 && spec.min_length >= spec.prefix.length() {
      buckets[rule_first(spec)].push(spec)
    }
  }
  for bucket in buckets {
    sort_specs(bucket)
  }
  buckets
}

///|
/// Longest prefix first so `sk-ant-` wins over `sk-` at the same position.
fn sort_specs(items : Array[TokenPrefixRule]) -> Unit {
  for i = 1; i < items.length(); i = i + 1 {
    let value = items[i]
    let mut j = i
    while j > 0 && items[j - 1].prefix.length() < value.prefix.length() {
      items[j] = items[j - 1]
      j -= 1
    }
    items[j] = value
  }
}

///|
fn scan_prefixed_tokens(
  text : String,
  extra : Array[TokenPrefixRule],
  out : Array[Finding],
) -> Unit {
  let specs = builtin_token_specs()
  for rule in extra {
    specs.push(rule)
  }
  let buckets = bucket_specs(specs)
  for i = 0; i < text.length(); i = i + 1 {
    let code = text[i].to_int()
    // Every built-in prefix starts with an ASCII character; skip non-ASCII
    // code units instead of indexing past the bucket table.
    if code >= 256 {
      continue
    }
    let bucket = buckets[code]
    for spec in bucket {
      if starts_at(text, i, spec.prefix) {
        let mut end = i + spec.prefix.length()
        while end < text.length() && is_token_char(text[end].to_int()) {
          end += 1
        }
        if end - i >= spec.min_length {
          push_finding(out, AccessToken, i, end, High)
        }
        break
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
      // Skip previously produced markers so repeated redaction stays idempotent
      // under every style, including PreserveLast4.
      if end - start >= 8 && !starts_at(text, start, "[REDACTED") {
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
  let lower = ascii_lower(text)
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
          starts_at(lower, start, "bearer ") {
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
/// A version-looking IPv4 sits inside a longer token such as `v1.2.3.4` or
/// `1.2.3.4rc1`. Reject matches glued to word characters on either side; a
/// trailing dot stays acceptable because sentences end IPs with periods.
fn ipv4_glued_to_word(text : String, start : Int, end : Int) -> Bool {
  if start > 0 {
    let before = text[start - 1].to_int()
    if is_ascii_alnum(before) || before == 46 || before == 45 || before == 95 {
      return true
    }
  }
  if end < text.length() {
    let after = text[end].to_int()
    if is_ascii_alnum(after) || after == 45 || after == 95 {
      return true
    }
  }
  false
}

///|
/// Parse a digit-and-dot run as an IPv4 literal. Returns the length of the
/// four valid octets, or -1 when the run is not a plain address. A single
/// trailing dot after the fourth octet is tolerated so sentence-ending
/// periods do not hide real addresses, but it is not part of the match.
fn ipv4_run_end(run : String) -> Int {
  let mut octets = 0
  let mut part_start = 0
  for i = 0; i <= run.length(); i = i + 1 {
    if i == run.length() || run[i].to_int() == 46 {
      if !ipv4_octet(run, part_start, i) {
        return -1
      }
      octets += 1
      if octets == 4 {
        if i == run.length() {
          return i
        }
        if i + 1 == run.length() {
          return i
        }
        return -1
      }
      part_start = i + 1
    }
  }
  -1
}

///|
fn scan_ipv4(
  text : String,
  suppress_versions : Bool,
  out : Array[Finding],
) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_ascii_digit(text[i].to_int()) &&
      (i == 0 || !is_ascii_digit(text[i - 1].to_int())) {
      let start = i
      while i < text.length() &&
            (is_ascii_digit(text[i].to_int()) || text[i].to_int() == 46) {
        i += 1
      }
      let run = text[start:i].to_owned()
      let valid_end = ipv4_run_end(run)
      if valid_end >= 0 &&
        !(suppress_versions &&
        ipv4_glued_to_word(text, start, start + valid_end)) {
        push_finding(out, Ipv4, start, start + valid_end, Medium)
      }
    } else {
      i += 1
    }
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
/// Major card-network prefixes: Visa 4, Mastercard 5, Discover/UnionPay 6,
/// Amex 34/37. Long digit runs outside these networks are overwhelmingly
/// order or account identifiers that happen to satisfy Luhn.
fn known_card_prefix(digits : Array[Int]) -> Bool {
  if digits.length() < 1 {
    return false
  }
  let first = digits[0]
  if first == 4 || first == 5 || first == 6 {
    return true
  }
  if digits.length() >= 2 {
    let two = first * 10 + digits[1]
    if two == 34 || two == 37 {
      return true
    }
  }
  false
}

///|
fn scan_cards(text : String, require_bin : Bool, out : Array[Finding]) -> Unit {
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
        } else if end > start &&
          is_ascii_digit(text[end - 1].to_int()) &&
          (
            c == 45 ||
            (
              c == 32 &&
              (
                digits.length() == 4 ||
                digits.length() == 8 ||
                digits.length() == 12
              )
            )
          ) {
          // Hyphenated groups anywhere; spaces only at the usual 4/8/12
          // digit boundaries, so an unrelated neighbouring number is never
          // glued onto a card candidate.
          end += 1
        } else {
          break
        }
      }
      while end > start &&
            (text[end - 1].to_int() == 32 || text[end - 1].to_int() == 45) {
        end -= 1
      }
      if luhn_valid(digits) && !(require_bin && !known_card_prefix(digits)) {
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
fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    _ =>
      if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        29
      } else {
        28
      }
  }
}

///|
fn two_digits(text : String, at : Int) -> Int {
  (text[at].to_int() - 48) * 10 + (text[at + 1].to_int() - 48)
}

///|
fn four_digits(text : String, at : Int) -> Int {
  let mut value = 0
  for k = 0; k < 4; k = k + 1 {
    value = value * 10 + text[at + k].to_int() - 48
  }
  value
}

///|
/// The birth-date segment must name a calendar date between 1900 and 2100;
/// checksum-valid strings like a fabricated 2001-02-29 are rejected here.
fn resident_id_birth_ok(text : String, start : Int) -> Bool {
  let year = four_digits(text, start + 6)
  let month = two_digits(text, start + 10)
  let day = two_digits(text, start + 12)
  year >= 1900 &&
  year <= 2100 &&
  month >= 1 &&
  month <= 12 &&
  day >= 1 &&
  day <= days_in_month(year, month)
}

///|
/// GB 11643-1999 check digit: weighted sum of the first 17 digits under
/// weights 7 9 10 5 8 4 2 1 6 3 7 9 10 5 8 4 2, mapped through `10X98765432`.
fn resident_id_checksum_ok(text : String, start : Int) -> Bool {
  let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
  let order = "10X98765432"
  let mut sum = 0
  for k = 0; k < 17; k = k + 1 {
    sum += (text[start + k].to_int() - 48) * weights[k]
  }
  text[start + 17] == order[sum % 11]
}

///|
/// Chinese resident identity numbers: eighteen characters, seventeen digits
/// plus a check digit that may be X. Both the checksum and the embedded
/// birth date must validate, which keeps ordinary 18-digit order numbers
/// from being reported.
fn scan_resident_ids(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i + 18 <= text.length() {
    if is_ascii_digit(text[i].to_int()) &&
      (i == 0 || !is_ascii_alnum(text[i - 1].to_int())) {
      let end = i + 18
      let last = text[end - 1].to_int()
      let shaped = if is_ascii_digit(last) || last == 88 || last == 120 {
        let mut k = i
        while k < end - 1 && is_ascii_digit(text[k].to_int()) {
          k += 1
        }
        k == end - 1
      } else {
        false
      }
      let tail_free = end >= text.length() ||
        (
          !is_ascii_alnum(text[end].to_int()) &&
          text[end].to_int() != 45 &&
          text[end].to_int() != 95
        )
      if shaped &&
        tail_free &&
        resident_id_checksum_ok(text, i) &&
        resident_id_birth_ok(text, i) {
        push_finding(out, ResidentId, i, end, High)
        i = end
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
}

///|
/// EUI-48 hardware addresses: six hyphen-or-colon separated hex pairs with a
/// consistent separator. Reported at medium confidence because most log
/// occurrences are ordinary device identifiers rather than personal data.
fn scan_mac_addresses(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i + 17 <= text.length() {
    if is_ascii_hexdigit(text[i].to_int()) &&
      (i == 0 || !is_ascii_hexdigit(text[i - 1].to_int())) {
      let sep = text[i + 2].to_int()
      if sep == 58 || sep == 45 {
        let mut k = i + 2
        let mut groups = 1
        while groups < 6 {
          if text[k].to_int() != sep {
            break
          }
          if !(is_ascii_hexdigit(text[k + 1].to_int()) &&
            is_ascii_hexdigit(text[k + 2].to_int())) {
            break
          }
          k += 3
          groups += 1
        }
        let end = i + 17
        let tail = if end < text.length() { text[end].to_int() } else { -1 }
        if groups == 6 &&
          (tail == -1 || (!is_ascii_hexdigit(tail) && tail != 58 && tail != 45)) {
          push_finding(out, MacAddress, i, end, Medium)
          i = end
        } else {
          i += 1
        }
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
}

///|
/// Canonical 8-4-4-4-12 hexadecimal UUIDs. Reported at medium confidence:
/// most occurrences are trace or entity identifiers, which are personal data
/// only in specific contexts.
fn scan_uuids(text : String, out : Array[Finding]) -> Unit {
  let lengths = [8, 4, 4, 4, 12]
  let mut i = 0
  while i + 36 <= text.length() {
    if is_ascii_hexdigit(text[i].to_int()) &&
      (
        i == 0 ||
        (
          !is_ascii_hexdigit(text[i - 1].to_int()) &&
          !is_ascii_letter(text[i - 1].to_int())
        )
      ) {
      let mut k = i
      let mut ok = true
      for group = 0; group < 5; group = group + 1 {
        for _ in 0..<lengths[group] {
          if k >= text.length() || !is_ascii_hexdigit(text[k].to_int()) {
            ok = false
            break
          }
          k += 1
        }
        if !ok {
          break
        }
        if group < 4 {
          if k >= text.length() || text[k].to_int() != 45 {
            ok = false
            break
          }
          k += 1
        }
      }
      let tail = if k < text.length() { text[k].to_int() } else { -1 }
      if ok &&
        (
          tail == -1 ||
          (!is_ascii_hexdigit(tail) && !is_ascii_letter(tail) && tail != 45)
        ) {
        push_finding(out, Uuid, i, k, Medium)
        i = k
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
}

///|
/// Validate a hex-and-colon run as an RFC 4291 address: groups of one to
/// four hex digits, at most one `::` compression, and either eight full
/// groups or fewer when compressed. IPv4-mapped tails are not accepted.
fn ipv6_run_ok(run : String) -> Bool {
  if run.length() < 2 || run.length() > 45 {
    return false
  }
  let mut groups = 0
  let mut compressed = false
  let mut part_start = 0
  let mut i = 0
  let mut expect_group = false
  while i <= run.length() {
    if i == run.length() || run[i].to_int() == 58 {
      if i > part_start {
        if i - part_start > 4 || !all_hex(run, part_start, i) {
          return false
        }
        groups += 1
      } else if i == 0 || i == run.length() {
        // leading or trailing single colon adjacent to compression
      } else if run[i - 1].to_int() == 58 {
        // second colon of a compression marker
      } else {
        return false
      }
      if i < run.length() && run[i].to_int() == 58 {
        if i + 1 < run.length() && run[i + 1].to_int() == 58 {
          if compressed {
            return false
          }
          compressed = true
          expect_group = false
          i += 2
          part_start = i
          continue
        }
      }
      part_start = i + 1
      expect_group = true
    }
    i += 1
  }
  ignore(expect_group)
  if compressed {
    groups < 8
  } else {
    groups == 8
  }
}

///|
fn all_hex(text : String, start : Int, end : Int) -> Bool {
  for k = start; k < end; k = k + 1 {
    if !is_ascii_hexdigit(text[k].to_int()) {
      return false
    }
  }
  true
}

///|
/// Scan for IPv6 literals inside hex-and-colon runs bounded by non-hex,
/// non-colon characters. The run is re-parsed strictly, so MAC-shaped and
/// time-shaped colon runs never qualify.
fn scan_ipv6(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    let c = text[i].to_int()
    if is_ascii_hexdigit(c) || c == 58 {
      let start = i
      while i < text.length() {
        let r = text[i].to_int()
        if is_ascii_hexdigit(r) || r == 58 {
          i += 1
        } else {
          break
        }
      }
      let run = text[start:i].to_owned()
      if ipv6_run_ok(run) {
        push_finding(out, Ipv6, start, i, Medium)
      }
    } else {
      i += 1
    }
  }
}

///|
/// E.164 phone numbers: a plus sign followed by eight to fifteen digits with
/// a non-zero country code. Opt-in because bare international numbers are
/// frequently order ids or reference codes; grouped formats like
/// `+86 138 0013 8000` are not matched.
fn scan_phones(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    if text[i].to_int() == 43 &&
      i + 1 < text.length() &&
      text[i + 1].to_int() >= 49 &&
      text[i + 1].to_int() <= 57 {
      let start = i
      let mut end = i + 1
      while end < text.length() && is_ascii_digit(text[end].to_int()) {
        end += 1
      }
      let digits = end - start - 1
      if digits >= 8 && digits <= 15 {
        push_finding(out, Phone, start, end, Medium)
        i = end
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
}

///|
/// Public key material: `ssh-rsa`, `ssh-ed25519`, and `ecdsa-sha2-*` key
/// lines whose base64 body is at least fifty characters. Public keys are not
/// secrets, but they identify infrastructure and are flagged for hygiene.
fn scan_public_keys(text : String, out : Array[Finding]) -> Unit {
  let heads = ["ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"]
  for i = 0; i < text.length(); i = i + 1 {
    for head in heads {
      if starts_at(text, i, head) {
        let body_start = i + head.length()
        let mut end = body_start
        while end < text.length() && is_base64url(text[end].to_int()) {
          end += 1
        }
        if end - body_start >= 50 {
          push_finding(out, PublicKey, i, end, High)
        }
      }
    }
  }
}

///|
fn run_detectors(
  text : String,
  config : ScanConfig,
  out : Array[Finding],
) -> Unit {
  if config.detect_access_token {
    scan_prefixed_tokens(text, config.extra_prefixes, out)
  }
  if config.detect_bearer {
    scan_bearer(text, out)
  }
  if config.detect_jwt {
    scan_jwt(text, out)
  }
  if config.detect_private_key {
    scan_private_keys(text, out)
  }
  if config.detect_url_credential {
    scan_url_credentials(text, out)
  }
  if config.detect_assignment {
    scan_assignments(text, out)
  }
  if config.detect_email {
    scan_emails(text, out)
  }
  if config.detect_ipv4 {
    scan_ipv4(text, config.suppress_version_ipv4, out)
  }
  if config.detect_ipv6 {
    scan_ipv6(text, out)
  }
  if config.detect_phone {
    scan_phones(text, out)
  }
  if config.detect_public_key {
    scan_public_keys(text, out)
  }
  // Resident IDs outrank payment cards: an eighteen-digit checksummed
  // identity number is stronger evidence than a Luhn pass, and Mastercard
  // BINs (51-55) overlap common area codes.
  if config.detect_resident_id {
    scan_resident_ids(text, out)
  }
  if config.detect_mac {
    scan_mac_addresses(text, out)
  }
  if config.detect_uuid {
    scan_uuids(text, out)
  }
  if config.detect_payment_card {
    scan_cards(text, config.require_known_card_prefix, out)
  }
}

///|
/// Scan text without retaining sensitive values in the returned findings.
pub fn scan(
  text : String,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> Array[Finding] {
  scan_with_config(text, policy.to_config())
}

///|
/// Scan with full control over detector families, suppressors and extra
/// prefixed-token rules.
pub fn scan_with_config(text : String, config : ScanConfig) -> Array[Finding] {
  let out : Array[Finding] = []
  run_detectors(text, config, out)
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
  scan_full(text, rules, policy.to_config())
}

///|
/// Unified entry point combining exact-value rules with a full configuration.
pub fn scan_full(
  text : String,
  rules : Array[CustomRule],
  config : ScanConfig,
) -> Array[Finding] {
  let out = scan_with_config(text, config)
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
