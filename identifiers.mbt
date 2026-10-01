///|
// Detector family module, split out of scan.mbt for navigability.

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
          // A third adjacent colon makes ":::" — never a valid compression.
          if i + 2 < run.length() && run[i + 2].to_int() == 58 {
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
/// Cryptocurrency wallet addresses as pure shape matches: `0x` plus forty
/// hex characters for Ethereum-style, and bech32 `bc1`/`tb1`/`ltc1` bodies
/// for SegWit-style. No checksum validation, hence medium confidence.
fn scan_wallet_addresses(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    let c = text[i].to_int()
    if c == 48 &&
      i + 1 < text.length() &&
      (text[i + 1].to_int() == 120 || text[i + 1].to_int() == 88) {
      let start = i
      let mut end = i + 2
      while end < text.length() && is_ascii_hexdigit(text[end].to_int()) {
        end += 1
      }
      if end - start == 42 {
        push_finding(out, WalletAddress, start, end, Medium)
        i = end
      } else {
        i += 1
      }
    } else if (c == 98 || c == 66) && i + 3 < text.length() {
      let probe = ascii_lower(text[i:i + 4].to_owned())
      if probe == "bc1q" ||
        probe == "bc1p" ||
        probe == "tb1q" ||
        probe == "tb1p" ||
        probe == "ltc1" {
        // Collect the full lowercase-alnum body (HRP plus separator plus
        // data); the prefix probe above already pins the family.
        let start = i
        let mut end = i
        while end < text.length() {
          let r = text[end].to_int()
          if is_ascii_digit(r) || (r >= 97 && r <= 122) {
            end += 1
          } else {
            break
          }
        }
        if end - start >= 14 && end - start <= 90 {
          push_finding(out, WalletAddress, start, end, Medium)
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
      // Inspect the domain in place: an allocation per '@' candidate would
      // dominate the scan on address-heavy text.
      if start < at && end - at >= 4 && domain_shape_ok(text, at + 1, end) {
        push_finding(out, Email, start, end, High)
      }
    }
  }
}

///|
/// Domain shape: at least three code units, no leading or trailing dot,
/// and at least one interior dot.
fn domain_shape_ok(text : String, from : Int, until : Int) -> Bool {
  if until - from < 3 {
    return false
  }
  if text[from].to_int() == 46 || text[until - 1].to_int() == 46 {
    return false
  }
  for k = from; k < until; k = k + 1 {
    if text[k].to_int() == 46 && k > from {
      return true
    }
  }
  false
}

///|
fn ipv4_octet(text : String, start : Int, end : Int) -> Bool {
  if end <= start || end - start > 3 {
    return false
  }
  // Leading zeros are ambiguous dotted-decimal (octal in some parsers) and
  // appear far more often in version strings than in addresses.
  if end - start > 1 && text[start].to_int() == 48 {
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
                digits.length() == 10 ||
                digits.length() == 12
              )
            )
          ) {
          // Hyphenated groups anywhere; spaces only at the usual 4/8/12
          // Visa-style boundaries and 4/10 for Amex 4-6-5, so an unrelated
          // neighbouring number is never glued onto a card candidate.
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
