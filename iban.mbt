///|
/// International Bank Account Number detection.
///
/// An IBAN is a country code, two check digits and a BBAN of up to 30
/// alphanumeric characters, with a country-specific total length between
/// 15 and 34. Detection walks uppercase alphanumeric runs that start with
/// two letters and two digits, filters by the country length table, and
/// validates the ISO 7064 MOD-97-10 checksum: rearranging the number so
/// the first four characters move to the end, expanding letters to their
/// base-36 digits, must leave remainder 1. The checksum is what keeps
/// this family precise — invoice numbers or order codes of the same
/// shape fail validation and are never reported.
///
/// Only contiguous uppercase IBANs are detected; the space-grouped
/// printing form is intentionally left alone in this version because
/// allowing spaces reopens false positives on part-number style text.

///|
fn iban_expected_length(run : String) -> Int {
  // Returns the expected total length for the country prefix, or 0 when
  // the country is not in the supported table.
  let c0 = run[0].to_int()
  let c1 = run[1].to_int()
  match (c0, c1) {
    (65, 84) => 20 // AT
    (65, 69) => 23 // AE
    (66, 71) => 28 // BG
    (66, 82) => 29 // BR
    (67, 72) => 21 // CH
    (67, 89) => 28 // CY
    (67, 90) => 24 // CZ
    (68, 69) => 22 // DE
    (68, 75) => 18 // DK
    (69, 83) => 24 // ES
    (69, 69) => 16 // EE
    (70, 73) => 18 // FI
    (70, 82) => 27 // FR
    (71, 66) => 22 // GB
    (71, 82) => 27 // GR
    (72, 82) => 21 // HR
    (72, 85) => 28 // HU
    (73, 69) => 22 // IE
    (73, 76) => 23 // IL
    (73, 83) => 26 // IS
    (73, 84) => 27 // IT
    (76, 73) => 21 // LI
    (76, 84) => 20 // LT
    (76, 85) => 20 // LU
    (76, 86) => 21 // LV
    (77, 84) => 31 // MT
    (77, 85) => 30 // MU
    (78, 76) => 18 // NL
    (78, 79) => 15 // NO
    (80, 76) => 28 // PL
    (80, 84) => 25 // PT
    (81, 65) => 29 // QA
    (82, 79) => 24 // RO
    (83, 65) => 24 // SA
    (83, 69) => 24 // SE
    (83, 73) => 19 // SI
    (83, 75) => 24 // SK
    (83, 77) => 27 // SM
    (84, 82) => 26 // TR
    _ => 0
  }
}

///|
fn iban_mod97_ok(run : String) -> Bool {
  // ISO 7064 MOD-97-10 over the rearranged number: BBAN first, then the
  // country code and check digits. Letters contribute two decimal digits
  // (A=10 ... Z=35), so each letter multiplies the running remainder by
  // 100 while digits multiply by 10.
  let mut remainder = 0
  for i = 4; i < run.length(); i = i + 1 {
    let c = run[i].to_int()
    if c >= 65 && c <= 90 {
      remainder = (remainder * 100 + (c - 65 + 10)) % 97
    } else {
      remainder = (remainder * 10 + (c - 48)) % 97
    }
  }
  for i = 0; i < 4; i = i + 1 {
    let c = run[i].to_int()
    if c >= 65 && c <= 90 {
      remainder = (remainder * 100 + (c - 65 + 10)) % 97
    } else {
      remainder = (remainder * 10 + (c - 48)) % 97
    }
  }
  remainder == 1
}

///|
fn iban_alnum_upper(code : Int) -> Bool {
  (code >= 65 && code <= 90) || (code >= 48 && code <= 57)
}

///|
fn scan_ibans(text : String, out : Array[Finding]) -> Unit {
  let mut i = 0
  while i < text.length() {
    let boundary = i == 0 || !iban_alnum_upper(text[i - 1].to_int())
    let four_ok = i + 4 <= text.length() && {
      let a = text[i].to_int()
      let b = text[i + 1].to_int()
      let c = text[i + 2].to_int()
      let d = text[i + 3].to_int()
      a >= 65 && a <= 90 && b >= 65 && b <= 90 && c >= 48 && c <= 57 && d >= 48 && d <= 57
    }
    if boundary && four_ok {
      let start = i
      let mut end = i
      while end < text.length() && iban_alnum_upper(text[end].to_int()) {
        end += 1
      }
      let run = text[start:end].to_owned()
      let length = end - start
      if length >= 15 &&
        length <= 34 &&
        iban_expected_length(run) == length &&
        iban_mod97_ok(run) {
        push_finding(out, Iban, start, end, High)
        i = end
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
}
