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
/// Remove email findings whose domain is an IANA-reserved documentation
/// domain: example.com/net/org plus the test/example/invalid TLDs.
fn filter_example_domains(text : String, out : Array[Finding]) -> Unit {
  let keep : Array[Finding] = []
  for finding in out {
    if finding.kind == Email && is_example_domain(text, finding) {
      continue
    }
    keep.push(finding)
  }
  out.clear()
  for finding in keep {
    out.push(finding)
  }
}

///|
fn is_example_domain(text : String, finding : Finding) -> Bool {
  // Walk back from the '@' recorded inside the finding range.
  let mut at = finding.end - 1
  while at > finding.start && text[at].to_int() != 64 {
    at -= 1
  }
  if text[at].to_int() != 64 {
    return false
  }
  let domain = ascii_lower(text[at + 1:finding.end].to_owned())
  domain == "example.com" ||
  domain == "example.net" ||
  domain == "example.org" ||
  domain == "test" ||
  domain == "example" ||
  domain == "invalid"
}

///|
fn run_detectors(
  text : String,
  config : ScanConfig,
  out : Array[Finding],
) -> Unit {
  let needs_lower = config.detect_bearer ||
    config.detect_assignment ||
    config.detect_webhook
  let lower = if needs_lower { ascii_lower(text) } else { "" }
  if config.detect_access_token {
    scan_prefixed_tokens(text, config.extra_prefixes, out)
    scan_pattern_rules(text, config.extra_patterns, out)
  }
  if config.detect_bearer {
    scan_bearer(text, lower, out)
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
    scan_assignments(text, lower, out)
  }
  if config.detect_email {
    scan_emails(text, out)
    if config.suppress_example_domains {
      filter_example_domains(text, out)
    }
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
  if config.detect_high_entropy {
    scan_high_entropy(text, out)
  }
  if config.detect_public_key {
    scan_public_keys(text, out)
  }
  if config.detect_wallet {
    scan_wallet_addresses(text, out)
  }
  if config.detect_webhook {
    scan_webhook_urls(text, lower, out)
  }
  if config.detect_assignment {
    scan_basic_auth(text, lower, out)
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
/// ```mbt check
/// test {
///   let config = @moon_scrub.ScanConfig::secrets_only()
///   let findings = @moon_scrub.scan_with_config("ip 10.0.0.8", config)
///   inspect(findings.length(), content="0")
/// }
/// ```
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

///|
/// ```mbt check
/// test {
///   let rows = @moon_scrub.findings_summary("a@b.co x@y.org")
///   inspect(rows.length(), content="1")
///   inspect(rows[0].kind.to_string(), content="EMAIL")
///   inspect(rows[0].count, content="2")
/// }
/// ```
pub fn findings_summary(
  text : String,
  config? : ScanConfig = ScanConfig::standard(),
) -> Array[KindCount] {
  let findings = scan_with_config(text, config)
  let rows : Array[KindCount] = []
  for finding in findings {
    let mut placed = false
    for row in rows {
      if row.kind == finding.kind {
        row.count += 1
        placed = true
        break
      }
    }
    if !placed {
      rows.push({ kind: finding.kind, count: 1, })
    }
  }
  for i = 1; i < rows.length(); i = i + 1 {
    let value = rows[i]
    let mut j = i
    while j > 0 &&
          lexicographic_before(
            value.kind.to_string(),
            rows[j - 1].kind.to_string(),
          ) {
      rows[j] = rows[j - 1]
      j -= 1
    }
    rows[j] = value
  }
  rows
}

///|

///|
/// ```mbt check
/// test {
///   let kept = @moon_scrub.scan_except("ip 10.0.0.1 ip 10.0.0.2", ["10.0.0.1"])
///   inspect(kept.length(), content="1")
/// }
/// ```
pub fn scan_except(
  text : String,
  keep : Array[String],
  config? : ScanConfig = ScanConfig::standard(),
) -> Array[Finding] {
  let findings = scan_with_config(text, config)
  let kept : Array[(Int, Int)] = []
  for literal in keep {
    if literal.length() >= 4 {
      let mut i = 0
      while i + literal.length() <= text.length() {
        if starts_at(text, i, literal) {
          kept.push((i, i + literal.length()))
          i += literal.length()
        } else {
          i += 1
        }
      }
    }
  }
  let out : Array[Finding] = []
  for finding in findings {
    let mut overlap = false
    for span in kept {
      if finding.start < span.1 && finding.end > span.0 {
        overlap = true
        break
      }
    }
    if !overlap {
      out.push(finding)
    }
  }
  out
}

///|

///|
/// ```mbt check
/// test {
///   let lines = @moon_scrub.explain("mail a@b.co")
///   inspect(lines.length(), content="1")
///   inspect(lines[0], content="EMAIL 5-11 HIGH")
/// }
/// ```
pub fn explain(
  text : String,
  config? : ScanConfig = ScanConfig::standard(),
) -> Array[String] {
  let lines : Array[String] = []
  for finding in scan_with_config(text, config) {
    lines.push(
      finding.kind.to_string() +
      " " +
      finding.start.to_string() +
      "-" +
      finding.end.to_string() +
      " " +
      finding.confidence.to_string(),
    )
  }
  lines
}

///|
/// explain as a JSON array: one object per finding with kind, start,
/// end, and confidence — no matched text anywhere. Fits report
/// pipelines that already speak JSON.
pub fn explain_json(
  text : String,
  config? : ScanConfig = ScanConfig::standard(),
) -> String {
  let items : Array[Json] = []
  for finding in scan_with_config(text, config) {
    let entry : Array[(String, Json)] = []
    ignore(entry)
    let obj : Map[String, Json] = Map([])
    obj["confidence"] = Json::string(finding.confidence.to_string())
    obj["end"] = Json::number(
      finding.end.to_double(),
      repr=finding.end.to_string(),
    )
    obj["kind"] = Json::string(finding.kind.to_string())
    obj["start"] = Json::number(
      finding.start.to_double(),
      repr=finding.start.to_string(),
    )
    items.push(Json::object(obj))
  }
  let buf = StringBuilder()
  write_json_value(Json::array(items), buf)
  buf.to_string()
}

///|
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
