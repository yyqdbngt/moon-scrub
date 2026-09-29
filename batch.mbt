///|
fn empty_summary(lines : Int) -> BatchSummary {
  {
    lines,
    changed_lines: 0,
    findings: 0,
    access_tokens: 0,
    bearer_tokens: 0,
    jwts: 0,
    credentials: 0,
    emails: 0,
    ipv4s: 0,
    payment_cards: 0,
    private_keys: 0,
    url_credentials: 0,
    custom_secrets: 0,
    resident_ids: 0,
    mac_addresses: 0,
    uuids: 0,
    ipv6s: 0,
    phones: 0,
  }
}

///|
/// Redact independent log/API/prompt lines and return aggregate counts. The
/// summary contains categories and counts only, never matched values.
pub fn redact_batch(
  lines : Array[String],
  style? : RedactionStyle = Typed,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> BatchResult {
  let output : Array[String] = []
  let summary = empty_summary(lines.length())
  for line in lines {
    let result = redact(line, style~, policy~)
    output.push(result.text)
    if result.changed {
      summary.changed_lines += 1
    }
    summary.findings += result.findings.length()
    for finding in result.findings {
      match finding.kind {
        AccessToken => summary.access_tokens += 1
        BearerToken => summary.bearer_tokens += 1
        Jwt => summary.jwts += 1
        CredentialAssignment => summary.credentials += 1
        Email => summary.emails += 1
        Ipv4 => summary.ipv4s += 1
        PaymentCard => summary.payment_cards += 1
        PrivateKey => summary.private_keys += 1
        UrlCredential => summary.url_credentials += 1
        CustomSecret => summary.custom_secrets += 1
        ResidentId => summary.resident_ids += 1
        Phone => summary.phones += 1
        Ipv6 => summary.ipv6s += 1
        Uuid => summary.uuids += 1
        MacAddress => summary.mac_addresses += 1
      }
    }
  }
  { lines: output, summary, }
}
