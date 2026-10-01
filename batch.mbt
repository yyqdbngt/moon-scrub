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
    public_keys: 0,
    wallet_addresses: 0,
    webhook_urls: 0,
    high_entropy_secrets: 0,
  }
}

///|
/// Fold one line's findings into the aggregate summary.
fn tally(summary : BatchSummary, findings : Array[Finding]) -> Unit {
  for finding in findings {
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
      HighEntropySecret => summary.high_entropy_secrets += 1
      MacAddress => summary.mac_addresses += 1
      Uuid => summary.uuids += 1
      Ipv6 => summary.ipv6s += 1
      Phone => summary.phones += 1
      PublicKey => summary.public_keys += 1
      WalletAddress => summary.wallet_addresses += 1
      WebhookUrl => summary.webhook_urls += 1
    }
  }
}

///|
/// Redact one line and fold its findings into the outputs and summary.
fn run_line(
  line : String,
  index : Int,
  config : ScanConfig,
  style~ : RedactionStyle,
  output : Array[String],
  changed_indices : Array[Int],
  summary : BatchSummary,
) -> Unit {
  let result = redact_with_config(line, config, style~)
  output.push(result.text)
  if result.changed {
    changed_indices.push(index)
    summary.changed_lines += 1
  }
  summary.findings += result.findings.length()
  tally(summary, result.findings)
}

///|
/// Batch redaction under a full configuration, enabling post-0.1.0
/// families such as resident ids and MAC addresses in log pipelines.
pub fn redact_batch_with_config(
  lines : Array[String],
  config : ScanConfig,
  style? : RedactionStyle = Typed,
) -> BatchResult {
  let output : Array[String] = []
  let changed_indices : Array[Int] = []
  let summary = empty_summary(lines.length())
  for index, line in lines {
    run_line(line, index, config, style~, output, changed_indices, summary)
  }
  { lines: output, summary, changed_indices, }
}

///|
/// ```mbt check
/// test {
///   let result = @moon_scrub.redact_batch(["password=x", "plain"])
///   inspect(result.summary.changed_lines, content="1")
/// }
/// ```
pub fn redact_batch(
  lines : Array[String],
  style? : RedactionStyle = Typed,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> BatchResult {
  let output : Array[String] = []
  let changed_indices : Array[Int] = []
  let summary = empty_summary(lines.length())
  let config = policy.to_config()
  for index, line in lines {
    run_line(line, index, config, style~, output, changed_indices, summary)
  }
  { lines: output, summary, changed_indices, }
}
