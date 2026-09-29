///|
fn masked_last4(text : String, finding : Finding) -> String {
  let length = finding.end - finding.start
  if length <= 4 {
    return "[REDACTED:" + finding.kind.to_string() + "]"
  }
  "[REDACTED:" +
  finding.kind.to_string() +
  ":*" +
  text[finding.end - 4:finding.end].to_owned() +
  "]"
}

///|
fn replacement(
  text : String,
  finding : Finding,
  style : RedactionStyle,
) -> String {
  match style {
    Marker => "[REDACTED]"
    Typed => "[REDACTED:" + finding.kind.to_string() + "]"
    PreserveLast4 => masked_last4(text, finding)
  }
}

///|
/// Redact all enabled findings. Already-produced markers contain no detector
/// pattern, so applying the same policy again is idempotent.
pub fn redact(
  text : String,
  style? : RedactionStyle = Typed,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> RedactionResult {
  redact_with_config(text, policy.to_config(), style~)
}

///|
/// Redact with full detector configuration, suppressor toggles and extra
/// prefixed-token rules.
pub fn redact_with_config(
  text : String,
  config : ScanConfig,
  style? : RedactionStyle = Typed,
) -> RedactionResult {
  let findings = scan_with_config(text, config)
  {
    text: redact_with_findings(text, findings, style),
    findings,
    changed: findings.length() > 0,
  }
}

///|
/// Redact with both built-in detectors under full configuration and
/// caller-supplied exact-value rules.
pub fn redact_full(
  text : String,
  rules : Array[CustomRule],
  config : ScanConfig,
  style? : RedactionStyle = Typed,
) -> RedactionResult {
  let findings = scan_full(text, rules, config)
  {
    text: redact_with_findings(text, findings, style),
    findings,
    changed: findings.length() > 0,
  }
}

///|
/// Return true only when a fresh scan finds no enabled sensitive values.
pub fn verify_clean(
  text : String,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> Bool {
  scan(text, policy~).length() == 0
}

///|
/// Return true only when a fresh configured scan finds nothing.
pub fn verify_clean_with_config(text : String, config : ScanConfig) -> Bool {
  scan_with_config(text, config).length() == 0
}
