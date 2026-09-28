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
  let findings = scan(text, policy~)
  if findings.length() == 0 {
    return { text, findings, changed: false, }
  }
  let mut out = ""
  let mut cursor = 0
  for finding in findings {
    out += text[cursor:finding.start].to_owned()
    out += replacement(text, finding, style)
    cursor = finding.end
  }
  out += text[cursor:].to_owned()
  { text: out, findings, changed: true, }
}

///|
/// Return true only when a fresh scan finds no enabled sensitive values.
pub fn verify_clean(
  text : String,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> Bool {
  scan(text, policy~).length() == 0
}
