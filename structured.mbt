///|
fn last_path_component(path : String) -> String {
  let mut start = 0
  for i = 0; i < path.length(); i = i + 1 {
    let c = path[i].to_int()
    if c == 46 || c == 47 || c == 92 || c == 91 || c == 93 {
      start = i + 1
    }
  }
  ascii_lower(path[start:].to_owned())
}

///|
fn path_is_sensitive(path : String) -> Bool {
  sensitive_key(last_path_component(path))
}

///|
fn redact_with_findings(
  text : String,
  findings : Array[Finding],
  style : RedactionStyle,
) -> String {
  if findings.length() == 0 {
    return text
  }
  let out = StringBuilder()
  let mut cursor = 0
  for finding in findings {
    out.write_string(text[cursor:finding.start].to_owned())
    out.write_string(replacement(text, finding, style))
    cursor = finding.end
  }
  out.write_string(text[cursor:].to_owned())
  out.to_string()
}

///|
/// Redact already-parsed structured fields. Sensitive paths are fail-closed:
/// their complete value is replaced even when its shape matches no detector.
/// Other fields use content scanning. Paths are retained for caller-side joins.
pub fn redact_fields(
  fields : Array[StructuredField],
  style? : RedactionStyle = Typed,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> StructuredResult {
  let output : Array[StructuredFieldResult] = []
  let mut changed_fields = 0
  let mut count = 0
  for field in fields {
    let sensitive_path = path_is_sensitive(field.path)
    let findings = if sensitive_path && field.value.length() > 0 {
      [
        {
          kind: CredentialAssignment,
          start: 0,
          end: field.value.length(),
          confidence: High,
        },
      ]
    } else {
      scan(field.value, policy~)
    }
    let changed = findings.length() > 0
    if changed {
      changed_fields += 1
    }
    count += findings.length()
    output.push({
      path: field.path,
      value: redact_with_findings(field.value, findings, style),
      findings,
      changed,
      sensitive_path,
    })
  }
  { fields: output, changed_fields, findings: count, }
}

///|
/// Redact structured fields under a full configuration, enabling
/// post-0.1.0 families for callers that normalize records themselves.
pub fn redact_fields_with_config(
  fields : Array[StructuredField],
  config : ScanConfig,
  style? : RedactionStyle = Typed,
) -> StructuredResult {
  let output : Array[StructuredFieldResult] = []
  let mut changed_fields = 0
  let mut count = 0
  for field in fields {
    let sensitive_path = path_is_sensitive(field.path)
    let findings = if sensitive_path && field.value.length() > 0 {
      [
        {
          kind: CredentialAssignment,
          start: 0,
          end: field.value.length(),
          confidence: High,
        },
      ]
    } else {
      scan_with_config(field.value, config)
    }
    let changed = findings.length() > 0
    if changed {
      changed_fields += 1
    }
    count += findings.length()
    output.push({
      path: field.path,
      value: redact_with_findings(field.value, findings, style),
      findings,
      changed,
      sensitive_path,
    })
  }
  { fields: output, changed_fields, findings: count, }
}

///|
/// Redact text with built-in and caller-supplied exact-value rules.
pub fn redact_with_rules(
  text : String,
  rules : Array[CustomRule],
  style? : RedactionStyle = Typed,
  policy? : ScanPolicy = ScanPolicy::standard(),
) -> RedactionResult {
  let findings = scan_with_rules(text, rules, policy~)
  {
    text: redact_with_findings(text, findings, style),
    findings,
    changed: findings.length() > 0,
  }
}
