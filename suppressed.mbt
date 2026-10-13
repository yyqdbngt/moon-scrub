///|
/// Suppression transparency.
///
/// The suppressors exist to keep false positives out of reports, but
/// a silent filter is an unauditable filter: when something is
/// missing from a finding list, callers cannot tell whether the text
/// was clean or the suppressor ate a hit. `explain_suppressed` runs
/// the detection pass with every suppressor disabled, subtracts the
/// real scan, and reports each suppressed candidate with the rule
/// that removed it — version-shaped IPv4, unknown-network Luhn
/// numbers, and IANA-reserved documentation email domains. The
/// finding values still never leave the process: suppressed entries
/// carry offsets and kinds only.

///|
pub(all) struct SuppressedFinding {
  kind : SensitiveKind
  start : Int
  end : Int
  reason : String
} derive(Eq, @debug.Debug)

///|
pub extend SuppressedFinding with Eq::{equal, not_equal}

///|
pub extend SuppressedFinding with @debug.Debug::{to_repr}

///|
fn SuppressedFinding::as_finding(self : SuppressedFinding) -> Finding {
  { kind: self.kind, start: self.start, end: self.end, confidence: Medium }
}

///|
pub fn explain_suppressed(
  text : String,
  config : ScanConfig,
) -> Array[SuppressedFinding] {
  // Unsuppressed view: same families, suppressors off.
  let relaxed = {
    ..config,
    suppress_version_ipv4: false,
    require_known_card_prefix: false,
    suppress_example_domains: false,
  }
  let collected : Array[Finding] = []
  run_detectors(text, relaxed, collected)
  let raw = non_overlapping(collected)
  let kept = scan_with_config(text, config)
  let diff = diff_findings(raw, kept)
  // Everything present in raw but missing from kept was suppressed;
  // attribute the reason from the config flags by kind.
  let entries : Array[SuppressedFinding] = []
  for finding in sort_findings_for_diff(diff.removed) {
    let reason = match finding.kind {
      Ipv4 => "version-shaped IPv4 (suppress_version_ipv4)"
      PaymentCard =>
        "Luhn-valid number outside known card networks (require_known_card_prefix)"
      Email => "IANA-reserved documentation domain (suppress_example_domains)"
      other => other.to_string() + " suppressed by an unknown rule"
    }
    entries.push({
      kind: finding.kind,
      start: finding.start,
      end: finding.end,
      reason,
    })
  }
  entries
}
