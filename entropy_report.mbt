///|
/// Entropy reporting for triage.
///
/// Findings do not all deserve the same attention: a JWT is proof by
/// construction, while a high-entropy run is evidence only. The
/// report grades every finding by the Shannon entropy of its own
/// span — structural tokens land low, random material lands high —
/// and summarizes the text: finding count, high-entropy share, and
/// the bits-per-character quartiles. Triage reads the report top
/// down; the numbers are deterministic, never a model score.

///|
pub(all) struct FindingEntropy {
  finding : Finding
  entropy : Double
  band : String
} derive(Eq, @debug.Debug)

///|
pub extend FindingEntropy with Eq::{equal, not_equal}

///|
pub extend FindingEntropy with @debug.Debug::{to_repr}

///|
fn entropy_band(bits : Double) -> String {
  if bits >= 4.75 {
    "very-high"
  } else if bits >= 4.0 {
    "high"
  } else if bits >= 3.0 {
    "medium"
  } else {
    "low"
  }
}

///|
pub fn entropy_report(text : String, config : ScanConfig) -> EntropySummary {
  let findings = scan_with_config(text, config)
  let entries : Array[FindingEntropy] = []
  let mut very_high = 0
  let mut high = 0
  let mut medium = 0
  let mut low = 0
  for finding in findings {
    let bits = shannon_entropy(text, finding.start, finding.end)
    let band = entropy_band(bits)
    match band {
      "very-high" => very_high += 1
      "high" => high += 1
      "medium" => medium += 1
      _ => low += 1
    }
    entries.push({ finding, entropy: bits, band })
  }
  let mut total_chars = 0
  for entry in entries {
    total_chars += entry.finding.end - entry.finding.start
  }
  {
    entries,
    finding_count: findings.length(),
    very_high,
    high,
    medium,
    low,
    sensitive_chars: total_chars,
    text_units: text.length(),
  }
}

///|
pub(all) struct EntropySummary {
  entries : Array[FindingEntropy]
  finding_count : Int
  very_high : Int
  high : Int
  medium : Int
  low : Int
  sensitive_chars : Int
  text_units : Int
} derive(Eq, @debug.Debug)

///|
pub extend EntropySummary with Eq::{equal, not_equal}

///|
pub extend EntropySummary with @debug.Debug::{to_repr}

///|
pub fn EntropySummary::density_per_kilo(self : EntropySummary) -> Double {
  if self.text_units == 0 {
    return 0.0
  }
  self.sensitive_chars.to_double() * 1000.0 / self.text_units.to_double()
}

///|
pub fn EntropySummary::needs_review(self : EntropySummary) -> Bool {
  self.very_high > 0 || self.high > 0
}
