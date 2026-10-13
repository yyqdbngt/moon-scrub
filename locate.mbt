///|
/// Finding locations for editor and CI annotations.
///
/// Findings carry flat UTF-16 offsets, which machines love and humans
/// cannot navigate. `locate_findings` maps every finding to a 1-based
/// line and column: line starts are computed once and findings are
/// walked in start order, so the pass is linear in the text length
/// regardless of finding count. Lines split on \n only (the dominant
/// log and source-file convention); a finding that spans lines — a
/// private key block, for example — reports the line and column where
/// it starts. `format_location` renders the conventional
/// "line X, col Y" annotation text.

///|
pub(all) struct FindingLocation {
  finding : Finding
  line : Int
  column : Int
} derive(Eq, @debug.Debug)

///|
pub extend FindingLocation with Eq::{equal, not_equal}

///|
pub extend FindingLocation with @debug.Debug::{to_repr}

///|
pub fn locate_findings(
  text : String,
  findings : Array[Finding],
) -> Array[FindingLocation] {
  // Line starts in ascending order; offset 0 always begins line 1.
  let line_starts : Array[Int] = [0]
  for i = 0; i < text.length(); i = i + 1 {
    if text[i].to_int() == 10 {
      line_starts.push(i + 1)
    }
  }
  let ordered = findings.copy()
  ordered.sort_by(fn(a, b) { a.start.compare(b.start) })
  let located : Array[FindingLocation] = []
  let mut cursor = 0
  for finding in ordered {
    while cursor + 1 < line_starts.length() &&
          line_starts[cursor + 1] <= finding.start {
      cursor += 1
    }
    located.push({
      finding,
      line: cursor + 1,
      column: finding.start - line_starts[cursor] + 1,
    })
  }
  located
}

///|
pub fn format_location(location : FindingLocation) -> String {
  "line " +
  location.line.to_string() +
  ", col " +
  location.column.to_string() +
  ": " +
  location.finding.kind.to_string() +
  " (" +
  location.finding.confidence.to_string() +
  ")"
}
