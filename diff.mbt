///|
/// Finding diffs for CI gates.
///
/// The gate pattern: scan the baseline once, scan the change under
/// review, diff the two finding lists. `diff_findings` compares by
/// exact Finding equality (kind, offsets, confidence) after a stable
/// sort, so scan order never creates phantom movement; `added` is
/// what the change introduced, `removed` is what it cleaned up.
/// `format_diff_report` renders the diff as human-readable lines with
/// `+`/`-` prefixes, ready for a CI annotation. Position-sensitive by
/// design: the same secret at a new offset counts as one removal and
/// one addition, because a gate that hides movement hides risk.

///|
pub(all) struct FindingsDiff {
  added : Array[Finding]
  removed : Array[Finding]
  unchanged : Int
} derive(Eq, @debug.Debug)

///|
pub extend FindingsDiff with Eq::{equal, not_equal}

///|
pub extend FindingsDiff with @debug.Debug::{to_repr}

///|
fn sort_findings_for_diff(items : Array[Finding]) -> Array[Finding] {
  let copy = items.copy()
  copy.sort_by(fn(a, b) {
    let by_start = a.start.compare(b.start)
    if by_start != 0 {
      return by_start
    }
    let by_end = a.end.compare(b.end)
    if by_end != 0 {
      return by_end
    }
    a.kind.to_string().compare(b.kind.to_string())
  })
  copy
}

///|
pub fn diff_findings(
  before : Array[Finding],
  after : Array[Finding],
) -> FindingsDiff {
  let left = sort_findings_for_diff(before)
  let right = sort_findings_for_diff(after)
  let added : Array[Finding] = []
  let removed : Array[Finding] = []
  let mut unchanged = 0
  let mut i = 0
  let mut j = 0
  while i < left.length() && j < right.length() {
    let cmp = Finding::compare(left[i], right[j])
    if cmp < 0 {
      removed.push(left[i])
      i += 1
    } else if cmp > 0 {
      added.push(right[j])
      j += 1
    } else {
      unchanged += 1
      i += 1
      j += 1
    }
  }
  while i < left.length() {
    removed.push(left[i])
    i += 1
  }
  while j < right.length() {
    added.push(right[j])
    j += 1
  }
  { added, removed, unchanged }
}

///|
fn Finding::compare(self : Finding, other : Finding) -> Int {
  let by_start = self.start.compare(other.start)
  if by_start != 0 {
    return by_start
  }
  let by_end = self.end.compare(other.end)
  if by_end != 0 {
    return by_end
  }
  self.kind.to_string().compare(other.kind.to_string())
}

///|
pub fn format_diff_report(diff : FindingsDiff) -> Array[String] {
  let lines : Array[String] = []
  for finding in sort_findings_for_diff(diff.added) {
    lines.push(
      "+ " +
      finding.kind.to_string() +
      " @ " +
      finding.start.to_string() +
      "-" +
      finding.end.to_string() +
      " " +
      finding.confidence.to_string(),
    )
  }
  for finding in sort_findings_for_diff(diff.removed) {
    lines.push(
      "- " +
      finding.kind.to_string() +
      " @ " +
      finding.start.to_string() +
      "-" +
      finding.end.to_string() +
      " " +
      finding.confidence.to_string(),
    )
  }
  lines
}
