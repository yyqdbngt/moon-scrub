///|
/// Streaming scanner for input that arrives in chunks: log tailing, socket
/// reads, or prompt fragments. Findings carry absolute offsets into the whole
/// stream, never into the current chunk.
///
/// The scanner keeps an `overlap`-sized tail of unseen data so secrets that
/// straddle a chunk boundary are still detected. Correctness holds for any
/// secret whose full span is no longer than `overlap`; longer spans can be
/// split and missed, so pick `overlap` above the largest expected secret (PEM
/// private-key blocks are the usual ceiling; the default fits 8 KB keys).
struct ChunkScanner {
  config : ScanConfig
  overlap : Int
  mut buffer : String
  mut base : Int
  mut finished : Bool
}

///|
/// Build a chunked scanner. `overlap` is clamped to at least 64 code units.
pub fn ChunkScanner::new(
  config? : ScanConfig = ScanConfig::standard(),
  overlap? : Int = 8192,
) -> ChunkScanner {
  {
    config,
    overlap: if overlap < 64 {
      64
    } else {
      overlap
    },
    buffer: "",
    base: 0,
    finished: false,
  }
}

///|
/// Consume one chunk and return every finding whose end position is settled:
/// at least `overlap` code units of later data exist, so no future chunk can
/// extend or start a match overlapping it.
pub fn ChunkScanner::push(
  self : ChunkScanner,
  chunk : String,
) -> Array[Finding] {
  if self.finished || chunk.length() == 0 {
    return []
  }
  self.buffer += chunk
  let limit = self.buffer.length() - self.overlap
  if limit <= 0 {
    return []
  }
  let findings = scan_with_config(self.buffer, self.config)
  let settled : Array[Finding] = []
  let mut drop = limit
  for finding in findings {
    if finding.end <= limit {
      settled.push({
        kind: finding.kind,
        start: self.base + finding.start,
        end: self.base + finding.end,
        confidence: finding.confidence,
      })
      drop = finding.end
    } else {
      break
    }
  }
  // `scan_with_config` returns disjoint, start-ordered findings, so dropping
  // through the last settled end can never cut into a pending match.
  self.base += drop
  self.buffer = self.buffer[drop:].to_owned()
  settled
}

///|
/// Push complete log lines with their newline included and collect settled
/// findings. Equivalent to one push per line, but a single buffer append.
pub fn ChunkScanner::push_lines(
  self : ChunkScanner,
  lines : Array[String],
) -> Array[Finding] {
  let batch = StringBuilder()
  for line in lines {
    batch.write_string(line)
    batch.write_char(Int::unsafe_to_char(10))
  }
  self.push(batch.to_string())
}

///|
/// Flush the remaining tail and close the stream. Chunks pushed afterwards
/// are ignored.
pub fn ChunkScanner::finish(self : ChunkScanner) -> Array[Finding] {
  if self.finished {
    return []
  }
  self.finished = true
  let findings = scan_with_config(self.buffer, self.config)
  let out : Array[Finding] = []
  for finding in findings {
    out.push({
      kind: finding.kind,
      start: self.base + finding.start,
      end: self.base + finding.end,
      confidence: finding.confidence,
    })
  }
  self.buffer = ""
  self.base = 0
  out
}
