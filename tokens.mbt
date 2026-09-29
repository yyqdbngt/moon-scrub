///|
// Detector family module, split out of scan.mbt for navigability.

///|
/// Recognized service token prefixes with per-family minimum total lengths.
/// All samples in tests are synthetic; real credentials never appear here.
fn builtin_token_specs() -> Array[TokenPrefixRule] {
  [
    { prefix: "github_pat_", min_length: 22, },
    { prefix: "sk-ant-", min_length: 15, },
    { prefix: "sk_live_", min_length: 16, },
    { prefix: "rk_live_", min_length: 16, },
    { prefix: "pk_live_", min_length: 16, },
    { prefix: "dop_v1_", min_length: 15, },
    { prefix: "dop_v2_", min_length: 15, },
    { prefix: "shpat_", min_length: 14, },
    { prefix: "shpca_", min_length: 14, },
    { prefix: "shppa_", min_length: 14, },
    { prefix: "ghp_", min_length: 12, },
    { prefix: "gho_", min_length: 12, },
    { prefix: "ghu_", min_length: 12, },
    { prefix: "ghs_", min_length: 12, },
    { prefix: "ghr_", min_length: 12, },
    { prefix: "gha_", min_length: 12, },
    { prefix: "xoxb-", min_length: 13, },
    { prefix: "xoxp-", min_length: 13, },
    { prefix: "xoxc-", min_length: 13, },
    { prefix: "xoxa-", min_length: 13, },
    { prefix: "xoxr-", min_length: 13, },
    { prefix: "glpat-", min_length: 14, },
    { prefix: "npm_", min_length: 12, },
    { prefix: "AIza", min_length: 20, },
    { prefix: "AKIA", min_length: 20, },
    { prefix: "ASIA", min_length: 20, },
    { prefix: "SG.", min_length: 20, },
    { prefix: "sk-", min_length: 11, },
  ]
}

///|
fn rule_first(rule : TokenPrefixRule) -> Int {
  rule.prefix[0].to_int()
}

///|
/// Bucket the rules by first character so the scan loop only compares a
/// position against candidates that can match at all.
fn bucket_specs(
  specs : Array[TokenPrefixRule],
) -> Array[Array[TokenPrefixRule]] {
  let buckets : Array[Array[TokenPrefixRule]] = []
  for _ in 0..<256 {
    buckets.push([])
  }
  for spec in specs {
    if spec.prefix.length() >= 2 && spec.min_length >= spec.prefix.length() {
      buckets[rule_first(spec)].push(spec)
    }
  }
  for bucket in buckets {
    sort_specs(bucket)
  }
  buckets
}

///|
/// Longest prefix first so `sk-ant-` wins over `sk-` at the same position.
fn sort_specs(items : Array[TokenPrefixRule]) -> Unit {
  for i = 1; i < items.length(); i = i + 1 {
    let value = items[i]
    let mut j = i
    while j > 0 && items[j - 1].prefix.length() < value.prefix.length() {
      items[j] = items[j - 1]
      j -= 1
    }
    items[j] = value
  }
}

///|
fn scan_prefixed_tokens(
  text : String,
  extra : Array[TokenPrefixRule],
  out : Array[Finding],
) -> Unit {
  let specs = builtin_token_specs()
  for rule in extra {
    specs.push(rule)
  }
  let buckets = bucket_specs(specs)
  for i = 0; i < text.length(); i = i + 1 {
    let code = text[i].to_int()
    // Every built-in prefix starts with an ASCII character; skip non-ASCII
    // code units instead of indexing past the bucket table.
    if code >= 256 {
      continue
    }
    let bucket = buckets[code]
    for spec in bucket {
      if starts_at(text, i, spec.prefix) {
        let mut end = i + spec.prefix.length()
        while end < text.length() && is_token_char(text[end].to_int()) {
          end += 1
        }
        if end - i >= spec.min_length {
          push_finding(out, AccessToken, i, end, High)
        }
        break
      }
    }
  }
}
