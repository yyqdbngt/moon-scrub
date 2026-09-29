# Moon Scrub

Offline sensitive-data detection and redaction for MoonBit applications.
Findings contain category, confidence, and UTF-16 offsets, but never retain the
matched value.

Version `0.1.0` is published on MoonCakes. Install it with
`moon add yyqdbngt/moon_scrub`.

## Public API

Scanning and redaction:

- `scan(text, policy~) -> Array[Finding]`
- `scan_with_config(text, config) -> Array[Finding]`
- `scan_with_rules(text, rules, policy~) -> Array[Finding]`
- `scan_full(text, rules, config) -> Array[Finding]`
- `redact(text, style~, policy~) -> RedactionResult`
- `redact_with_config(text, config, style~) -> RedactionResult`
- `redact_full(text, rules, config, style~) -> RedactionResult`
- `redact_with_rules(text, rules, style~, policy~) -> RedactionResult`
- `verify_clean(text, policy~) -> Bool`
- `verify_clean_with_config(text, config) -> Bool`
- `redact_batch(lines, style~, policy~) -> BatchResult`
- `redact_batch_with_config(lines, config, style~) -> BatchResult`
- `redact_fields(fields, style~, policy~) -> StructuredResult`
- `redact_fields_with_config(fields, config, style~) -> StructuredResult`
- `redact_json(text, config~, style~) -> JsonRedactionResult`
- `redact_json_with_rules(text, rules, config~, style~) -> JsonRedactionResult`

Streaming:

- `ChunkScanner::new(config~, overlap~)`
- `ChunkScanner::push(chunk) -> Array[Finding]`
- `ChunkScanner::push_lines(lines) -> Array[Finding]`
- `ChunkScanner::finish() -> Array[Finding]`

Reporting and exceptions:

- `findings_summary(text, config~) -> Array[KindCount]`
- `explain(text, config~) -> Array[String]`
- `scan_except(text, keep, config~) -> Array[Finding]`
- `redact_except(text, keep, style~, config~) -> RedactionResult`

Configuration:

- `ScanPolicy::secrets_only()` and `ScanPolicy::standard()`
- `ScanConfig::secrets_only()` and `ScanConfig::standard()`: per-family
  switches, false-positive suppressor toggles, and extra `TokenPrefixRule`
  prefixed-token rules
- `CustomRule` exact-value rules

Detectors cover structured access tokens across GitHub, GitLab, Slack, AWS,
Google, Stripe, Anthropic, OpenAI-style, SendGrid, Doppler and npm prefixes,
plus bearer credentials, JWTs, sensitive assignments, email addresses, IPv4
addresses, private-key blocks, URL credentials, and Luhn-valid payment cards
with major-network BIN prefixes. This is a deterministic helper, not a
complete DLP or compliance system. See the repository README and security
model for limitations.
