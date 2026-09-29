# Moon Scrub

Offline sensitive-data detection and redaction for MoonBit applications.
Findings contain category, confidence, and UTF-16 offsets, but never retain the
matched value.

Version `0.1.0` is published on MoonCakes. Install it with
`moon add 123123213weqw/moon_scrub`.

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
bearer and Basic credentials, JWTs, sensitive assignments (including
JSON-style quoted keys), webhook URLs, email addresses, IPv4 and IPv6,
Luhn-valid payment cards with major-network BIN prefixes (Amex spacing
included), Chinese resident identity numbers with checksum validation, MAC
addresses, UUIDs, SSH public keys and certificate blocks, wallet addresses,
and opt-in E.164 phone numbers. This is a deterministic helper, not a
complete DLP or compliance system. See the repository README and security
model for limitations.
