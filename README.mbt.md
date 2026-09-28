# Moon Scrub

Offline sensitive-data detection and redaction for MoonBit applications.
Findings contain category, confidence, and UTF-16 offsets, but never retain the
matched value.

Version `0.1.0` is published on MoonCakes. Install it with
`moon add yyqdbngt/moon_scrub@0.1.0`.

## Public API

- `scan(text, policy~) -> Array[Finding]`
- `redact(text, style~, policy~) -> RedactionResult`
- `verify_clean(text, policy~) -> Bool`
- `redact_batch(lines, style~, policy~) -> BatchResult`
- `scan_with_rules(text, rules, policy~) -> Array[Finding]`
- `redact_with_rules(text, rules, style~, policy~) -> RedactionResult`
- `redact_fields(fields, style~, policy~) -> StructuredResult`
- `ScanPolicy::secrets_only()` and `ScanPolicy::standard()`

Detectors cover structured access tokens, bearer credentials, JWTs, sensitive
assignments, email addresses, IPv4 addresses, and Luhn-valid payment-card
candidates. This is a deterministic helper, not a complete DLP or compliance
system. See the repository README and security model for limitations.
