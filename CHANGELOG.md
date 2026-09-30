# Changelog

## 0.4.0 — 2026-09-30

- PatternRule shape rules: prefix plus a constrained character class
  (alnum-undash, hex variants, base64url, digits) inside a min/max
  total-length window, for secrets whose alphabet is narrower than
  generic token characters; a match stands only when the class owns the
  whole run. Feeds the ACCESS_TOKEN family via
  ScanConfig.extra_patterns.
- Opt-in high-entropy secret detection: runs of 40+ credential-alphabet
  characters with Shannon entropy at or above 4.75 bits per character
  report as HIGH_ENTROPY_SECRET (medium confidence). The threshold is
  calibrated to sit above English prose (~4.5) and base64-encoded prose
  (~4.7) and below generated keys (~4.8+); enabled with
  detect_high_entropy, off by default.
- New token prefixes: lin_api_ (Linear), glc_ (Grafana Cloud), cko_
  (Checkout.com), with vectors and the Python reference in lockstep.
- explain_json: the explain report as a JSON array (kind, offsets,
  confidence; sorted keys; integer-spelled numbers) for report
  pipelines.

## 0.3.0 — 2026-09-29

Fifty-commit push: thirteen new detector families, a reporting and
exception API layer, performance work, and the infrastructure that turns
the vector file into a proven cross-language contract. Verified on
wasm, wasm-gc, js and native under moonc 0.10.14.

Detectors:

- Chinese resident identity numbers with GB 11643 checksum and
  calendar-valid birth date (checksum-passing fabrications rejected);
  ordered before card scanning so Mastercard-overlapping area codes
  resolve to the identity finding.
- EUI-48 MAC addresses (colon or hyphen, consistent separator), canonical
  UUIDs, IPv6 literals with strict RFC 4291 run re-validation, opt-in
  E.164 phone numbers, SSH public key lines, PEM certificate and CSR
  blocks, Ethereum and bech32 wallet shapes, Slack and Discord incoming
  webhook URLs with structural path validation, HTTP Basic
  authorization blobs, and ENCRYPTED/PGP/DSA private key headers.
- Sensitive key list extended to Azure/AWS connection-string spellings
  (including camel-case SharedAccessKey), passphrase, credential,
  refresh_token, session_key and more; JSON-style quoted keys
  ("password": value) now match, with quoted markers skipped for
  idempotence.

Configuration and API:

- ScanConfig::pii_only preset; redact_batch_with_config,
  redact_fields_with_config, verify_clean_with_rules,
  redact_json_with_rules.
- findings_summary (deterministic kind-ordered counts without redacted
  text), explain (value-free per-finding report lines), scan_except and
  redact_except for caller-certified safe literals,
  ChunkScanner::push_lines, BatchResult.changed_indices,
  JsonRedactionResult::paths, Confidence::to_string.
- Opt-in suppress_example_domains drops documentation-domain emails.

Performance:

- Allocation-free prefix comparison (batch throughput roughly doubled),
  one shared lowercase pass for the four case-insensitive detectors,
  StringBuilder rebuild for redaction output and the streaming buffer,
  in-place email domain shape checks, and scan.mbt split into per-family
  modules.

Streaming correctness (found by the new property tests):

- StringBuilder::to_string hands off its backing array when full; the
  streaming buffer now re-seeds after every materialization.
- Sliding the window to an unsettled finding's start cuts the trigger
  context (the password= key, Bearer word, URL scheme) so assignments
  could never settle; the window retains a 32-code-unit context margin
  and emitted findings are deduplicated when the retreat re-shows them.
- Both defects were invisible to the fixed-sample tests because their
  corpus never exceeded the overlap window.

Infrastructure:

- Python reference scanner implementing the full vector contract; CI
  runs it as a differential gate on every push (all vectors match).
- pkg.generated.mbti API snapshot checked in and gated in CI; vector
  generator emits moon-fmt-stable output; json-pipeline and
  stream-pipeline examples run on every backend; bench gained a JSON
  throughput mode; performance methodology and cross-language porting
  guides added.

Fixes:

- Amex 4-6-5 spaced grouping (3782 822463 10005) now redacts like the
  unspaced form; leading-zero IPv4 octets are rejected as version noise;
  PEM footers stop at the closing dash run instead of swallowing
  same-line prose; redact_batch_with_config now counts changed_lines.

## 0.2.0 — 2026-09-29

Everything from the 0.1.0 proposal's follow-up plan, plus fixes found on the
way. Developed against moonc 0.10.14 and verified on wasm, wasm-gc, js and
native.

- Wider token coverage: GitHub (ghp_/gho_/ghu_/ghs_/ghr_/gha_/github_pat_),
  GitLab glpat-, Slack (xoxb-/xoxp-/xoxc-/xoxa-/xoxr-), AWS AKIA/ASIA, Google
  AIza, Stripe (sk_live_/rk_live_/pk_live_), Anthropic sk-ant-, OpenAI-style
  sk-, SendGrid SG., Doppler (dop_v1_/dop_v2_), npm npm_.
- Configurable rules: `ScanConfig` switches every detector family on or off,
  toggles the false-positive suppressors, and accepts extra `TokenPrefixRule`
  prefixed-token rules; `scan_with_config`, `redact_with_config`,
  `redact_full` and `verify_clean_with_config` run under it. Existing
  `ScanPolicy` entry points keep their behaviour.
- False-positive suppression: IPv4 look-alikes glued into version tokens
  (`v1.2.3.4`, `2.0.0.1rc1`) are no longer reported; Luhn-valid digit runs
  outside major card BIN prefixes are treated as order identifiers. Both
  suppressors can be turned off for recall. Bearer values that are already
  redaction markers are skipped, fixing a `PreserveLast4` idempotence hole.
- Structured JSON adaptation: `redact_json` parses with `moonbitlang/core`
  json, redacts every string leaf (sensitive paths fail closed), reports
  findings by JSON-pointer-like path, and emits compact deterministic output
  with RFC 8785-style sorted keys. Malformed input fails closed to plain
  text scanning.
- Streaming chunked scanning: `ChunkScanner` accepts chunks, keeps an
  `overlap`-sized window so boundary-straddling secrets survive, returns
  findings with absolute stream offsets, and matches whole-text scanning for
  any secret no longer than the window.
- Cross-language test vectors: `testvectors/vectors.json` plus
  `scripts/gen_vectors.py` generate per-vector MoonBit assertions; CI checks
  the generated file stays in sync. Ports to other languages assert the same
  tuples.
- Strict performance benchmark: `examples/bench` reports deterministic-corpus
  throughput and per-line cost on all four backends, and enforces a
  linearity gate against quadratic rescanning regressions.
- Fixed: card scanning could glue a neighbouring number onto a candidate
  through unbounded space swallowing (`10.0.0.1 4111111111111111` was missed);
  spaces are now only accepted at 4/8/12-digit group boundaries.
- Fixed: sentence-ending IPv4 (`peer 10.0.0.8.`) was swallowed into a
  five-component run and never reported; the run parser now tolerates one
  trailing dot.
- Performance: prefix matching no longer allocates substring slices on the
  hot path, roughly doubling batch throughput.
- Toolchain: migrated to moonc 0.10.14 conventions (explicit `pub extend`
  trait declarations, qualified references in black-box tests); CI pins the
  same version.

## 0.1.0 — 2026-09-28

- Initial structured-secret, email, IPv4 and Luhn-valid card detection.
- Safe findings that omit matched values.
- Three redaction styles, overlap merging, idempotence and clean verification.
- Batch summaries and a 10,000-line deterministic integrity test.
- Published to MoonCakes and verified from an independent consumer module.
