# Changelog

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
