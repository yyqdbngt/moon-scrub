///|
/// Character vocabulary a custom pattern rule matches after its prefix.
pub(all) enum CharClass {
  AlnumUndash
  HexLower
  HexAny
  Base64Url
  Digits
} derive(Eq, @debug.Debug)

///|
pub extend CharClass with Eq::{equal, not_equal}

///|
pub extend CharClass with @debug.Debug::{to_repr}

///|
/// A caller-defined shape rule: a prefix followed by `min_length` to
/// `max_length` total code units drawn from a character class. More
/// expressive than TokenPrefixRule when secrets carry a constrained
/// alphabet, e.g. lowercase-hex transaction ids or numeric tenant keys.
pub(all) struct PatternRule {
  prefix : String
  chars : CharClass
  min_length : Int
  max_length : Int
} derive(Eq, @debug.Debug)

///|
pub extend PatternRule with Eq::{equal, not_equal}

///|
pub extend PatternRule with @debug.Debug::{to_repr}

///|
/// A caller-defined prefixed-token rule. `min_length` is the minimum total
/// match length including the prefix. Prefixes shorter than two code units or
/// minimums below the prefix length are ignored to limit accidental broad
/// matches.
pub(all) struct TokenPrefixRule {
  prefix : String
  min_length : Int
} derive(Eq, @debug.Debug)

///|
pub extend TokenPrefixRule with Eq::{equal, not_equal}

///|
pub extend TokenPrefixRule with @debug.Debug::{to_repr}

///|
/// Full detector configuration. Every detector family can be switched off
/// independently, and the false-positive suppressors can be relaxed by callers
/// who prefer recall over precision. Turning credential detectors off creates
/// surprising leak paths, so the preset constructors keep them on.
pub(all) struct ScanConfig {
  detect_access_token : Bool
  detect_bearer : Bool
  detect_jwt : Bool
  detect_private_key : Bool
  detect_url_credential : Bool
  detect_assignment : Bool
  detect_email : Bool
  detect_ipv4 : Bool
  detect_payment_card : Bool
  detect_resident_id : Bool
  detect_webhook : Bool
  detect_wallet : Bool
  detect_public_key : Bool
  detect_phone : Bool
  detect_ipv6 : Bool
  detect_uuid : Bool
  detect_mac : Bool
  suppress_version_ipv4 : Bool
  require_known_card_prefix : Bool
  /// Drop email findings on IANA-reserved documentation domains
  /// (example.com/net/org and the TLDs .test/.example/.invalid), which
  /// dominate test-suite output and drown real findings.
  suppress_example_domains : Bool
  extra_prefixes : Array[TokenPrefixRule]
  extra_patterns : Array[PatternRule]
} derive(Eq, @debug.Debug)

///|
pub extend ScanConfig with Eq::{equal, not_equal}

///|
pub extend ScanConfig with @debug.Debug::{to_repr}

///|
/// All detectors on with false-positive suppression enabled.
pub fn ScanConfig::standard() -> ScanConfig {
  {
    detect_access_token: true,
    detect_bearer: true,
    detect_jwt: true,
    detect_private_key: true,
    detect_url_credential: true,
    detect_assignment: true,
    detect_email: true,
    detect_ipv4: true,
    detect_payment_card: true,
    detect_resident_id: true,
    detect_webhook: true,
    detect_wallet: true,
    detect_public_key: true,
    detect_phone: false,
    detect_ipv6: true,
    detect_uuid: true,
    detect_mac: true,
    suppress_version_ipv4: true,
    require_known_card_prefix: true,
    suppress_example_domains: false,
    extra_prefixes: [],
    extra_patterns: [],
  }
}

///|
/// Only credential families run; emails, IPv4 addresses and payment cards are
/// left untouched.
pub fn ScanConfig::secrets_only() -> ScanConfig {
  {
    ..ScanConfig::standard(),
    detect_email: false,
    detect_ipv4: false,
    detect_payment_card: false,
    detect_resident_id: false,
    detect_webhook: false,
    detect_wallet: false,
    detect_public_key: false,
    detect_phone: false,
    detect_ipv6: false,
    detect_uuid: false,
    detect_mac: false,
  }
}

///|
/// Only the personal-identifier families run; every credential detector is
/// off. Useful for telemetry scrubbing where secrets are handled elsewhere.
pub fn ScanConfig::pii_only() -> ScanConfig {
  {
    ..ScanConfig::standard(),
    detect_access_token: false,
    detect_bearer: false,
    detect_jwt: false,
    detect_private_key: false,
    detect_url_credential: false,
    detect_assignment: false,
    detect_public_key: false,
    detect_webhook: false,
  }
}

///|
/// Bridge the small `ScanPolicy` surface onto the full configuration so older
/// call sites keep their semantics, including the new suppressors.
fn ScanPolicy::to_config(self : ScanPolicy) -> ScanConfig {
  {
    ..ScanConfig::secrets_only(),
    detect_email: self.detect_email,
    detect_ipv4: self.detect_ipv4,
    detect_payment_card: self.detect_payment_card,
  }
}
