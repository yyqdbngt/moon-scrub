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
  detect_phone : Bool
  detect_ipv6 : Bool
  detect_uuid : Bool
  detect_mac : Bool
  suppress_version_ipv4 : Bool
  require_known_card_prefix : Bool
  extra_prefixes : Array[TokenPrefixRule]
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
    detect_phone: false,
    detect_ipv6: true,
    detect_uuid: true,
    detect_mac: true,
    suppress_version_ipv4: true,
    require_known_card_prefix: true,
    extra_prefixes: [],
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
    detect_phone: false,
    detect_ipv6: false,
    detect_uuid: false,
    detect_mac: false,
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
