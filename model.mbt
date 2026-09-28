///|
/// Detection categories intentionally stay small and auditable. This library
/// detects structured secrets and common identifiers; it is not an NLP system.
pub(all) enum SensitiveKind {
  AccessToken
  BearerToken
  Jwt
  CredentialAssignment
  Email
  Ipv4
  PaymentCard
  PrivateKey
  UrlCredential
  CustomSecret
} derive(Eq, @debug.Debug)

///|
pub fn SensitiveKind::to_string(self : SensitiveKind) -> String {
  match self {
    AccessToken => "ACCESS_TOKEN"
    BearerToken => "BEARER_TOKEN"
    Jwt => "JWT"
    CredentialAssignment => "CREDENTIAL"
    Email => "EMAIL"
    Ipv4 => "IPV4"
    PaymentCard => "PAYMENT_CARD"
    PrivateKey => "PRIVATE_KEY"
    UrlCredential => "URL_CREDENTIAL"
    CustomSecret => "CUSTOM_SECRET"
  }
}

///|
pub(all) enum Confidence {
  High
  Medium
} derive(Eq, @debug.Debug)

///|
/// Half-open UTF-16 offsets. A finding never stores or returns the matched
/// value, making reports safer to log than the original input.
pub(all) struct Finding {
  kind : SensitiveKind
  start : Int
  end : Int
  confidence : Confidence
} derive(Eq, @debug.Debug)

///|
pub(all) enum RedactionStyle {
  Marker
  Typed
  PreserveLast4
} derive(Eq, @debug.Debug)

///|
/// A policy controls which detector families run. Known credentials are always
/// enabled because suppressing them creates surprising leak paths.
pub(all) struct ScanPolicy {
  detect_email : Bool
  detect_ipv4 : Bool
  detect_payment_card : Bool
} derive(Eq, @debug.Debug)

///|
pub fn ScanPolicy::secrets_only() -> ScanPolicy {
  { detect_email: false, detect_ipv4: false, detect_payment_card: false, }
}

///|
pub fn ScanPolicy::standard() -> ScanPolicy {
  { detect_email: true, detect_ipv4: true, detect_payment_card: true, }
}

///|
pub(all) struct RedactionResult {
  text : String
  findings : Array[Finding]
  changed : Bool
} derive(Eq, @debug.Debug)

///|
pub(all) struct BatchSummary {
  lines : Int
  mut changed_lines : Int
  mut findings : Int
  mut access_tokens : Int
  mut bearer_tokens : Int
  mut jwts : Int
  mut credentials : Int
  mut emails : Int
  mut ipv4s : Int
  mut payment_cards : Int
  mut private_keys : Int
  mut url_credentials : Int
  mut custom_secrets : Int
} derive(Eq, @debug.Debug)

///|
/// A caller-supplied exact value that should never leave the process. Rules
/// shorter than four UTF-16 code units are ignored to limit accidental broad
/// matches. The label is metadata only and never appears in output markers.
pub(all) struct CustomRule {
  label : String
  value : String
} derive(Eq, @debug.Debug)

///|
/// Domain-neutral structured field adapter. `path` may be a JSON pointer,
/// dotted property path, form field name, or database column name.
pub(all) struct StructuredField {
  path : String
  value : String
} derive(Eq, @debug.Debug)

///|
pub(all) struct StructuredFieldResult {
  path : String
  value : String
  findings : Array[Finding]
  changed : Bool
  sensitive_path : Bool
} derive(Eq, @debug.Debug)

///|
pub(all) struct StructuredResult {
  fields : Array[StructuredFieldResult]
  changed_fields : Int
  findings : Int
} derive(Eq, @debug.Debug)

///|
pub(all) struct BatchResult {
  lines : Array[String]
  summary : BatchSummary
} derive(Eq, @debug.Debug)
