///|
// Detector family module, split out of scan.mbt for navigability.

///|
fn scan_bearer(text : String, lower : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 7 < text.length(); i = i + 1 {
    if starts_at(lower, i, "bearer ") {
      let start = i + 7
      let end = trim_value_end(text, start)
      // Skip previously produced markers so repeated redaction stays idempotent
      // under every style, including PreserveLast4.
      if end - start >= 8 && !starts_at(text, start, "[REDACTED") {
        push_finding(out, BearerToken, start, end, High)
      }
    }
  }
}

///|
fn scan_jwt(text : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 12 < text.length(); i = i + 1 {
    if starts_at(text, i, "eyJ") {
      let mut end = i
      let mut dots = 0
      while end < text.length() {
        let c = text[end].to_int()
        if c == 46 {
          dots += 1
          end += 1
        } else if is_base64url(c) {
          end += 1
        } else {
          break
        }
      }
      if dots == 2 && end - i >= 16 {
        push_finding(out, Jwt, i, end, High)
      }
    }
  }
}

///|
/// A PEM footer runs to the closing `-----` dash run, not to end of line:
/// trailing prose on the same line must stay outside the finding. Falls back
/// to line end when the footer is truncated.
fn pem_footer_end(text : String, from : Int) -> Int {
  let mut k = from
  while k + 5 <= text.length() && !starts_at(text, k, "-----") {
    k += 1
  }
  if k + 5 <= text.length() {
    return k + 5
  }
  let mut e = from
  while e < text.length() && text[e].to_int() != 10 && text[e].to_int() != 13 {
    e += 1
  }
  e
}

///|
fn scan_private_keys(text : String, out : Array[Finding]) -> Unit {
  let begins = [
    "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----BEGIN DSA PRIVATE KEY-----",
  ]
  for i = 0; i < text.length(); i = i + 1 {
    for begin in begins {
      if starts_at(text, i, begin) {
        let mut end = i + begin.length()
        let marker = "-----END"
        while end < text.length() && !starts_at(text, end, marker) {
          end += 1
        }
        if end < text.length() {
          end = pem_footer_end(text, end + 7)
        } else {
          end = text.length()
        }
        push_finding(out, PrivateKey, i, end, High)
      }
    }
  }
}

///|
/// PEM certificate and CSR blocks: everything from a BEGIN marker through
/// the end of its END line is public material worth flagging for hygiene.
fn scan_certificates(text : String, out : Array[Finding]) -> Unit {
  let begins = [
    "-----BEGIN CERTIFICATE-----", "-----BEGIN TRUSTED CERTIFICATE-----", "-----BEGIN CERTIFICATE REQUEST-----",
  ]
  for i = 0; i < text.length(); i = i + 1 {
    for begin in begins {
      if starts_at(text, i, begin) {
        let mut end = i + begin.length()
        while end < text.length() && !starts_at(text, end, "-----END") {
          end += 1
        }
        if end < text.length() {
          end = pem_footer_end(text, end + 7)
        } else {
          end = text.length()
        }
        push_finding(out, PublicKey, i, end, High)
      }
    }
  }
}

///|
/// Public key material: `ssh-rsa`, `ssh-ed25519`, and `ecdsa-sha2-*` key
/// lines whose base64 body is at least fifty characters. Public keys are not
/// secrets, but they identify infrastructure and are flagged for hygiene.
fn scan_public_keys(text : String, out : Array[Finding]) -> Unit {
  let heads = ["ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"]
  for i = 0; i < text.length(); i = i + 1 {
    for head in heads {
      if starts_at(text, i, head) {
        let body_start = i + head.length()
        let mut end = body_start
        while end < text.length() && is_base64url(text[end].to_int()) {
          end += 1
        }
        if end - body_start >= 50 {
          push_finding(out, PublicKey, i, end, High)
        }
      }
    }
  }
  scan_certificates(text, out)
}

///|
fn scan_url_credentials(text : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 3 < text.length(); i = i + 1 {
    if starts_at(text, i, "://") {
      let authority_start = i + 3
      let mut at = authority_start
      let mut colon = -1
      while at < text.length() &&
            text[at].to_int() != 47 &&
            text[at].to_int() != 32 &&
            text[at].to_int() != 9 {
        if text[at].to_int() == 58 && colon < 0 {
          colon = at
        }
        if text[at].to_int() == 64 {
          break
        }
        at += 1
      }
      if at < text.length() &&
        text[at].to_int() == 64 &&
        colon > authority_start &&
        colon + 1 < at {
        push_finding(out, UrlCredential, authority_start, at, High)
      }
    }
  }
}

///|
fn sensitive_key(key : String) -> Bool {
  let k = ascii_lower(key)
  k == "password" ||
  k == "passwd" ||
  k == "pwd" ||
  k == "secret" ||
  k == "token" ||
  k == "api_key" ||
  k == "apikey" ||
  k == "private_key" ||
  k == "authorization" ||
  k == "client_secret" ||
  k == "account_key" ||
  k == "shared_access_key" ||
  k == "sharedaccesskey" ||
  k == "secret_key" ||
  k == "private_token" ||
  k == "passphrase" ||
  k == "credential" ||
  k == "auth_token" ||
  k == "refresh_token" ||
  k == "session_key" ||
  k == "aws_secret_access_key"
}

///|
fn scan_assignments(
  text : String,
  lower : String,
  out : Array[Finding],
) -> Unit {
  let mut i = 0
  while i < text.length() {
    if is_ascii_letter(text[i].to_int()) || text[i].to_int() == 95 {
      let key_start = i
      while i < text.length() &&
            (
              is_ascii_alnum(text[i].to_int()) ||
              text[i].to_int() == 95 ||
              text[i].to_int() == 45
            ) {
        i += 1
      }
      let key = text[key_start:i].to_owned()
      let mut sep = i
      while sep < text.length() &&
            (text[sep].to_int() == 32 || text[sep].to_int() == 9) {
        sep += 1
      }
      if sensitive_key(key) &&
        sep < text.length() &&
        (text[sep].to_int() == 61 || text[sep].to_int() == 58) {
        let mut start = sep + 1
        while start < text.length() &&
              (text[start].to_int() == 32 || text[start].to_int() == 9) {
          start += 1
        }
        if ascii_lower(key) == "authorization" &&
          starts_at(lower, start, "bearer ") {
          i = start + 7
        } else if ascii_lower(key) == "authorization" &&
          starts_at(lower, start, "basic ") {
          // The Basic-auth detector owns the base64 blob; do not double-report.
          i = start + 6
        } else if starts_at(text, start, "[REDACTED") {
          i = start + 9
        } else if start < text.length() &&
          (text[start].to_int() == 34 || text[start].to_int() == 39) {
          let quote = text[start].to_int()
          start += 1
          let mut end = start
          while end < text.length() && text[end].to_int() != quote {
            end += 1
          }
          push_finding(out, CredentialAssignment, start, end, High)
        } else {
          push_finding(
            out,
            CredentialAssignment,
            start,
            trim_value_end(text, start),
            High,
          )
        }
      }
    } else {
      i += 1
    }
  }
}

///|
/// HTTP Basic credentials in `Authorization: Basic <base64>` headers. The
/// base64 blob decodes to user:password, so the whole value is secret even
/// though no single word looks like one.
fn scan_basic_auth(text : String, lower : String, out : Array[Finding]) -> Unit {
  for i = 0; i + 20 < text.length(); i = i + 1 {
    if starts_at(lower, i, "authorization: basic ") ||
      starts_at(lower, i, "authorization basic ") {
      let start = i + 21
      let mut end = start
      while end < text.length() && is_base64url(text[end].to_int()) {
        end += 1
      }
      if end - start >= 16 && !starts_at(text, start, "[REDACTED") {
        push_finding(out, CredentialAssignment, start, end, High)
      }
    }
  }
}

///|
/// Incoming-webhook URLs: Slack `hooks.slack.com/services/T.../B.../token`
/// and Discord `discord.com/api/webhooks/<id>/<token>`. The path structure
/// and segment shapes are validated, not just the host name.
fn scan_webhook_urls(
  text : String,
  lower : String,
  out : Array[Finding],
) -> Unit {
  let anchors = ["hooks.slack.com/services/", "discord.com/api/webhooks/"]
  for i = 0; i < text.length(); i = i + 1 {
    for anchor in anchors {
      if starts_at(lower, i, anchor) {
        let start = i
        let mut end = i + anchor.length()
        let mut segments = 1
        let mut seg_start = end
        let mut shapes_ok = true
        let seg_lengths : Array[Int] = []
        while end < text.length() {
          let c = text[end].to_int()
          if is_ascii_alnum(c) || c == 45 || c == 95 {
            end += 1
          } else if c == 47 && segments < 4 {
            seg_lengths.push(end - seg_start)
            segments += 1
            end += 1
            seg_start = end
          } else {
            break
          }
        }
        seg_lengths.push(end - seg_start)
        if anchor == "hooks.slack.com/services/" {
          shapes_ok = segments == 3 &&
            seg_lengths[0] >= 8 &&
            seg_lengths[0] <= 12 &&
            seg_lengths[1] >= 8 &&
            seg_lengths[1] <= 12 &&
            seg_lengths[2] >= 20
        } else {
          shapes_ok = segments == 2 &&
            seg_lengths[0] >= 17 &&
            seg_lengths[1] >= 50
        }
        if shapes_ok {
          push_finding(out, WebhookUrl, start, end, High)
        }
      }
    }
  }
}
