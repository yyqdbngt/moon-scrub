#!/usr/bin/env python3
"""Reference scanner proving the cross-language vector contract.

Reads testvectors/vectors.json, runs an independent Python implementation
of the documented detector behaviour, and asserts that every vector's
expected kind/start/end/confidence tuples match. Ports to any language
can be validated the same way, which is what makes vectors.json a
cross-language contract rather than a MoonBit-local test.

Usage:
  python3 scripts/reference_scan.py            # run all vectors
  python3 scripts/reference_scan.py --quiet    # exit code only
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TOKEN_SPECS = [
    ("github_pat_", 22), ("sk-ant-", 15), ("sk_live_", 16), ("rk_live_", 16),
    ("pk_live_", 16), ("dop_v1_", 15), ("dop_v2_", 15), ("shpat_", 14),
    ("shpca_", 14), ("shppa_", 14), ("ghp_", 12), ("gho_", 12), ("ghu_", 12),
    ("ghs_", 12), ("ghr_", 12), ("gha_", 12), ("xoxb-", 13), ("xoxp-", 13),
    ("xoxc-", 13), ("xoxa-", 13), ("xoxr-", 13), ("glpat-", 14), ("npm_", 12),
    ("AIza", 20), ("AKIA", 20), ("ASIA", 20), ("SG.", 20), ("sk-", 11),
]
TOKEN_SPECS.sort(key=lambda p: -len(p[0]))

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "private_key", "authorization", "client_secret", "account_key",
    "shared_access_key", "sharedaccesskey", "secret_key", "private_token",
    "passphrase", "credential", "auth_token", "refresh_token", "session_key",
    "aws_secret_access_key",
}

PEM_PRIVATE = [
    "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN DSA PRIVATE KEY-----",
]
PEM_PUBLIC = [
    "-----BEGIN CERTIFICATE-----", "-----BEGIN TRUSTED CERTIFICATE-----",
    "-----BEGIN CERTIFICATE REQUEST-----",
]

TOKEN_CHARS = re.compile(r"[A-Za-z0-9._-]")


def push(out, kind, start, end, confidence):
    if start >= 0 and end > start:
        out.append((kind, start, end, confidence))


def scan_prefixed_tokens(text, out):
    for i in range(len(text)):
        for prefix, minimum in TOKEN_SPECS:
            if text.startswith(prefix, i):
                end = i + len(prefix)
                while end < len(text) and TOKEN_CHARS.match(text[end]):
                    end += 1
                if end - i >= minimum:
                    push(out, "ACCESS_TOKEN", i, end, "HIGH")
                break


def scan_bearer(text, out):
    for m in re.finditer(r"[Bb]earer ", text):
        start = m.end()
        end = start
        while end < len(text) and text[end] not in " \t\n\r,;\"'}]":
            end += 1
        if end - start >= 8 and not text.startswith("[REDACTED", start):
            push(out, "BEARER_TOKEN", start, end, "HIGH")


def scan_jwt(text, out):
    for m in re.finditer("eyJ", text):
        end, dots = m.start(), 0
        while end < len(text):
            c = text[end]
            if c == ".":
                dots += 1
                end += 1
            elif c.isalnum() or c in "-_=":
                end += 1
            else:
                break
        if dots == 2 and end - m.start() >= 16:
            push(out, "JWT", m.start(), end, "HIGH")


def pem_end(text, marker_start, footer=False):
    if footer:
        k = marker_start + 7
        while k + 5 <= len(text) and not text.startswith("-----", k):
            k += 1
        if k + 5 <= len(text):
            return k + 5
        e = marker_start + 7
        while e < len(text) and text[e] not in "\n\r":
            e += 1
        return e
    end = marker_start
    while end < len(text) and not text.startswith("-----END", end):
        end += 1
    if end < len(text):
        return pem_end(text, end, footer=True)
    return len(text)


def scan_private_keys(text, out):
    for begin in PEM_PRIVATE:
        for m in re.finditer(re.escape(begin), text):
            push(out, "PRIVATE_KEY", m.start(), pem_end(text, m.start()), "HIGH")


def scan_certificates(text, out):
    for begin in PEM_PUBLIC:
        for m in re.finditer(re.escape(begin), text):
            push(out, "PUBLIC_KEY", m.start(), pem_end(text, m.start()), "HIGH")


def scan_ssh_public(text, out):
    for head in ("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-"):
        for m in re.finditer(re.escape(head), text):
            end = m.end()
            while end < len(text) and (text[end].isalnum() or text[end] in "-_=."):
                end += 1
            if end - m.end() >= 50:
                push(out, "PUBLIC_KEY", m.start(), end, "HIGH")


def scan_url_credentials(text, out):
    for m in re.finditer("://", text):
        authority = m.end()
        at, colon = authority, -1
        while at < len(text) and text[at] not in "/ \t":
            if text[at] == ":" and colon < 0:
                colon = at
            if text[at] == "@":
                break
            at += 1
        if at < len(text) and text[at] == "@" and authority < colon < at - 1:
            push(out, "URL_CREDENTIAL", authority, at, "HIGH")


def scan_assignments(text, out):
    for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_-]*", text):
        key = m.group(0)
        if key.lower() not in SENSITIVE_KEYS:
            continue
        sep = m.end()
        while sep < len(text) and text[sep] in " \t":
            sep += 1
        if sep >= len(text) or text[sep] not in "=:":
            continue
        start = sep + 1
        while start < len(text) and text[start] in " \t":
            start += 1
        low = text.lower()
        if key.lower() == "authorization" and low.startswith("bearer ", start):
            continue
        if key.lower() == "authorization" and low.startswith("basic ", start):
            continue
        if text.startswith("[REDACTED", start):
            continue
        if start < len(text) and text[start] in "\"'":
            quote = text[start]
            end = text.find(quote, start + 1)
            end = len(text) if end < 0 else end
            push(out, "CREDENTIAL", start + 1, end, "HIGH")
        else:
            end = start
            while end < len(text) and text[end] not in " \t\n\r,;\"'}]":
                end += 1
            push(out, "CREDENTIAL", start, end, "HIGH")


def scan_basic_auth(text, out):
    for m in re.finditer(r"[Aa]uthorization: [Bb]asic ", text):
        start = m.end()
        end = start
        while end < len(text) and (text[end].isalnum() or text[end] in "-_.="):
            end += 1
        if end - start >= 16 and not text.startswith("[REDACTED", start):
            push(out, "CREDENTIAL", start, end, "HIGH")


def scan_emails(text, out):
    for at, ch in enumerate(text):
        if ch != "@" or at < 1 or at + 3 >= len(text):
            continue
        start = at
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "!#$%&'*+-./?^_`{|}~"):
            start -= 1
        end = at + 1
        while end < len(text) and (text[end].isalnum() or text[end] in "-."):
            end += 1
        domain = text[at + 1:end]
        if start < at and len(domain) >= 3 and "." in domain[1:-1] and not domain.startswith(".") and not domain.endswith("."):
            push(out, "EMAIL", start, end, "HIGH")


def ipv4_octet(part):
    return part.isdigit() and len(part) <= 3 and int(part) <= 255


def ipv4_run_end(run):
    octets, part_start = 0, 0
    for i in range(len(run) + 1):
        if i == len(run) or run[i] == ".":
            if not ipv4_octet(run[part_start:i]):
                return -1
            octets += 1
            if octets == 4:
                if i == len(run):
                    return i
                if i + 1 == len(run):
                    return i
                return -1
            part_start = i + 1
    return -1


def scan_ipv4(text, out):
    for m in re.finditer(r"\d[\d.]*", text):
        run = m.group(0)
        valid = ipv4_run_end(run)
        if valid < 0:
            continue
        start, end = m.start(), m.start() + valid
        before = text[start - 1] if start > 0 else ""
        after = text[end] if end < len(text) else ""
        if (before.isalnum() or before in ".-_") or (after.isalnum() or after in "-_"):
            continue
        push(out, "IPV4", start, end, "MEDIUM")


def luhn_ok(digits):
    if not 13 <= len(digits) <= 19:
        return False
    total, alternate = 0, False
    for d in reversed(digits):
        v = d
        if alternate:
            v *= 2
            if v > 9:
                v -= 9
        total += v
        alternate = not alternate
    return total % 10 == 0


def known_bin(digits):
    if not digits:
        return False
    if digits[0] in (4, 5, 6):
        return True
    return len(digits) >= 2 and digits[0] * 10 + digits[1] in (34, 37)


def scan_cards(text, out):
    i = 0
    while i < len(text):
        if text[i].isdigit() and (i == 0 or not text[i - 1].isdigit()):
            digits, end = [], i
            while end < len(text):
                c = text[end]
                if c.isdigit():
                    digits.append(int(c))
                    end += 1
                elif end > i and text[end - 1].isdigit() and (
                        c == "-" or (c == " " and len(digits) in (4, 8, 10, 12))):
                    end += 1
                else:
                    break
            while end > i and text[end - 1] in " -":
                end -= 1
            if luhn_ok(digits) and known_bin(digits):
                push(out, "PAYMENT_CARD", i, end, "HIGH")
            i = max(end, i + 1)
        else:
            i += 1


WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ORDER = "10X98765432"


def scan_resident_ids(text, out):
    i = 0
    while i + 18 <= len(text):
        if text[i].isdigit() and (i == 0 or not text[i - 1].isalnum()):
            end = i + 18
            last = text[end - 1]
            body = text[i:end - 1]
            if body.isdigit() and (last.isdigit() or last in "Xx"):
                after = text[end] if end < len(text) else ""
                if after.isalnum() or after in "-_":
                    i += 1
                    continue
                checksum = ORDER[sum(int(d) * w for d, w in zip(body, WEIGHTS)) % 11]
                year, month, day = int(text[i + 6:i + 10]), int(text[i + 10:i + 12]), int(text[i + 12:i + 14])
                if checksum == last.upper() and 1900 <= year <= 2100 and 1 <= month <= 12:
                    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
                    dim = 29 if (month == 2 and leap) else (28 if month == 2 else (31 if month in (1, 3, 5, 7, 8, 10, 12) else 30))
                    if 1 <= day <= dim:
                        push(out, "RESIDENT_ID", i, end, "HIGH")
                        i = end
                        continue
        i += 1


def scan_macs(text, out):
    for m in re.finditer(r"[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){4}", text):
        s, e = m.start(), m.end()
        before = text[s - 2:s]
        sep = text[s + 2]
        seps = {text[k] for k in range(s + 2, e, 3)}
        if len(seps) == 1 and (s == 0 or not text[s - 1].isalnum()) and (e >= len(text) or not text[e].isalnum() and text[e] not in ":-"):
            push(out, "MAC_ADDRESS", s, e, "MEDIUM")


def scan_uuids(text, out):
    for m in re.finditer(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b", text):
        if not (m.end() < len(text) and text[m.end()].isalpha()) and not (m.start() > 0 and text[m.start() - 1].isalpha()):
            push(out, "UUID", m.start(), m.end(), "MEDIUM")


def scan_phones(text, out):
    for m in re.finditer(r"\+[1-9]\d{7,14}\b", text):
        push(out, "PHONE", m.start(), m.end(), "MEDIUM")


def scan_ipv6(text, out):
    def group_ok(g):
        return 1 <= len(g) <= 4 and all(c in "0123456789abcdefABCDEF" for c in g)

    for m in re.finditer(r"[0-9A-Fa-f:]+", text):
        run = m.group(0)
        if "::" in run:
            if run.count("::") > 1:
                continue
            parts = run.split("::")
            left = [g for g in parts[0].split(":") if g]
            right = [g for g in parts[1].split(":") if g]
            if not all(group_ok(g) for g in left + right):
                continue
            if len(left) + len(right) >= 8:
                continue
        else:
            groups = run.split(":")
            if len(groups) != 8 or not all(group_ok(g) for g in groups):
                continue
        push(out, "IPV6", m.start(), m.end(), "MEDIUM")


def scan_wallets(text, out):
    for m in re.finditer(r"0x[0-9A-Fa-f]{40}\b", text):
        push(out, "WALLET_ADDRESS", m.start(), m.end(), "MEDIUM")
    for m in re.finditer(r"\b(?:bc1[qp]|tb1[qp]|ltc1)[a-z0-9]{11,87}\b", text):
        push(out, "WALLET_ADDRESS", m.start(), m.end(), "MEDIUM")


def scan_webhooks(text, out):
    for m in re.finditer(r"hooks\.slack\.com/services/[\w-]+/[\w-]+/[\w-]+", text):
        segs = m.group(0).split("/")[2:]
        if 8 <= len(segs[0]) <= 12 and 8 <= len(segs[1]) <= 12 and len(segs[2]) >= 20:
            push(out, "WEBHOOK_URL", m.start(), m.end(), "HIGH")
    for m in re.finditer(r"discord\.com/api/webhooks/\d{17,}/[\w-]{50,}", text):
        push(out, "WEBHOOK_URL", m.start(), m.end(), "HIGH")


CREDENTIALS = {
    "tokens", "bearer", "jwt", "private", "url", "assignment", "basic",
}
LEGACY_POLICY_EXTRA = {"email", "ipv4", "card"}
CONFIG_EXTRA = {"resident", "mac", "uuid", "ipv6", "public", "wallet", "webhook"}


def families_for(mode):
    if mode == "secrets":
        return CREDENTIALS
    if mode == "standard":
        return CREDENTIALS | LEGACY_POLICY_EXTRA
    if mode == "config":
        return CREDENTIALS | LEGACY_POLICY_EXTRA | CONFIG_EXTRA
    if mode == "phone":
        return CREDENTIALS | LEGACY_POLICY_EXTRA | CONFIG_EXTRA | {"phone"}
    raise ValueError(mode)


def scan_all(text, mode):
    fam = families_for(mode)
    out = []
    if "tokens" in fam: scan_prefixed_tokens(text, out)
    if "bearer" in fam: scan_bearer(text, out)
    if "jwt" in fam: scan_jwt(text, out)
    if "private" in fam: scan_private_keys(text, out)
    if "url" in fam: scan_url_credentials(text, out)
    if "assignment" in fam: scan_assignments(text, out)
    if "basic" in fam: scan_basic_auth(text, out)
    if "email" in fam: scan_emails(text, out)
    if "ipv4" in fam: scan_ipv4(text, out)
    if "resident" in fam: scan_resident_ids(text, out)
    if "mac" in fam: scan_macs(text, out)
    if "uuid" in fam: scan_uuids(text, out)
    if "ipv6" in fam: scan_ipv6(text, out)
    if "phone" in fam: scan_phones(text, out)
    if "public" in fam:
        scan_ssh_public(text, out)
        scan_certificates(text, out)
    if "wallet" in fam: scan_wallets(text, out)
    if "webhook" in fam: scan_webhooks(text, out)
    if "card" in fam: scan_cards(text, out)
    return sorted(out, key=lambda f: (f[1], -f[2]))


def non_overlapping(findings):
    out, last_end = [], -1
    for f in findings:
        if f[1] >= last_end:
            out.append(f)
            last_end = f[2]
    return out


def main():
    quiet = "--quiet" in sys.argv
    doc = json.loads((ROOT / "testvectors" / "vectors.json").read_text(encoding="utf-8"))
    failures = 0
    for vector in doc["vectors"]:
        actual = non_overlapping(scan_all(vector["input"], vector["mode"]))
        expected = []
        for e in vector["expect"]:
            idx = vector["input"].find(e["literal"])
            assert idx >= 0, f"{vector['name']}: literal not found"
            expected.append((e["kind"], idx, idx + len(e["literal"]), e["confidence"]))
        if actual != expected:
            failures += 1
            if not quiet:
                print(f"FAIL {vector['name']}")
                print(f"  expected: {expected}")
                print(f"  actual:   {actual}")
    total = len(doc["vectors"])
    if not quiet:
        print(f"{total - failures}/{total} vectors matched")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
