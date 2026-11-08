#!/usr/bin/env python3
"""
js_analyze.py - normalize and statically analyze JS captured by recon.sh

recon.sh stores raw HTTP request+response pairs (httpx -srd). Bodies may be
chunked and/or compressed (gzip/deflate/br), so this script dechunks and
decompresses them before scanning.

Usage:
    ./js_analyze.py <recon target dir>          # e.g. recon/swedavia.se
    ./js_analyze.py <recon target dir> --plain  # only normalize

Outputs (under <target>/04-js/analysis):
    manifest.tsv        url, host, status, content-type, file, bytes
    plain/              decoded JavaScript
    secrets.tsv         pattern, value, host, file, context
    auth.tsv            keyword, host, file, context
    hosts.txt           hosts referenced in JS
    paths.txt           absolute URLs + rooted paths leaking from JS
"""
import argparse
import gzip
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path
from urllib.parse import urlsplit

try:
    import brotli
except ImportError:  # brotli is optional unless a body uses it
    brotli = None


# --------------------------------------------------------------- HTTP parse --
def split_http(raw: bytes):
    """Return (request_line, request_headers, status, resp_headers, body)."""
    first_end = raw.find(b"\r\n\r\n")
    if first_end == -1:
        return "", {}, 0, {}, raw
    head = raw[:first_end].decode("latin1", "replace")
    rest = raw[first_end + 4:]
    req_line, req_headers = head.split("\r\n", 1)[0], {}
    for line in head.split("\r\n")[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            req_headers[k.lower()] = v

    status = 0
    if not rest.startswith(b"HTTP/"):
        return req_line, req_headers, 0, {}, rest
    resp_end = rest.find(b"\r\n\r\n")
    if resp_end == -1:
        return req_line, req_headers, 0, {}, b""
    head2 = rest[:resp_end].decode("latin1", "replace")
    body = rest[resp_end + 4:]
    status_line = head2.split("\r\n", 1)[0]
    m = re.match(r"HTTP/\S+\s+(\d+)", status_line)
    status = int(m.group(1)) if m else 0
    resp_headers = {}
    for line in head2.split("\r\n")[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            resp_headers[k.lower()] = v
    return req_line, req_headers, status, resp_headers, body


def dechunk(body: bytes) -> bytes:
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            return bytes(out) or body
        if size == 0:
            break
        i = j + 2
        out += body[i:i + size]
        i += size + 2
    return bytes(out)


def decode_body(body: bytes, headers: dict) -> bytes:
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = dechunk(body)
    enc = headers.get("content-encoding", "").lower()
    # httpx usually decompresses gzip but not always other encodings.
    if enc == "gzip" or body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    elif enc == "deflate":
        for wbits in (15, -15):
            try:
                body = zlib.decompress(body, wbits)
                break
            except zlib.error:
                continue
    elif enc == "br" and brotli is not None:
        try:
            body = brotli.decompress(body)
        except Exception:
            pass
    return body


def looks_like_js(data: bytes) -> bool:
    if not data:
        return False
    if data.lstrip()[:1] in (b"{", b"["):
        return False
    head = data[:2000].decode("latin1", "replace").lstrip()
    if head.startswith("<"):
        return False
    markers = ("function", "var ", "let ", "const ", "=>", "class ", "import ",
               "export ", "!function", "window.", "[", "this.")
    return any(m in head for m in markers)


# ----------------------------------------------------------------- patterns --
SECRET_PATTERNS = [
    ("aws_access_key",        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 3),
    ("aws_secret_assignment", r"aws_?secret_?(?:access_?)?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", 3),
    ("google_api_key",        r"\bAIza[0-9A-Za-z_-]{35}\b", 2),
    ("gcp_service_account",   r'"type"\s*:\s*"service_account"', 3),
    ("github_token",          r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b", 3),
    ("gitlab_token",          r"\bglpat-[0-9A-Za-z_-]{20,}\b", 3),
    ("slack_token",           r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b", 3),
    ("stripe_secret",         r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b", 3),
    ("stripe_public",         r"\bpk_live_[0-9A-Za-z]{20,}\b", 1),
    ("sendgrid_key",          r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 3),
    ("twilio_key",            r"\bSK[0-9a-fA-F]{32}\b", 2),
    ("mailgun_key",           r"\bkey-[0-9a-zA-Z]{32}\b", 2),
    ("google_oauth_secret",   r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", 3),
    ("azure_account_key",     r"AccountKey=[A-Za-z0-9+/=]{40,}", 3),
    ("azure_sas_token",       r"[?&]sig=[A-Za-z0-9%+/=]{20,}", 2),
    ("sql_connection",        r"(?:Server|Data Source)\s*=\s*[^;\"']+;[^\n]{0,200}?(?:Password|Pwd)\s*=\s*[^;\"']+", 3),
    ("private_key",           r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", 3),
    ("jwt",                   r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", 2),
    ("basic_auth_url",        r"https?://[^/\s:@\"']+:[^/\s@\"']+@[A-Za-z0-9.-]+", 3),
    ("sentry_dsn",            r"https://[0-9a-f]{32}@[\w.-]+/\d+", 1),
    ("newrelic_browser_key",  r"\bNRJS-[0-9a-f]{19}\b", 1),
    ("datadog_api_key",       r"\b(?:DD_API_KEY|datadog[_-]?api[_-]?key)\s*[:=]\s*['\"]([0-9a-f]{32})['\"]", 3),
    ("algolia_key",           r"\b(?:algolia|ALGOLIA)[^\n]{0,80}?['\"]([0-9a-f]{32})['\"]", 1),
    ("generic_secret_assign", r"(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*['\"]([^'\"\s]{8,80})['\"]", 1),
]

AUTH_PATTERNS = [
    ("client_secret",      r"client[_-]?secret", 3),
    ("redirect_uri",       r"redirect[_-]?uri", 2),
    ("oauth_scope",        r"\bscope\b|\bgrant_type\b|response_type", 2),
    ("bearer_token",       r"Bearer\s+[A-Za-z0-9._-]{10,}", 3),
    ("authorization_hdr",  r"['\"]?Authorization['\"]?\s*[:=]", 3),
    ("x_api_key",          r"x-api-key", 3),
    ("jwt_handling",       r"jwt|decodeToken|parseJwt|atob\(", 2),
    ("web_storage",        r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)", 2),
    ("cookie_write",       r"document\.cookie\s*=", 2),
    ("role_check",         r"\b(?:isAdmin|is_admin|hasRole|hasPermission|permissions?|authorities|userRole|user_role)\b", 2),
    ("cognito",            r"IdentityPoolId|UserPoolId|cognito", 3),
    ("firebase_config",    r"firebaseConfig|firebaseapp\.com|firebaseio\.com", 2),
    ("auth0",              r"auth0|\.auth0\.com", 2),
    ("keycloak",           r"keycloak|openid-connect|realms/", 2),
    ("saml",               r"\bSAML|saml2?\b", 1),
    ("postmessage",        r"postMessage|addEventListener\(\s*['\"]message['\"]", 2),
    ("xss_sink",           r"dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\(|insertAdjacentHTML", 2),
    ("eval",               r"\beval\(|new\s+Function\(", 2),
    ("impersonation",      r"impersonat|\bactAs\b|on[_-]?behalf", 3),
    ("debug_flag",         r"\bdebug\s*[:=]\s*(?:true|1)|devMode|development\s*[:=]", 1),
]

HOST_RE = re.compile(r"""(?:https?|wss?)://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?::\d+)?[/"'\s]""")
PATH_RE = re.compile(r"""["'](/(?:api|v\d+|graphql|rest|internal|admin|auth|oauth|user|account|upload|download|file|files|config|token|sso|login|logout)[A-Za-z0-9_./?=&%:+{}$-]*)["']""")

# Placeholder values that show up in every bundle and are not findings.
PLACEHOLDER = re.compile(
    r"^(?:x{3,}|\.{3,}|changeme|your[_-]?|example|placeholder|undefined|null|"
    r"process\.env|import\.meta|window\.|__|%s|\{\{)", re.I)


def snippet(text: str, start: int, end: int, width: int = 90) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="recon target dir, e.g. recon/swedavia.se")
    ap.add_argument("--plain", action="store_true", help="only normalize files")
    args = ap.parse_args()

    target = Path(args.target).expanduser().resolve()
    resp = target / "04-js" / "files" / "response"
    if not resp.is_dir():
        print(f"[-] no stored responses at {resp}", file=sys.stderr)
        return 1
    out = target / "04-js" / "analysis"
    plain = out / "plain"
    plain.mkdir(parents=True, exist_ok=True)

    manifest = []
    secrets, auth, hosts, paths = [], [], {}, set()
    auth_keys = set()
    seen_bodies = set()
    used = set()

    for f in sorted(resp.rglob("*.txt")):
        if f.name == "index.txt":
            continue
        raw = f.read_bytes()
        req_line, req_h, status, resp_h, body = split_http(raw)
        body = decode_body(body, resp_h)
        parts = req_line.split()
        path = parts[1] if len(parts) > 1 else "/"
        host = req_h.get("host", f.parent.name)
        url = f"https://{host}{path}"
        ctype = resp_h.get("content-type", "")

        if not body or not looks_like_js(body):
            continue

        text = body.decode("utf-8", "replace")
        digest = hashlib.sha1(body).hexdigest()[:12]
        if digest in seen_bodies:
            continue
        seen_bodies.add(digest)
        name = f"{host}__{digest}.js"
        n = 1
        while name in used:
            n += 1
            name = f"{host}__{digest}_{n}.js"
        used.add(name)
        (plain / name).write_text(text, errors="replace")
        manifest.append((url, host, status, ctype, name, len(body)))

        if args.plain:
            continue

        for pname, rx, conf in SECRET_PATTERNS:
            for m in re.finditer(rx, text, re.I):
                val = m.group(1) if m.groups() else m.group(0)
                if PLACEHOLDER.search(val or ""):
                    continue
                secrets.append((pname, conf, val[:120], host, name,
                                snippet(text, m.start(), m.end())))

        for kname, rx, conf in AUTH_PATTERNS:
            seen = 0
            for m in re.finditer(rx, text, re.I):
                ctx = snippet(text, m.start(), m.end(), 40)
                key = (kname, host, ctx)
                if key in auth_keys:
                    continue
                auth_keys.add(key)
                auth.append((kname, host, ctx, conf))
                seen += 1
                if seen >= 40:  # cap per file/keyword
                    break

        for m in HOST_RE.finditer(text):
            h = m.group(1).lower()
            hosts[h] = hosts.get(h, 0) + 1
        for m in PATH_RE.finditer(text):
            paths.add(m.group(1))

    with (out / "manifest.tsv").open("w") as fh:
        fh.write("url\thost\tstatus\tcontent_type\tfile\tbytes\n")
        for row in manifest:
            fh.write("\t".join(map(str, row)) + "\n")

    with (out / "secrets.tsv").open("w") as fh:
        fh.write("pattern\tconfidence\tvalue\thost\tfile\tcontext\n")
        for row in sorted(secrets, key=lambda r: (-r[1], r[0])):
            fh.write("\t".join(str(x).replace("\t", " ") for x in row) + "\n")

    with (out / "auth.tsv").open("w") as fh:
        fh.write("keyword\thost\tcontext\tconfidence\n")
        for row in sorted(auth, key=lambda r: (-r[3], r[0])):
            fh.write("\t".join(str(x).replace("\t", " ") for x in row) + "\n")

    (out / "hosts.txt").write_text(
        "".join(f"{c}\t{h}\n" for h, c in sorted(hosts.items(), key=lambda x: -x[1])))
    (out / "paths.txt").write_text("".join(f"{p}\n" for p in sorted(paths)))

    print(f"[+] decoded {len(manifest)} JS files -> {plain}")
    print(f"[+] secrets: {len(secrets)} | auth hits: {len(auth)} | hosts: {len(hosts)} | paths: {len(paths)}")
    print(f"[+] results in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
