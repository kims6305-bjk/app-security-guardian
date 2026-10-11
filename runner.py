#!/usr/bin/env python3
"""origin-security v0.2 blackbox — minimal local HTTP response-hardening checker (stdlib only).

Scope (hard limits, by design):
  * ONE GET to an exact http://127.0.0.1:PORT/path URL. Nothing else.
  * --authorized must be passed or nothing is validated/fetched.
  * http.client directly: no proxy env, no redirect following, no crawling.
  * Bounded timeouts and body read; body is discarded, never reported.
  * Report: status, allowlisted headers, cookie *metadata* (no values), findings.
Findings are hardening observations, not proven exploits; a clean run is not a
"secure" certificate.
"""
import argparse
import http.client
import json
import re
import sys
import time

VERSION = "0.2.0"
TIMEOUT_S = 5.0          # per socket op (connect/read)
MAX_BODY = 64 * 1024     # bytes read then discarded
BODY_DEADLINE_S = 10.0   # wall-clock cap on the body phase (checked between single recv()s)
MAX_HEADER_VALUE = 512   # reported header values are truncated
# ponytail: header phase is bounded only per socket op (http.client: <=100 headers, 64 KiB/line);
# a slow-drip server can stall it ~TIMEOUT_S per recv. Body phase <= BODY_DEADLINE_S + TIMEOUT_S.
# Add a watchdog thread/socket deadline if this ever points at untrusted servers (it must not).
_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_SAMESITE = {"strict": "Strict", "lax": "Lax", "none": "None"}
REPORT_HEADERS = (
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "x-content-type-options", "content-type",
    "referrer-policy", "strict-transport-security",
)
# exact host, explicit port 1-65535 w/o leading zero, optional path; no userinfo/query/fragment.
_URL_RE = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})(/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*)?")


class Refused(ValueError):
    pass


def validate_url(url):
    """Return (port, path) or raise Refused. Pure function, no I/O."""
    if not isinstance(url, str) or not url.isascii() or any(ord(c) < 0x21 or ord(c) == 0x7F for c in url):
        raise Refused("non-ascii, whitespace or control characters")
    m = _URL_RE.fullmatch(url)
    if not m:
        raise Refused("only exact http://127.0.0.1:PORT[/path] is allowed (no other host/scheme, userinfo, query, fragment)")
    port = int(m.group(1))
    if port > 65535:
        raise Refused("port out of range")
    return port, m.group(2) or "/"


def _cookie_meta(raw):
    """Parse one Set-Cookie into metadata. The cookie value is never returned."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if "=" in parts[0] else ""
    name = name if _TOKEN_RE.fullmatch(name) else "(invalid-name)"
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    ss = attrs.get("samesite")
    # enum only: an attacker/garbage SameSite value is never echoed.
    ss = None if ss is None else _SAMESITE.get(ss.lower(), "invalid")
    return {"name": name, "httponly": "httponly" in attrs, "secure": "secure" in attrs, "samesite": ss}


def _clean_header(v):
    """Redact CSP nonces/hashes and truncate; header values are otherwise reported."""
    v = re.sub(r"'(nonce|sha256|sha384|sha512)-[^']*'", r"'\1-REDACTED'", v, flags=re.I)
    return v[:MAX_HEADER_VALUE]


def check_headers(hdr, cookies):
    """hdr: dict lower-name -> value; cookies: list of cookie metadata. Returns (checks, findings)."""
    checks, findings = [], []

    def add(cid, status, detail, severity=None):
        checks.append({"id": cid, "status": status, "detail": detail})
        if status == "finding":
            findings.append({"id": cid, "severity": severity, "detail": detail,
                             "nature": "missing/weak hardening header (observation, not a proven exploit)"})

    csp = hdr.get("content-security-policy")
    if not csp:
        ro = " (only Report-Only present; not enforced)" if hdr.get("content-security-policy-report-only") else ""
        add("csp", "finding", "Content-Security-Policy missing" + ro, "medium")
    else:
        # script execution is what XSS needs; 'unsafe-inline' in style-src only is noted, not a finding
        exec_src = re.search(r"(?:^|;)\s*script-src([^;]*)", csp, re.I) or re.search(r"(?:^|;)\s*default-src([^;]*)", csp, re.I)
        exec_src = exec_src.group(1).lower() if exec_src else csp.lower()
        weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in exec_src]
        if re.search(r"(?:^|;)\s*(?:default-src|script-src)[^;]*\s\*(?:\s|;|$)", csp):
            weak.append("wildcard * source")
        if weak:
            add("csp", "finding", "CSP present but weak (script execution): " + ", ".join(weak), "low")
        elif "'unsafe-inline'" in csp.lower():
            add("csp", "pass", "CSP enforced; 'unsafe-inline' only in style-src (styling, not script) — low value, optional cleanup")
        else:
            add("csp", "pass", "CSP present (content not deeply evaluated)")

    xfo = (hdr.get("x-frame-options") or "").strip().upper()
    fa = re.search(r"(?:^|;)\s*frame-ancestors(?:\s([^;]*)|\s*(?:;|$))", csp or "", re.I)
    fa_src = fa.group(1).split() if fa and fa.group(1) else []
    fa_weak = [t for t in fa_src if t == "*" or t.lower() in ("http:", "https:", "data:", "blob:")]
    if fa and fa_weak:  # browsers prefer frame-ancestors over XFO, so a weak one is not rescued by XFO
        add("frame", "finding", "CSP frame-ancestors allows any origin (" + ", ".join(fa_weak) + ")", "medium")
    elif fa and fa_src:
        add("frame", "pass", "frame protection via CSP frame-ancestors")
    elif xfo in ("DENY", "SAMEORIGIN"):
        add("frame", "pass", "frame protection via X-Frame-Options " + xfo)
    else:
        add("frame", "finding", "no X-Frame-Options DENY/SAMEORIGIN and no CSP frame-ancestors", "medium")

    if (hdr.get("x-content-type-options") or "").strip().lower() == "nosniff":
        add("nosniff", "pass", "X-Content-Type-Options: nosniff")
    else:
        add("nosniff", "finding", "X-Content-Type-Options: nosniff missing", "low")

    if not cookies:
        add("cookies", "n/a", "no Set-Cookie in response")
    else:
        bad = []
        for c in cookies:
            if not c["httponly"]:
                bad.append(f"{c['name']}: HttpOnly missing")
            if c["samesite"] not in ("Lax", "Strict"):  # None/invalid/missing
                bad.append(f"{c['name']}: SameSite {c['samesite'] or 'missing'}")
        if bad:
            add("cookies", "finding", "; ".join(bad), "medium")
        else:
            add("cookies", "pass", f"{len(cookies)} cookie(s) HttpOnly + SameSite Lax/Strict")
    # Plain local HTTP: Secure flag / HSTS cannot be meaningfully evaluated. Never a pass.
    add("transport", "n/a", "local plain HTTP: HSTS and cookie Secure flag not evaluated (not a pass)")
    return checks, findings


def run(url, authorized):
    """Returns (exit_code, report dict). No I/O unless authorized and URL valid."""
    try:
        port, path = validate_url(url)
        err = None
    except Refused as e:
        err = e
    # a rejected URL is never echoed (it may carry userinfo/credentials or control chars)
    base = {"tool": "origin-security", "mode": "blackbox", "version": VERSION,
            "url": url if err is None else "(rejected; not echoed)",
            "limits": {"method": "GET", "requests": 1, "timeout_s": TIMEOUT_S, "max_body_bytes": MAX_BODY, "body_deadline_s": BODY_DEADLINE_S,
                       "redirects": "never followed", "proxy": "not used", "body": "discarded, not reported",
                       "non_2xx": "not evaluated", "mutation": "GET is not guaranteed side-effect free; "
                       "only point at handlers you own that do not mutate on GET"}}
    if not authorized:
        return 2, {**base, "ok": False, "error": "refused: --authorized not given (no request made)"}
    if err is not None:
        return 2, {**base, "ok": False, "error": f"refused: {err} (no request made)"}
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT_S)
    t0 = time.monotonic()
    try:
        conn.request("GET", path, headers={"User-Agent": f"origin-security/{VERSION}", "Accept": "*/*",
                                           "Connection": "close"})
        resp = conn.getresponse()
        body_read, deadline, truncated = 0, time.monotonic() + BODY_DEADLINE_S, False
        while body_read < MAX_BODY:
            if time.monotonic() > deadline:
                truncated = True
                break
            chunk = resp.read1(MAX_BODY - body_read)  # at most one recv() per call
            if not chunk:
                break
            body_read += len(chunk)
        status = resp.status
        hdr = {k.lower(): _clean_header(v) for k, v in resp.getheaders() if k.lower() in REPORT_HEADERS}
        cookies = [_cookie_meta(v) for k, v in resp.getheaders() if k.lower() == "set-cookie"]
    except (OSError, http.client.HTTPException) as e:
        return 3, {**base, "ok": False, "error": f"request failed: {type(e).__name__}"}
    finally:
        conn.close()
    ev = {"status": status, "elapsed_ms": round((time.monotonic() - t0) * 1000), "body_bytes_read": body_read,
          "body_deadline_hit": truncated, "headers": hdr, "cookies": cookies}
    if 300 <= status < 400:
        return 3, {**base, "ok": False, "evidence": ev,
                   "error": "redirect response; not followed and not evaluated (point at the final local URL)"}
    if not 200 <= status < 300:
        return 3, {**base, "ok": False, "evidence": ev,
                   "error": f"non-2xx status {status}; not evaluated (not a clean result)"}
    checks, findings = check_headers(hdr, cookies)
    return (1 if findings else 0), {
        **base, "ok": True, "evidence": ev, "checks_count": len(checks), "checks": checks,
        "findings_count": len(findings), "findings": findings,
        "verdict": ("hardening gaps observed" if findings else "no gaps among these checks")
                   + " — scoped header observation only; not a security certification or pentest"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="One GET to http://127.0.0.1:PORT/path; report response hardening headers.")
    ap.add_argument("url")
    ap.add_argument("--authorized", action="store_true", help="I own/am authorized to test this local service")
    a = ap.parse_args(argv)
    code, rep = run(a.url, a.authorized)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
