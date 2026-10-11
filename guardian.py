#!/usr/bin/env python3
"""app-security-guardian (가디언) — defensive, local-only security check of apps WE own.

  guardian.py scan SOURCE_DIR --authorized   whitebox: semgrep(local rules) + gitleaks + osv-scanner(offline) + builtin Python AST
  guardian.py blackbox http://127.0.0.1:PORT/ --authorized   headers/cookies + path-traversal + CORS (3-4 GETs, loopback only)
  guardian.py attack   http://127.0.0.1:PORT/ --authorized   active known-signature scan (nuclei, no OAST, no dos/fuzz/intrusive), loopback only

No destructive exploitation (attack = nuclei signature checks only), no remote targets, no code upload: semgrep --metrics=off with rules/ files only,
osv-scanner --offline-vulnerabilities, gitleaks --redact. Source snippets and secret values are never reported.
Exit: 0 clean (all tools ran) · 1 findings · 2 refused · 3 partial (a tool missing/failed) — 3 is never "clean".
"""
import argparse, hashlib, http.client, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import origin, runner  # noqa: E402

VERSION = "0.4.0"
RULES = [os.path.join(HERE, "rules", f"p-{p}.yml") for p in ("default", "javascript", "nodejs", "xss", "secrets", "python")]
EXCLUDE = ["node_modules", "upstream", ".git", "venv", ".venv", "dist", "build", "*.bak.*", "*.min.js"]
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _run(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "", type(e).__name__


def _tool(name, fn, root):
    if not shutil.which(name):
        return {"tool": name, "status": "not_run", "reason": f"{name} not installed", "findings": []}
    try:
        return {"tool": name, **fn(root)}
    except Exception as e:  # a broken tool must surface as PARTIAL, never as clean
        return {"tool": name, "status": "error", "reason": f"{type(e).__name__}: {str(e)[:200]}", "findings": []}


def _semgrep(root):
    missing = [r for r in RULES if not os.path.isfile(r)]
    if missing:
        return {"status": "error", "reason": "rules missing — run fetch_rules.py", "findings": []}
    cmd = ["semgrep", "scan", "--metrics=off", "--disable-version-check", "--quiet", "--json", "--timeout", "30"]
    for r in RULES:
        cmd += ["--config", r]
    for x in EXCLUDE:
        cmd += ["--exclude", x]
    rc, out, err = _run(cmd + [root])
    if rc not in (0, 1) or not out:
        return {"status": "error", "reason": f"exit {rc}: {err[-200:]}", "findings": []}
    d = json.loads(out)
    seen, fs = set(), []
    for r in d.get("results", []):
        key = (r["path"], r["start"]["line"], r["check_id"])
        if key in seen:
            continue
        seen.add(key)
        fs.append({"path": os.path.relpath(r["path"], root), "line": r["start"]["line"], "rule": r["check_id"].split(".")[-1],
                   "severity": SEV.get(r["extra"].get("severity"), "low"), "message": r["extra"].get("message", "")[:240]})
    scanned = len(d.get("paths", {}).get("scanned", []))
    errs = len(d.get("errors", []))
    return {"status": "partial" if errs else "ok", "files_scanned": scanned, "parse_errors": errs, "findings": fs}


def _gitleaks(root):
    fs = []
    with tempfile.TemporaryDirectory() as t:
        targets = [("dir", root)] + ([("git", root)] if os.path.isdir(os.path.join(root, ".git")) else [])
        for mode, tgt in targets:
            rep = os.path.join(t, f"{mode}.json")
            rc, _, err = _run(["gitleaks", mode, tgt, "--no-banner", "--redact", "-f", "json", "-r", rep])
            if rc not in (0, 1):
                return {"status": "error", "reason": f"gitleaks {mode} exit {rc}: {err[-200:]}", "findings": []}
            with open(rep) as fh:
                found = json.load(fh)
            for r in found:  # Match/Secret deliberately dropped
                fs.append({"path": os.path.relpath(r.get("File", ""), root) if mode == "dir" else r.get("File", ""),
                           "line": r.get("StartLine"), "rule": r.get("RuleID"), "severity": "high",
                           "where": "git history " + r.get("Commit", "")[:7] if mode == "git" else "working tree",
                           "message": "possible secret (value redacted) — rotate if real"})
        return {"status": "ok", "modes": [m for m, _ in targets], "findings": fs}


def _osv(root):
    rc, out, err = _run(["osv-scanner", "scan", "source", "--offline-vulnerabilities", "--download-offline-databases",
                         "--format", "json", "-r", root])
    if rc == 128:  # no lockfile/package sources found
        return {"status": "not_run", "reason": "no lockfile (package-lock.json/requirements.txt/...) found", "findings": []}
    if rc not in (0, 1) or not out:
        return {"status": "error", "reason": f"exit {rc}: {err[-200:]}", "findings": []}
    fs = []
    for res in json.loads(out).get("results", []):
        for p in res.get("packages", []):
            ids = [v["id"] for v in p.get("vulnerabilities", [])]
            if ids:
                fs.append({"path": os.path.relpath(res["source"]["path"], root), "rule": "vulnerable-dependency", "severity": "high",
                           "message": f"{p['package']['name']}@{p['package']['version']}: {len(ids)} advisories ({', '.join(ids[:5])})"})
    return {"status": "ok", "findings": fs}


def _builtin_py(root):
    code, rep = origin.whitebox(root, True)
    if code == 4:
        return {"status": "not_run", "reason": "no Python files", "findings": []}
    return {"status": "partial" if code == 3 else "ok",
            "findings": [{k: f.get(k) for k in ("path", "line", "rule", "confidence")} | {"severity": "medium"} for f in rep.get("findings", [])]}


def scan(root, authorized):
    base = {"tool": "app-security-guardian", "mode": "scan", "version": VERSION}
    if not authorized:
        return 2, {**base, "error": "refused: --authorized not given (nothing read)"}
    if ".." in root.split(os.sep) or not os.path.isdir(root) or os.path.islink(root):
        return 2, {**base, "error": "refused: SOURCE must be an existing local directory (no symlink, no '..')"}
    root = os.path.abspath(root)
    tools = [_tool("semgrep", _semgrep, root), _tool("gitleaks", _gitleaks, root),
             _tool("osv-scanner", _osv, root), {"tool": "builtin-python-ast", **_builtin_py(root)}]
    n = sum(len(t["findings"]) for t in tools)
    broken = [t["tool"] for t in tools if t["status"] in ("error", "partial") or (t["status"] == "not_run" and "installed" in t.get("reason", ""))]
    code = 1 if n else (3 if broken else 0)
    return code, {**base, "source": root, "findings_total": n,
                  "by_tool": {t["tool"]: {"status": t["status"], "findings": len(t["findings"])} for t in tools},
                  "incomplete_tools": broken, "tools": tools,
                  "verdict": ("candidates found — review each" if n else "PARTIAL — some tools did not run" if broken else "no findings from these tools")
                             + "; not a security certification or pentest"}


def _get(port, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=runner.TIMEOUT_S)
    try:
        c.request("GET", path, headers={"User-Agent": f"app-security-guardian/{VERSION}", "Connection": "close", **(headers or {})})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(runner.MAX_BODY)
    finally:
        c.close()


def blackbox(url, authorized):
    code, rep = runner.run(url, authorized)
    rep["tool"], rep["version"] = "app-security-guardian", VERSION
    if code == 2 or not rep.get("ok"):
        return code, rep
    port, _ = runner.validate_url(url)
    extra = []
    try:
        # path traversal: a 200 whose body differs from the app's normal unknown-path response (SPA fallback) = files outside the web root are served
        st, _, body = _get(port, "/../package.json")
        _, _, miss = _get(port, "/guardian-probe-does-not-exist-7f3a")
        leak = st == 200 and hashlib.sha256(body).digest() != hashlib.sha256(miss).digest()
        extra.append({"id": "path-traversal", "status": "finding" if leak else "pass",
                      "detail": f"GET /../package.json -> {st}" + (" (served a file outside the web root)" if leak else "")})
        # CORS: does the API let any other site read responses from a victim's browser?
        _, h, _ = _get(port, "/", {"Origin": "https://guardian-cors-probe.invalid"})
        acao = h.get("access-control-allow-origin")
        bad = acao in ("*", "https://guardian-cors-probe.invalid")
        extra.append({"id": "cors", "status": "finding" if bad else "pass",
                      "detail": f"Access-Control-Allow-Origin: {acao or '(none)'}" + (" — any site can read responses" if bad else "")})
    except (OSError, http.client.HTTPException) as e:
        extra.append({"id": "extra-probes", "status": "error", "detail": type(e).__name__})
    sev = {"path-traversal": "high", "cors": "medium"}
    new = [{"id": x["id"], "severity": sev.get(x["id"]), "detail": x["detail"]} for x in extra if x["status"] == "finding"]
    rep["checks"] += extra
    rep["findings"] += new
    rep["findings_count"] = len(rep["findings"])
    rep["limits"]["requests"] = 4
    if any(x["status"] == "error" for x in extra):
        return 3, {**rep, "ok": False, "verdict": "PARTIAL — extra probes failed"}
    return (1 if rep["findings"] else 0), rep


NUCLEI_SEV = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}


def attack(url, authorized, template_ids=None, timeout=1500):
    """Active DAST with nuclei templates against a loopback app we own. No OAST callbacks (-ni), http only,
    dos/fuzz/intrusive tags excluded, no redirects, no update check. Payload/response bodies are not reported."""
    base = {"tool": "app-security-guardian", "mode": "attack", "version": VERSION}
    if not authorized:
        return 2, {**base, "error": "refused: --authorized not given (no request sent)"}
    try:
        runner.validate_url(url)  # loopback http only — same gate as blackbox
    except Exception:
        return 2, {**base, "error": "refused: target must be http://127.0.0.1:PORT/ (rejected; not echoed)"}
    if not shutil.which("nuclei"):
        return 3, {**base, "error": "nuclei not installed (brew install nuclei && nuclei -update-templates)"}
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-ni", "-duc", "-pt", "http", "-etags", "dos,fuzz,intrusive",
           "-rl", "100", "-timeout", "5", "-retries", "0", "-omit-raw", "-no-color"]
    if template_ids:
        cmd += ["-id", ",".join(template_ids)]
    rc, out, err = _run(cmd, timeout=timeout)
    if rc != 0:
        return 3, {**base, "ok": False, "error": f"nuclei exit {rc}: {err[-200:]}", "verdict": "PARTIAL — attack scan did not finish"}
    fs = []
    for line in out.splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        info = r.get("info", {})
        fs.append({"rule": r.get("template-id"), "severity": NUCLEI_SEV.get(info.get("severity"), "low"),
                   "name": info.get("name"), "path": (r.get("matched-at") or "").replace(url.rstrip("/"), "") or "/"})
    return (1 if fs else 0), {**base, "ok": True, "target": "127.0.0.1 (validated)", "findings_count": len(fs), "findings": fs,
                              "verdict": ("candidates found — reproduce and fix" if fs else "no template matched")
                                         + "; known-signature scan, not a full pentest"}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian.py", description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=["scan", "whitebox", "blackbox", "attack"])
    ap.add_argument("target")
    ap.add_argument("--authorized", action="store_true", help="I own / am authorized to test this local target")
    a = ap.parse_args(argv)
    fn = {"blackbox": blackbox, "attack": attack}.get(a.mode, scan)
    code, rep = fn(a.target, a.authorized)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
