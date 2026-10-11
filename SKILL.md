---
name: app-security-guardian
description: Local security check for a web app the user owns — white-box source scan (Semgrep, gitleaks, osv-scanner), black-box response check (headers, cookies, path traversal, CORS) and signature-based active check (nuclei) against http://127.0.0.1 only. Use when the user asks to security-check, audit or harden their own app, find leaked API keys, or check vulnerable dependencies. Not for third-party or remote sites.
---

# app-security-guardian

Defensive, local-only security checks for an app **the user owns**. `guardian.py` wraps proven scanners and prints one JSON report. Run every command from **this skill's directory** (the folder containing this file).

## Hard rules (do not work around them)

1. **Authorization first.** Before passing `--authorized`, confirm the user owns the target or is explicitly authorized to test it. If unclear, ask. Never test a third-party site.
2. **Loopback only.** `blackbox` / `attack` accept only `http://127.0.0.1:PORT/`. For a deployed site, run the app locally and test the local copy. Do not edit `runner.py` / `guardian.py` to lift this gate.
3. **No secrets in output.** Report a secret's file, line and rule only — never its value, a prefix or a hash.
4. **Exit 3 is not clean.** A missing or failed tool means PARTIAL. Say which tool, not "no issues".
5. Findings are **candidates**. Say so; this is not a certification or a pentest.

## One-time setup (check, then ask the user before installing)

```bash
command -v semgrep gitleaks osv-scanner nuclei      # what is missing?
brew install semgrep gitleaks osv-scanner nuclei    # macOS; Linux: each tool's official installer
nuclei -update-templates                            # one-time template download
python3 fetch_rules.py                              # one-time Semgrep rules download into rules/
```

Python 3.9+ stdlib only. After setup, scans run offline (Semgrep `--metrics=off` on local rules, osv-scanner offline DB, nuclei `-ni` with no OAST callbacks).

## Procedure

1. **Source scan (white-box)**
   ```bash
   python3 guardian.py scan /path/to/app --authorized > /tmp/guardian-scan.json; echo "exit=$?"
   ```
   Covers risky code patterns in 20+ languages, secrets in the working tree and git history, vulnerable dependencies (lockfiles/manifests), and Python AST checks.

2. **Run the app locally**, then black-box it:
   ```bash
   python3 guardian.py blackbox http://127.0.0.1:3000/ --authorized
   ```
   Checks CSP / framing / nosniff, cookie flags, `/../` traversal, CORS wildcard. Uses 4 GETs.

3. **Active signature check** (optional, takes minutes):
   ```bash
   python3 guardian.py attack http://127.0.0.1:3000/ --authorized
   ```
   Uses nuclei http templates, with dos, fuzz and intrusive tags excluded. Finds exposed `.git/config`, `.env` and known-CVE signatures.

4. **Stop the local server** you started.

## Exit codes

`0` nothing found (all tools ran) · `1` candidates found · `2` refused (no `--authorized` or non-loopback target) · `3` partial (tool missing or failed). **Not** safe.

## Reporting to the user

- Group findings by severity, then by mode. For each one give the file:line or path, what it means in plain words, and the concrete fix.
- Triage before alarming. A key in `.env` that git ignores is expected; a key in **git history** is not, so recommend rotating it. A vulnerable package in an unused or undeployed folder is lower priority. Say which applies.
- Common fixes: add the missing headers (CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`), confine static file serving to the public dir (resolve the path, require it to start with `PUBLIC_DIR + sep`), drop `Access-Control-Allow-Origin: *` unless the API is meant to be public, upgrade the flagged packages, and rotate leaked keys.
- **robots.txt (crawler opt-out).** If the user doesn't want the site crawled or scraped, create `robots.txt` in the static/public root (the folder served at `/`):
  ```
  User-agent: *
  Disallow: /
  ```
  Then verify `GET http://127.0.0.1:PORT/robots.txt` returns 200 with that body (add a `text/plain` MIME type if the server lacks `.txt`). Tell the user its limit: only well-behaved bots obey it. It is **not** access control, and it also removes the site from search engines. It never replaces the headers above.
- After a fix, **re-run the same mode** and show before/after counts.
- Do not apply fixes, rewrite git history or redeploy without the user's go-ahead.

## Self-test

```bash
python3 reports/run_tests.py   # unit tests + mutation testing; GATE_EXIT must be 0
```
