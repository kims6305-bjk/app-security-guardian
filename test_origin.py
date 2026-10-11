"""v0.2 tests: origin.py whitebox + blackbox hardening. Original test_runner.py is untouched.
Source fixtures are synthetic, written to a temp dir under $TMPDIR.
Network: only an ephemeral 127.0.0.1 server owned by this test."""
import builtins
import http.client
import http.server
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

import origin
import runner

SENTINEL = "SENTINEL-sk-live-9f8e7d6c5b4a"
MARKER_NAME = "EXECUTED_MARKER"

VULN = f'''
import subprocess as sp
from subprocess import Popen as P
import requests, os
API_KEY = "{SENTINEL}"
open(os.path.join(os.path.dirname(__file__), "{MARKER_NAME}"), "w").write("ran")  # must never run
def f(user):
    eval(user)
    exec("x = 1")
    sp.run(user, shell=True)
    P(user, shell=True)
    requests.get("https://x.invalid", verify=False, headers={{"k": API_KEY}})
    app.run(debug=True)
'''
SAFE = f'''
import subprocess, json, ast
TOKEN = "{SENTINEL}"
def f(user):
    ast.literal_eval(user)
    subprocess.run(["ls", user], shell=False)
    json.loads(user)
    app.run(debug=False)
'''


class Whitebox(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="origin-wb-", dir=os.environ.get("TMPDIR"))
        self.outside = tempfile.mkdtemp(prefix="origin-out-", dir=os.environ.get("TMPDIR"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def w(self, rel, text, base=None):
        p = os.path.join(base or self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def rules(self, rep):
        return sorted((f["path"], f["rule"]) for f in rep["findings"])

    def test_vulnerable_vs_safe_and_no_execution(self):
        self.w("app/vuln.py", VULN)
        self.w("app/safe.py", SAFE)
        real_socket = socket.socket
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")):
            code, rep = origin.whitebox(self.d, True)
        self.assertIs(socket.socket, real_socket)
        self.assertEqual(code, 1)
        self.assertEqual(self.rules(rep), sorted([
            ("app/vuln.py", "PY-EVAL"), ("app/vuln.py", "PY-EVAL"),
            ("app/vuln.py", "PY-SUBPROCESS-SHELL"), ("app/vuln.py", "PY-SUBPROCESS-SHELL"),
            ("app/vuln.py", "PY-TLS-VERIFY-OFF"), ("app/vuln.py", "PY-DEBUG-RUN")]))
        conf = {(f["rule"], f["description"]): f["confidence"] for f in rep["findings"]}
        self.assertEqual(conf[("PY-EVAL", "candidate: eval()/exec() call (dynamic argument)")], "medium")
        self.assertEqual(conf[("PY-EVAL", "candidate: eval()/exec() call (literal argument)")], "low")
        fns = {f["description"] for f in rep["findings"] if f["rule"] == "PY-SUBPROCESS-SHELL"}
        self.assertEqual(fns, {"candidate: subprocess.run(..., shell=True)", "candidate: subprocess.Popen(..., shell=True)"})
        self.assertEqual(next(f for f in rep["findings"] if f["rule"] == "PY-TLS-VERIFY-OFF")["confidence"], "high")
        self.assertEqual(next(f for f in rep["findings"] if f["rule"] == "PY-EVAL" and "dynamic" in f["description"])["line"], 8)
        self.assertEqual(rep["counts"]["files_scanned"], 2)
        self.assertEqual(rep["coverage"], "complete")
        self.assertFalse(os.path.exists(os.path.join(self.d, "app", MARKER_NAME)))  # scanned code never ran
        self.assertNotIn("vuln", sys.modules)
        s = json.dumps(rep)
        for leak in (SENTINEL, "x.invalid", "x = 1", MARKER_NAME, "API_KEY", self.outside):
            self.assertNotIn(leak, s)
        self.assertTrue(all(set(f) == {"path", "line", "rule", "confidence", "description", "remediation"}
                            for f in rep["findings"]))

    def test_safe_only_is_clean(self):
        self.w("safe.py", SAFE)
        self.w("README.txt", "x")
        code, rep = origin.whitebox(self.d, True)
        self.assertEqual((code, rep["findings"], rep["coverage"]), (0, [], "complete"))
        self.assertEqual(rep["counts"]["skipped"]["unsupported_files"], 1)
        code, rep = origin.whitebox(os.path.join(self.d, "safe.py"), True)  # explicit single file root
        self.assertEqual((code, rep["counts"]["files_scanned"]), (0, 1))

    def test_missing_authorization_opens_nothing(self):
        self.w("vuln.py", VULN)
        with mock.patch.object(builtins, "open", side_effect=AssertionError("open")), \
                mock.patch.object(os, "open", side_effect=AssertionError("os.open")), \
                mock.patch.object(os, "lstat", side_effect=AssertionError("lstat")), \
                mock.patch.object(os, "walk", side_effect=AssertionError("walk")):
            code, rep = origin.whitebox(self.d, False)
        self.assertEqual(code, 2)
        self.assertIn("--authorized", rep["error"])
        self.assertNotIn("findings", rep)

    def test_symlinks_cannot_escape(self):
        secret = self.w("secret.py", f'eval(x)  # {SENTINEL}\n', base=self.outside)
        self.w("ok.py", "x = 1\n")
        os.symlink(secret, os.path.join(self.d, "link.py"))
        os.symlink(self.outside, os.path.join(self.d, "linkdir"))
        code, rep = origin.whitebox(self.d, True)
        self.assertEqual(code, 0)
        self.assertEqual(rep["counts"]["skipped"]["symlinks"], 2)
        self.assertEqual(rep["counts"]["files_scanned"], 1)
        self.assertEqual(rep["findings"], [])
        rootlink = os.path.join(self.outside, "rootlink")
        os.symlink(self.d, rootlink)
        code, rep = origin.whitebox(rootlink, True)
        self.assertEqual(code, 2)
        self.assertIn("symlink", rep["error"])
        code, rep = origin.whitebox(os.path.join(self.d, "..", os.path.basename(self.outside)), True)
        self.assertEqual(code, 2)
        self.assertNotIn(SENTINEL, json.dumps(rep))

    def test_empty_unsupported_and_missing_roots_never_pass(self):
        code, rep = origin.whitebox(self.d, True)  # empty dir
        self.assertEqual((code, rep["coverage"]), (4, "none"))
        self.assertIn("NOT_CHECKED", rep["verdict"])
        self.w("a.js", "eval(x)")
        self.w("node_modules/x.py", "eval(x)")
        self.w("upstream/y.py", "eval(x)")
        self.w(".git/z.py", "eval(x)")
        code, rep = origin.whitebox(self.d, True)  # unsupported/skipped only
        self.assertEqual(code, 4)
        self.assertEqual(rep["counts"]["skipped"]["dirs"], 3)
        code, rep = origin.whitebox(os.path.join(self.d, "a.js"), True)
        self.assertEqual(code, 4)
        code, rep = origin.whitebox(os.path.join(self.d, "nope"), True)
        self.assertEqual(code, 2)

    def test_syntax_invalid_is_surfaced_not_clean(self):
        self.w("bad.py", f'def (:\n  "{SENTINEL}"\n')
        code, rep = origin.whitebox(self.d, True)
        self.assertEqual(code, 4)  # only file broken -> nothing checked
        self.assertEqual(rep["errors"], [{"path": "bad.py", "kind": "syntax error", "line": 1}])
        self.w("good.py", "x = 1\n")
        self.w("nul.py", "x = 1\x00\n")
        code, rep = origin.whitebox(self.d, True)
        self.assertEqual((code, rep["coverage"], rep["counts"]["errors"]), (3, "partial", 2))
        self.assertFalse(rep["ok"])
        self.assertNotIn(SENTINEL, json.dumps(rep))
        self.w("v.py", "eval(x)\n")
        code, rep = origin.whitebox(self.d, True)
        self.assertEqual(code, 1)
        self.assertIn("PARTIAL", rep["verdict"])

    def test_limits_make_partial(self):
        self.w("a.py", "x = 1\n")
        self.w("b.py", "y = 2\n")
        with mock.patch.object(origin, "MAX_FILES", 1):
            code, rep = origin.whitebox(self.d, True)
        self.assertEqual((code, rep["counts"]["skipped"]["limit"]), (3, 1))
        with mock.patch.object(origin, "MAX_FILE_BYTES", 3):
            code, rep = origin.whitebox(self.d, True)
        self.assertEqual(code, 4)

    def test_cli_dispatch(self):
        self.w("v.py", VULN)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = origin.main(["whitebox", self.d, "--authorized"])
        self.assertEqual(code, 1)
        self.assertNotIn(SENTINEL, buf.getvalue())
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = origin.main(["whitebox", self.d])
        self.assertEqual(code, 2)
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.object(http.client, "HTTPConnection",
                                                      side_effect=AssertionError("network")):
            code = origin.main(["blackbox", "http://example.com/", "--authorized"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(buf.getvalue())["mode"], "blackbox")


COOKIE_SECRET = "c00kie-SECRET-vv"
NONCE = "n0nce-SECRET-abc"


class Fixture2(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Fixture2.hits.append(self.path)
        hdrs = {
            "/fa-star": [("Content-Security-Policy", "default-src 'self'; frame-ancestors *"),
                         ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff")],
            "/fa-ok": [("Content-Security-Policy", f"default-src 'self'; script-src 'nonce-{NONCE}'; frame-ancestors 'self'"),
                       ("X-Content-Type-Options", "nosniff"),
                       ("Set-Cookie", f"sid={COOKIE_SECRET}; HttpOnly; SameSite=Strict")],
            "/samesite-junk": [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                               ("X-Content-Type-Options", "nosniff"),
                               ("Set-Cookie", f"sid=v; HttpOnly; SameSite={COOKIE_SECRET}"),
                               ("Set-Cookie", f"{COOKIE_SECRET}<x>=v; HttpOnly; SameSite=Lax")],
        }
        status = 200 if self.path in hdrs else 500 if self.path == "/err" else 404
        self.send_response(status)
        for k, v in hdrs.get(self.path, [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                                         ("X-Content-Type-Options", "nosniff")]):
            self.send_header(k, v)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class Blackbox2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture2)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Fixture2.hits.clear()

    def test_frame_ancestors_wildcard_is_not_pass(self):
        code, rep = runner.run(self.base + "/fa-star", True)
        self.assertEqual(code, 1)
        self.assertEqual({f["id"] for f in rep["findings"]}, {"frame"})  # XFO DENY does not rescue it
        code, rep = runner.run(self.base + "/fa-ok", True)
        self.assertEqual((code, rep["findings"]), (0, []))
        s = json.dumps(rep)
        self.assertNotIn(NONCE, s)
        self.assertNotIn(COOKIE_SECRET, s)
        self.assertIn("'nonce-REDACTED'", s)

    def test_non_2xx_is_not_clean(self):
        for p, st in (("/err", 500), ("/missing", 404)):
            code, rep = runner.run(self.base + p, True)
            self.assertEqual(code, 3, p)
            self.assertFalse(rep["ok"])
            self.assertNotIn("verdict", rep)
            self.assertEqual(rep["evidence"]["status"], st)

    def test_samesite_and_cookie_name_sanitized(self):
        code, rep = runner.run(self.base + "/samesite-junk", True)
        self.assertEqual(code, 1)
        self.assertNotIn(COOKIE_SECRET, json.dumps(rep))
        cs = rep["evidence"]["cookies"]
        self.assertEqual([c["samesite"] for c in cs], ["invalid", "Lax"])
        self.assertEqual(cs[1]["name"], "(invalid-name)")

    def test_rejected_url_not_echoed(self):
        u = f"http://admin:{COOKIE_SECRET}@127.0.0.1:{self.srv.server_address[1]}/"
        for auth in (True, False):
            code, rep = runner.run(u, auth)
            self.assertEqual(code, 2)
            self.assertNotIn(COOKIE_SECRET, json.dumps(rep))
        self.assertEqual(Fixture2.hits, [])
        _, rep = runner.run(self.base + "/fa-ok", True)
        self.assertEqual(rep["url"], self.base + "/fa-ok")  # accepted URL still echoed
        self.assertIn("mutation", rep["limits"])

    def test_body_deadline_bounds_slow_drip(self):
        with mock.patch.object(runner, "BODY_DEADLINE_S", -1):
            code, rep = runner.run(self.base + "/fa-ok", True)
        self.assertTrue(rep["evidence"]["body_deadline_hit"])
        self.assertEqual(rep["evidence"]["body_bytes_read"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
