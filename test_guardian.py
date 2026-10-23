"""Tests for guardian.py (multi-tool scan + extra blackbox probes). Synthetic fixtures only.
Run: python3 -m unittest -v test_guardian"""
import http.server, os, threading, unittest
import guardian

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def serve(handler):
    s = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Vuln(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        files = {"/": b"<html>ok</html>", "/../package.json": b'{"name":"secret-pkg"}', "/api/auth/status": b'{"initialized": false}',
                 "/.git/config": b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n'}
        body = files.get(self.path, b"nf")
        self.send_response(200 if self.path in files else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers(); self.wfile.write(body)


class Safe(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/api/auth/status":  # admin already claimed -> not a finding
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"initialized": true}'); return
        ok = self.path == "/"
        self.send_response(200 if ok else 404)
        for k, v in (("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY")):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(b"<html>ok</html>" if ok else b"404")


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vcode, cls.v = guardian.scan(os.path.join(FX, "vuln-js"), True)
        cls.scode, cls.s = guardian.scan(os.path.join(FX, "safe-js"), True)

    def test_refused_without_authorized(self):
        self.assertEqual(guardian.scan(os.path.join(FX, "vuln-js"), False)[0], 2)

    def test_each_tool_catches_vuln_fixture(self):
        self.assertEqual(self.vcode, 1)
        bt = self.v["by_tool"]
        for t in ("semgrep", "gitleaks", "osv-scanner"):
            self.assertGreater(bt[t]["findings"], 0, t)
        rules = {f["rule"] for f in self.v["tools"][0]["findings"]}
        self.assertIn("eval-detected", rules)
        self.assertIn("detect-child-process", rules)

    def test_secret_value_never_reported(self):
        import json
        raw = open(os.path.join(FX, "vuln-js", "app.js")).read()
        tok = raw.split('API_KEY = "')[1].split('"')[0]
        self.assertNotIn(tok, json.dumps(self.v))
        self.assertNotIn("eval(req.query.expr)", json.dumps(self.v))  # no source snippets

    def test_safe_fixture_has_no_high_findings(self):
        high = [f for t in self.s["tools"] for f in t["findings"] if f["severity"] == "high"]
        self.assertEqual(high, [])
        self.assertEqual(self.s["by_tool"]["gitleaks"]["findings"], 0)

    def test_custom_rules_catch_cors_and_bind_all(self):
        hits = {(f["rule"], f["path"]) for f in self.v["tools"][0]["findings"]}
        for want in (("cors-wildcard-origin", "server.go"), ("listen-all-interfaces", "server.go"),
                     ("node-listen-all-interfaces", "app.js"), ("compose-port-all-interfaces", "docker-compose.yml")):
            self.assertIn(want, hits)
        safe = {f["rule"] for f in self.s["tools"][0]["findings"]}
        self.assertFalse(safe & {"cors-wildcard-origin", "listen-all-interfaces", "node-listen-all-interfaces", "compose-port-all-interfaces"}, safe)

    def test_test_file_secret_kept_but_downgraded(self):
        gl = {f["path"]: f["severity"] for f in self.v["tools"][1]["findings"]}
        self.assertEqual(gl.get("tests/app.test.js"), "low", gl)
        self.assertEqual(gl.get("app.js"), "high", gl)

    def test_missing_rules_is_partial_not_clean(self):
        old = guardian.RULES
        guardian.RULES = ["/nonexistent.yml"]
        try:
            code, rep = guardian.scan(os.path.join(FX, "safe-js"), True)
        finally:
            guardian.RULES = old
        self.assertEqual(rep["by_tool"]["semgrep"]["status"], "error")
        self.assertIn("semgrep", rep["incomplete_tools"])
        self.assertNotEqual(code, 0)


class BlackboxTests(unittest.TestCase):
    def test_vuln_server_traversal_and_cors_flagged(self):
        s = serve(Vuln)
        try:
            code, rep = guardian.blackbox(f"http://127.0.0.1:{s.server_port}/", True)
        finally:
            s.shutdown()
        ids = {f["id"] for f in rep["findings"]}
        self.assertEqual(code, 1)
        self.assertTrue({"path-traversal", "cors", "open-setup"} <= ids, ids)
        self.assertNotIn("bind", ids)  # test server binds 127.0.0.1

    def test_safe_server_passes_extra_probes(self):
        s = serve(Safe)
        try:
            code, rep = guardian.blackbox(f"http://127.0.0.1:{s.server_port}/", True)
        finally:
            s.shutdown()
        st = {c["id"]: c["status"] for c in rep["checks"]}
        self.assertEqual((st["path-traversal"], st["cors"], st["open-setup"], st["bind"]), ("pass",) * 4)
        self.assertEqual(code, 0, rep["findings"])

    def test_attack_finds_exposed_git_config_on_vuln_only(self):
        ids = ["git-config"]
        v, s = serve(Vuln), serve(Safe)
        try:
            vc, vr = guardian.attack(f"http://127.0.0.1:{v.server_port}/", True, ids, timeout=300)
            sc, sr = guardian.attack(f"http://127.0.0.1:{s.server_port}/", True, ids, timeout=300)
        finally:
            v.shutdown(); s.shutdown()
        self.assertEqual(vc, 1, vr)
        self.assertIn("git-config", {f["rule"] for f in vr["findings"]})
        self.assertEqual((sc, sr["findings"]), (0, []))
        self.assertNotIn("repositoryformatversion", str(vr))  # response bodies not reported

    def test_attack_refuses_remote_and_unauthorized(self):
        self.assertEqual(guardian.attack("https://example.com/", True)[0], 2)
        self.assertEqual(guardian.attack("http://127.0.0.1:1/", False)[0], 2)

    def test_setup_and_bind_helpers(self):
        self.assertEqual(guardian._setup_open(b'{"initialized": false}'), "initialized")
        self.assertEqual(guardian._setup_open(b'{"needsSetup": true}'), "needsSetup")
        self.assertIsNone(guardian._setup_open(b'{"initialized": true}'))
        self.assertIsNone(guardian._setup_open(b'not json'))
        self.assertTrue(guardian._exposed(["*:8787"]))
        self.assertTrue(guardian._exposed(["127.0.0.1:8787", "100.69.33.124:8787"]))
        self.assertFalse(guardian._exposed(["127.0.0.1:8787", "[::1]:8787"]))

    def test_remote_refused(self):
        self.assertEqual(guardian.blackbox("https://example.com/", True)[0], 2)


if __name__ == "__main__":
    unittest.main()
