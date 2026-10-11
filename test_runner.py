"""unittest for runner.py. Network: only an ephemeral 127.0.0.1 server owned by this test."""
import http.client
import http.server
import io
import json
import os
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

import runner

SECRET = "s3cr3t-session-VALUE-zz"
HITS = []


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS.append(self.path)
        if self.path == "/bad":
            self.send_response(200)
            self.send_header("Set-Cookie", f"sid={SECRET}; Path=/")
            self.send_header("Content-Security-Policy-Report-Only", "default-src 'self'")
            body = b"<html>bad</html>" * 10000   # > MAX_BODY -> bounded read
        elif self.path == "/good":
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", f"sid={SECRET}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("X-Secret-Internal", SECRET)  # not allowlisted -> must not appear
            body = b"<html>good</html>"
        elif self.path == "/weak":
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src * 'unsafe-inline'")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-Content-Type-Options", "nosniff")
            body = b"weak"
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/good")
            body = b""
        else:
            self.send_response(404)
            body = b""
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        HITS.clear()

    def ids(self, rep):
        return {f["id"] for f in rep["findings"]}

    def test_bad_vs_good_contrast(self):
        cb, bad = runner.run(self.base + "/bad", True)
        cg, good = runner.run(self.base + "/good", True)
        self.assertEqual((cb, cg), (1, 0))
        self.assertEqual(self.ids(bad), {"csp", "frame", "nosniff", "cookies"})
        self.assertEqual(good["findings"], [])
        self.assertEqual(bad["checks_count"], 5)
        self.assertEqual(good["checks_count"], 5)
        self.assertIn("Report-Only", next(f for f in bad["findings"] if f["id"] == "csp")["detail"])
        self.assertEqual(bad["evidence"]["body_bytes_read"], runner.MAX_BODY)  # bounded
        self.assertEqual(HITS, ["/bad", "/good"])  # exactly one GET each
        tr = next(c for c in good["checks"] if c["id"] == "transport")
        self.assertEqual(tr["status"], "n/a")
        self.assertNotIn("secure", good["verdict"].split("—")[0].lower())

    def test_weak_csp(self):
        code, rep = runner.run(self.base + "/weak", True)
        self.assertEqual(code, 1)
        self.assertEqual(self.ids(rep), {"csp"})

    def test_no_secrets_or_bodies_in_report(self):
        for p in ("/bad", "/good"):
            _, rep = runner.run(self.base + p, True)
            s = json.dumps(rep)
            self.assertNotIn(SECRET, s)
            self.assertNotIn("<html>", s)
            self.assertNotIn("x-secret-internal", s.lower())
            self.assertEqual(rep["evidence"]["cookies"][0]["name"], "sid")

    def test_redirect_not_followed(self):
        code, rep = runner.run(self.base + "/redir", True)
        self.assertEqual(code, 3)
        self.assertFalse(rep["ok"])
        self.assertNotIn("findings", rep)
        self.assertEqual(HITS, ["/redir"])

    def test_request_failure_is_not_success(self):
        s = http.server.HTTPServer(("127.0.0.1", 0), Fixture)
        dead = s.server_address[1]
        s.server_close()  # port now closed
        code, rep = runner.run(f"http://127.0.0.1:{dead}/", True)
        self.assertEqual(code, 3)
        self.assertFalse(rep["ok"])
        self.assertNotIn("verdict", rep)

    def test_proxy_env_ignored(self):
        env = {k: "http://203.0.113.1:9" for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")}
        with mock.patch.dict(os.environ, env):
            code, rep = runner.run(self.base + "/good", True)
        self.assertEqual(code, 0)
        self.assertEqual(HITS, ["/good"])

    BAD_URLS = [
        "http://localhost:{p}/", "https://127.0.0.1:{p}/", "HTTP://127.0.0.1:{p}/", "ftp://127.0.0.1:{p}/",
        "http://127.0.0.2:{p}/", "http://[::1]:{p}/", "http://2130706433:{p}/", "http://0x7f.0.0.1:{p}/",
        "http://127.0.0.1.nip.io:{p}/", "http://example.com/", "http://user:pw@127.0.0.1:{p}/",
        "http://127.0.0.1:{p}@evil.com/", "http://127.0.0.1:{p}/?q=1", "http://127.0.0.1:{p}/#f",
        "http://127.0.0.1:{p}/a b", "http://127.0.0.1:{p}/\r\nX: y", "http://127.0.0.1:{p}/\x00",
        "http://127.0.0.1:{p}/\u00e9", "http://127.0.0.1/", "http://127.0.0.1:/", "http://127.0.0.1:0/",
        "http://127.0.0.1:65536/", "http://127.0.0.1:0{p}/", "http://127.0.0.1:{p}x/", "//127.0.0.1:{p}/",
        "127.0.0.1:{p}", "http://127.0.0.1:{p}\\@evil.com/", "", " http://127.0.0.1:{p}/",
    ]

    def test_refusals_make_no_network_call(self):
        boom = mock.Mock(side_effect=AssertionError("network attempted"))
        with mock.patch.object(http.client, "HTTPConnection", boom):
            for u in self.BAD_URLS:
                u = u.format(p=self.port)
                code, rep = runner.run(u, True)
                self.assertEqual(code, 2, u)
                self.assertIn("refused", rep["error"], u)
            code, rep = runner.run(self.base + "/good", False)  # valid URL, no authorization
            self.assertEqual(code, 2)
            self.assertIn("--authorized", rep["error"])
        boom.assert_not_called()
        self.assertEqual(HITS, [])

    def test_valid_url_forms(self):
        self.assertEqual(runner.validate_url("http://127.0.0.1:8080"), (8080, "/"))
        self.assertEqual(runner.validate_url("http://127.0.0.1:65535/a/b%20c"), (65535, "/a/b%20c"))

    def test_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = runner.main([self.base + "/good"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(buf.getvalue())["ok"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = runner.main([self.base + "/bad", "--authorized"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(buf.getvalue())["findings_count"], 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
