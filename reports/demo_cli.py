"""Demo: start own synthetic fixture on ephemeral 127.0.0.1 and run the real CLI against it."""
import http.server, json, os, pathlib, subprocess, sys, threading

here = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here))
from test_runner import Fixture  # noqa: E402

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
threading.Thread(target=srv.serve_forever, daemon=True).start()
res = {}
for p in ("/bad", "/good"):
    url = f"http://127.0.0.1:{srv.server_address[1]}{p}"
    r = subprocess.run([sys.executable, str(here / "runner.py"), url, "--authorized"], capture_output=True, text=True,
                       env={"HTTP_PROXY": "http://203.0.113.1:9", "PATH": "/usr/bin:/bin"})
    res[p] = {"exit": r.returncode, "report": json.loads(r.stdout)}
r = subprocess.run([sys.executable, str(here / "runner.py"), "http://example.com/", "--authorized"], capture_output=True, text=True)
res["external"] = {"exit": r.returncode, "report": json.loads(r.stdout)}
srv.shutdown()
import tempfile  # noqa: E402
from test_origin import VULN, SAFE, SENTINEL  # noqa: E402
with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as d:
    for n, t in (("vuln.py", VULN), ("safe.py", SAFE)):
        pathlib.Path(d, n).write_text(t)
    for k, a in (("whitebox", ["--authorized"]), ("whitebox-unauth", [])):
        r = subprocess.run([sys.executable, str(here / "origin.py"), "whitebox", d, *a], capture_output=True, text=True)
        assert SENTINEL not in r.stdout and not pathlib.Path(d, "EXECUTED_MARKER").exists()
        rep = json.loads(r.stdout)
        rep.pop("root", None)  # temp path
        res[k] = {"exit": r.returncode, "report": rep}
(here / "reports" / "sample-cli.json").write_text(json.dumps(res, ensure_ascii=False, indent=2))
print({k: (v["exit"], v["report"].get("findings_count"), v["report"].get("error")) for k, v in res.items()})
