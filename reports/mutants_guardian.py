"""Mutation check for guardian.py: each mutant must make test_guardian fail (KILLED)."""
import os, shutil, subprocess, sys, tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTANTS = [
    ("traversal never flagged", 'leak = st == 200 and', 'leak = False and'),
    ("cors never flagged", 'bad = acao in ("*", "https://guardian-cors-probe.invalid")', 'bad = False'),
    ("gitleaks findings dropped", 'fs.append({"path": path,', 'None and fs.append({"path": path,'),
    ("semgrep error reported clean", 'return {"status": "error", "reason": "rules missing', 'return {"status": "ok", "reason": "rules missing'),
    ("open-setup never flagged", 'if k:\n                hits.append', 'if False:\n                hits.append'),
    ("bind exposure never flagged", 'return any(not (h.startswith("127.")', 'return False and any(not (h.startswith("127.")'),
    ("custom rules not loaded", '+ \\\n        [os.path.join(HERE, "rules", "guardian-custom.yml")]', ''),
    ("test-file secrets not downgraded", 'test = bool(TESTFILE.search(path))', 'test = False'),
    # (no mutant removes the loopback gate: that mutant would send real traffic to a remote host)
    ("attack --authorized gate removed", 'return 2, {**base, "error": "refused: --authorized not given (no request sent)"}', 'pass'),
    ("attack findings dropped", "fs.append({\"rule\": r.get(\"template-id\")", "None and fs.append({\"rule\": r.get(\"template-id\")"),
    ("secret value leaked (redact off + Secret echoed)", '"--redact", ', ''),
]
EXTRA = {"secret value leaked (redact off + Secret echoed)":
         ('"message": ("in a test/fixture file', '"message": r.get("Secret") or ("in a test/fixture file')}
killed = 0
for name, a, b in MUTANTS:
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as t:
        for f in ("guardian.py", "origin.py", "runner.py", "test_guardian.py"):
            shutil.copy(os.path.join(SRC, f), t)
        os.symlink(os.path.join(SRC, "rules"), os.path.join(t, "rules"))
        os.symlink(os.path.join(SRC, "fixtures"), os.path.join(t, "fixtures"))
        p = os.path.join(t, "guardian.py")
        s = open(p).read()
        assert a in s, f"mutation anchor missing: {name}"
        s = s.replace(a, b, 1)
        if name in EXTRA:
            assert EXTRA[name][0] in s
            s = s.replace(*EXTRA[name], 1)
        open(p, "w").write(s)
        rc = subprocess.run([sys.executable, "-m", "unittest", "test_guardian"], cwd=t, capture_output=True).returncode
        ok = rc != 0
        killed += ok
        print(("KILLED  " if ok else "SURVIVED"), name)
print(f"{killed}/{len(MUTANTS)} killed")
sys.exit(0 if killed == len(MUTANTS) else 1)
