"""Regenerate reports/: unittest output + mutation checks (tests must FAIL on a broken runner/origin)."""
import os, pathlib, shutil, subprocess, sys, tempfile

here = pathlib.Path(__file__).resolve().parent.parent
FILES = ("runner.py", "origin.py", "test_runner.py", "test_origin.py")
out = []
r = subprocess.run([sys.executable, "-m", "unittest", "-v", "test_runner", "test_origin"], cwd=here,
                   capture_output=True, text=True)
out.append(f"## unittest (exit {r.returncode})\n{r.stderr}")
MUTANTS = {  # name -> (file, old, new)
    "allow localhost": ("runner.py", r'http://127\.0\.0\.1:', r'http://(?:127\.0\.0\.1|localhost):'),
    "skip authorization": ("runner.py", "if not authorized:", "if False:"),
    "frame-ancestors * passes": ("runner.py", "if fa and fa_weak:", "if False:"),
    "non-2xx evaluated": ("runner.py", "if not 200 <= status < 300:", "if False:"),
    "raw SameSite echoed": ("runner.py", '_SAMESITE.get(ss.lower(), "invalid")', "ss"),
    "rejected URL echoed": ("runner.py", '"(rejected; not echoed)"', "url"),
    "no body deadline": ("runner.py", "truncated = True\n                break", "pass"),
    "wb skip authorization": ("origin.py", "    if not authorized:\n        return 2", "    if False:\n        return 2"),
    "wb follow symlinks": ("origin.py", "if os.path.islink(p):", "if False:"),
    "wb symlink root ok": ("origin.py", "if stat.S_ISLNK(st.st_mode):", "if False:"),
    "wb no alias resolution": ("origin.py", "parts.append(al.get(node.id, node.id))", "parts.append(node.id)"),
    "wb empty root clean": ("origin.py", "    if not scanned:\n        return 4", "    if False:\n        return 4"),
    "wb partial is clean": ("origin.py", "    if partial:\n        return 3", "    if False:\n        return 3"),
    "wb no skip dirs": ("origin.py", "if x in SKIP_DIRS:", "if False:"),
    "wb source text in finding": ("origin.py", '"remediation": fix}', '"remediation": fix, "src": data.decode("latin-1")}'),
    "wb executes scanned code": ("origin.py", "            tree = ast.parse(data, filename=rel)",
                                 "            tree = ast.parse(data, filename=rel)\n"
                                 "            exec(compile(data, rel, 'exec'), {'__file__': path})"),
}
killed = 0
for name, (fn, old, new) in MUTANTS.items():
    src = (here / fn).read_text()
    assert src.count(old) == 1, name
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as d:
        for f in FILES:
            shutil.copy(here / f, d)
        (pathlib.Path(d) / fn).write_text(src.replace(old, new))
        m = subprocess.run([sys.executable, "-m", "unittest", "test_runner", "test_origin"], cwd=d,
                           capture_output=True, text=True, timeout=120)
        killed += bool(m.returncode)
        out.append(f"## mutant '{name}': tests exit {m.returncode} -> {'KILLED' if m.returncode else 'SURVIVED'}")
out.append(f"## mutants killed {killed}/{len(MUTANTS)}")
(here / "reports").mkdir(exist_ok=True)
(here / "reports" / "test-results.txt").write_text(f"python {sys.version.split()[0]}\n" + "\n".join(out) + "\n")
print("\n".join(out))
# v0.3 gate: guardian multi-tool tests + guardian mutants
g = subprocess.run([sys.executable, "-m", "unittest", "test_guardian"], cwd=here, capture_output=True, text=True)
gm = subprocess.run([sys.executable, str(here / "reports" / "mutants_guardian.py")], cwd=here, capture_output=True, text=True)
print(f"## guardian unittest exit {g.returncode}\n{g.stderr.strip().splitlines()[-3:]}\n## guardian mutants\n{gm.stdout}")
sys.exit(0 if r.returncode == 0 and killed == len(MUTANTS) and g.returncode == 0 and gm.returncode == 0 else 1)
