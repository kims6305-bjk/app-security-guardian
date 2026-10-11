#!/usr/bin/env python3
"""origin-security v0.2 — two bounded defensive modes (stdlib only).

  origin.py whitebox SOURCE --authorized   static AST scan of LOCAL Python source (never imported/executed)
  origin.py blackbox URL --authorized      = runner.py: one GET to http://127.0.0.1:PORT/path, header hardening

Whitebox scope (hard limits, by design):
  * Python (*.py) only, read via ast.parse. Scanned code is never imported, executed or subprocess'd.
  * Flags bounded syntactic CANDIDATES: eval/exec, subprocess shell=True (import aliases resolved),
    verify=False, .run(debug=True). No dataflow/taint, no reachability, no auth proof.
  * Findings carry relative path, line, rule, confidence, description, remediation — never source text.
  * Clean (exit 0) only when >=1 file was scanned and coverage is complete.
"""
import argparse
import ast
import json
import os
import stat
import sys

import runner

VERSION = "0.2.0"
MAX_FILES = 2000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
SKIP_DIRS = {".git", "upstream", "venv", ".venv", "env", "node_modules", "__pycache__", "site-packages",
             ".tox", ".mypy_cache", ".pytest_cache", "build", "dist", "generated", ".fablize"}
SUBPROCESS_FUNCS = {"subprocess." + f for f in ("run", "call", "check_call", "check_output", "Popen")}

RULES = {
    "PY-EVAL": ("eval()/exec() call ({how} argument)",
                "Avoid eval/exec; use ast.literal_eval, json, or an explicit dispatch table."),
    "PY-SUBPROCESS-SHELL": ("{fn}(..., shell=True)",
                            "Pass an argument list with shell=False; never build shell strings from input."),
    "PY-TLS-VERIFY-OFF": ("TLS certificate verification disabled (verify=False){where}",
                          "Remove verify=False; use a CA bundle path for private CAs."),
    "PY-DEBUG-RUN": (".run(debug=True) — likely a web framework debug server",
                     "Gate debug on an env flag that is off by default; never expose the debugger."),
}


def _aliases(tree):
    """name -> qualified name from every import in the module. ponytail: flow-insensitive, ignores rebinding."""
    m = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                m[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                m[a.asname or a.name] = f"{n.module}.{a.name}"
    return m


def _qual(node, al):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(al.get(node.id, node.id))
    return ".".join(reversed(parts))


def _kw_const(call, name, value):
    return any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is value for k in call.keywords)


def scan_tree(tree):
    """Yield (line, rule, confidence, description-args). Pure; works on a parsed AST only."""
    al = _aliases(tree)
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        q = _qual(n.func, al) or ""
        if q in ("eval", "exec", "builtins.eval", "builtins.exec"):
            lit = bool(n.args) and isinstance(n.args[0], ast.Constant)
            yield n.lineno, "PY-EVAL", "low" if lit else "medium", {"how": "literal" if lit else "dynamic"}
        if q in SUBPROCESS_FUNCS and _kw_const(n, "shell", True):
            yield n.lineno, "PY-SUBPROCESS-SHELL", "medium", {"fn": q}
        if _kw_const(n, "verify", False):
            known = q.split(".")[0] in ("requests", "httpx")
            yield n.lineno, "PY-TLS-VERIFY-OFF", "high" if known else "medium", \
                {"where": f" in {q.split('.')[0]} call" if known else ""}
        if isinstance(n.func, ast.Attribute) and n.func.attr == "run" and _kw_const(n, "debug", True):
            yield n.lineno, "PY-DEBUG-RUN", "medium", {}


def _read_py(path):
    """Read a regular file without following symlinks. Returns bytes or raises OSError/ValueError."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        if st.st_size > MAX_FILE_BYTES:
            raise ValueError("file too large")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("file too large")
    return data


def whitebox(root, authorized):
    """Returns (exit_code, report). Touches the filesystem only after authorization + root validation.
    Exit: 0 clean+complete, 1 candidates, 2 refused, 3 partial coverage w/o candidates, 4 NOT_CHECKED."""
    base = {"tool": "origin-security", "mode": "whitebox", "version": VERSION,
            "limits": {"language": "Python (*.py) only", "max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES,
                       "max_total_bytes": MAX_TOTAL_BYTES, "execution": "never imports/executes scanned code",
                       "analysis": "syntactic candidates only; no dataflow, no reachability, no auth proof",
                       "skipped_dirs": sorted(SKIP_DIRS), "symlinks": "never followed"}}
    if not authorized:
        return 2, {**base, "ok": False, "error": "refused: --authorized not given (nothing read)"}
    if not isinstance(root, str) or not root or "\x00" in root or ".." in root.replace("\\", "/").split("/"):
        return 2, {**base, "ok": False, "error": "refused: root must be an explicit path without '..'"}
    try:
        st = os.lstat(root)
    except OSError:
        return 2, {**base, "ok": False, "error": "refused: root does not exist or is not accessible"}
    if stat.S_ISLNK(st.st_mode):
        return 2, {**base, "ok": False, "error": "refused: root is a symlink"}
    real_root = os.path.realpath(root)
    base["root"] = root
    findings, errors = [], []
    skipped = {"unsupported_files": 0, "symlinks": 0, "dirs": 0, "limit": 0}
    scanned = total = 0

    def scan_file(path, rel):
        nonlocal scanned, total
        if scanned >= MAX_FILES or total >= MAX_TOTAL_BYTES:
            skipped["limit"] += 1
            return
        if os.path.commonpath([real_root, os.path.realpath(path)]) != real_root:
            errors.append({"path": rel, "kind": "outside root"})
            return
        try:
            data = _read_py(path)
            tree = ast.parse(data, filename=rel)
        except (OSError, ValueError) as e:  # ValueError: size / non-regular / NUL bytes
            errors.append({"path": rel, "kind": "unreadable" if isinstance(e, OSError)
                           else "rejected (size, file type, NUL bytes or encoding)"})
            return
        except SyntaxError as e:  # e.text (source) deliberately not reported
            errors.append({"path": rel, "kind": "syntax error", "line": e.lineno})
            return
        except (RecursionError, MemoryError):
            errors.append({"path": rel, "kind": "too complex to parse"})
            return
        scanned += 1
        total += len(data)
        for line, rule, conf, args in scan_tree(tree):
            desc, fix = RULES[rule]
            findings.append({"path": rel, "line": line, "rule": rule, "confidence": conf,
                             "description": "candidate: " + desc.format(**args), "remediation": fix})

    if stat.S_ISREG(st.st_mode):
        if root.endswith(".py"):
            scan_file(root, os.path.basename(root))
        else:
            skipped["unsupported_files"] += 1
    elif stat.S_ISDIR(st.st_mode):
        def onerror(e):
            errors.append({"path": os.path.relpath(e.filename, root) if e.filename else ".", "kind": "unreadable dir"})
        for d, dirs, files in os.walk(root, onerror=onerror, followlinks=False):
            keep = []
            for x in sorted(dirs):
                if x in SKIP_DIRS:
                    skipped["dirs"] += 1
                elif os.path.islink(os.path.join(d, x)):
                    skipped["symlinks"] += 1
                else:
                    keep.append(x)
            dirs[:] = keep
            for f in sorted(files):
                p = os.path.join(d, f)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                if os.path.islink(p):
                    skipped["symlinks"] += 1
                elif not f.endswith(".py"):
                    skipped["unsupported_files"] += 1
                else:
                    scan_file(p, rel)
    else:
        return 2, {**base, "ok": False, "error": "refused: root is neither a regular file nor a directory"}

    partial = bool(errors or skipped["limit"])
    counts = {"files_scanned": scanned, "bytes_scanned": total, "skipped": skipped, "errors": len(errors),
              "findings": len(findings)}
    rep = {**base, "counts": counts, "errors": errors, "findings": findings,
           "coverage": "none" if not scanned else "partial" if partial else "complete"}
    if not scanned:
        return 4, {**rep, "ok": False, "verdict": "NOT_CHECKED — no Python file was successfully scanned"}
    if findings:
        return 1, {**rep, "ok": True, "verdict": "candidates found (review each; not proven vulnerabilities)"
                   + ("; coverage PARTIAL" if partial else "")}
    if partial:
        return 3, {**rep, "ok": False, "verdict": "PARTIAL — no candidates in scanned files, but coverage incomplete"}
    return 0, {**rep, "ok": True, "verdict": "no candidates for these 4 rules — not a security certification"}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["blackbox"]:
        return runner.main(argv[1:])
    ap = argparse.ArgumentParser(prog="origin.py", description="origin.py {whitebox SOURCE|blackbox URL} --authorized")
    ap.add_argument("mode", choices=["whitebox", "blackbox"])
    ap.add_argument("source", help="local Python file or directory you own")
    ap.add_argument("--authorized", action="store_true", help="I own/am authorized to review this source")
    a = ap.parse_args(argv)
    code, rep = whitebox(a.source, a.authorized)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
