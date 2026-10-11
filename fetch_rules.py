"""One-time download of Semgrep registry rule packs to rules/ (code never leaves the machine).
Re-run to refresh rules. Afterwards scans use only the local files (--metrics=off)."""
import hashlib, json, pathlib, urllib.request

PACKS = ["default", "javascript", "nodejs", "secrets", "xss", "python"]
out = pathlib.Path(__file__).parent / "rules"
out.mkdir(exist_ok=True)
manifest = {}
for p in PACKS:
    req = urllib.request.Request(f"https://semgrep.dev/c/p/{p}", headers={"User-Agent": "semgrep/1.180.0"})
    data = urllib.request.urlopen(req, timeout=60).read()
    f = out / f"p-{p}.yml"
    f.write_bytes(data)
    manifest[p] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "rules": data.count(b"\n- id:") + data.count(b"\n  - id:")}
    print(p, manifest[p]["bytes"], "bytes", manifest[p]["rules"], "rules")
(out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
