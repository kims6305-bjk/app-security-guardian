"""Render docs/infographic-{ko,en}.png from one template (Chrome headless). Usage: python3 docs/make_infographic.py"""
import subprocess, sys
from pathlib import Path

D = Path(__file__).resolve().parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

T = {
 "ko": dict(kicker="내 앱을 지키는 로컬 보안 점검", title="app-security-guardian", sub="검증된 오픈소스 도구를 순서대로 돌리고, 결과를 JSON 하나로 묶습니다 · 코드는 밖으로 나가지 않습니다",
   modes=[("scan", "화이트박스 · 소스 코드", ["위험 코드 패턴 (JS·TS·Python·Go·Java…)", "비밀키 — 작업폴더 + git 기록", "알려진 취약 의존성 (npm·pip…)", "Python AST 내장 검사"], "Semgrep · gitleaks · osv-scanner"),
          ("blackbox", "블랙박스 · 응답 관찰", ["보안 헤더: CSP · 프레이밍 · nosniff", "쿠키 플래그", "경로 탈출 /../ 노출", "CORS 와일드카드"], "Python 표준 라이브러리 · GET 4회"),
          ("attack", "능동 점검 · 시그니처", ["노출된 .git/config · .env 등", "알려진 취약점 템플릿", "dos · fuzz · intrusive 제외", "외부 OAST 콜백 끔 (-ni)"], "nuclei")],
   rails_t="안전장치 (코드로 강제)", rails=["대상은 <code>http://127.0.0.1:PORT/</code> 만", "<code>--authorized</code> 없으면 요청 0건", "규칙·DB 로컬 사본, 통계 전송 끔", "비밀값·응답 본문 미기록 (<code>--redact</code>)"],
   exit_t="종료 코드", exits=[("0", "발견 없음"), ("1", "후보 발견"), ("2", "거부"), ("3", "부분 실행 ≠ 안전")],
   gate="검증: 단위 테스트 + 뮤테이션 검사 — 검사 로직을 일부러 망가뜨리면 테스트가 실패해야 통과", foot="발견 항목은 사람이 확인할 후보입니다 · 보안 인증이나 완전한 침투 테스트가 아닙니다 · 내 소유 또는 허가받은 대상에만"),
 "en": dict(kicker="Local security checks for apps you own", title="app-security-guardian", sub="Runs proven open-source scanners in sequence and merges results into one JSON · your code never leaves the machine",
   modes=[("scan", "White-box · source", ["Risky code patterns (JS·TS·Py·Go·Java…)", "Secrets — working tree + git history", "Known-vulnerable dependencies", "Built-in Python AST checks"], "Semgrep · gitleaks · osv-scanner"),
          ("blackbox", "Black-box · responses", ["Headers: CSP · framing · nosniff", "Cookie flags", "Path traversal /../ exposure", "CORS wildcard"], "Python stdlib · 4 GETs"),
          ("attack", "Active · signatures", ["Exposed .git/config, .env, …", "Known-vulnerability templates", "No dos / fuzz / intrusive", "No external OAST callbacks (-ni)"], "nuclei")],
   rails_t="Guardrails (enforced in code)", rails=["Target must be <code>http://127.0.0.1:PORT/</code>", "No <code>--authorized</code> → zero requests", "Local rules & DBs, telemetry off", "Secrets & bodies never logged (<code>--redact</code>)"],
   exit_t="Exit codes", exits=[("0", "nothing found"), ("1", "candidates"), ("2", "refused"), ("3", "partial ≠ safe")],
   gate="Verified by unit tests + mutation testing — deliberately broken checks must make the tests fail", foot="Findings are candidates for human review · not a certification or a full pentest · use only on targets you own or are authorized to test"),
}
ACC = {"scan": "#38bdf8", "blackbox": "#a78bfa", "attack": "#fb7185"}


def html(t):
    cards = "".join(f"""<div class=card style="--a:{ACC[m]}"><div class=mode>{m}</div><div class=role>{r}</div>
      <ul>{''.join(f'<li>{x}</li>' for x in items)}</ul><div class=tool>{tool}</div></div>""" for m, r, items, tool in t["modes"])
    rails = "".join(f"<li>{x}</li>" for x in t["rails"])
    exits = "".join(f"<div class=ex><b>{c}</b><span>{d}</span></div>" for c, d in t["exits"])
    return f"""<!doctype html><meta charset=utf-8><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{width:1600px;height:1000px;background:#0b1220;color:#e5e7eb;padding:56px 64px;
 font-family:'Pretendard',-apple-system,'Apple SD Gothic Neo','Helvetica Neue',sans-serif;word-break:keep-all}}
.k{{color:#34d399;font-weight:700;letter-spacing:.04em;font-size:22px}}
h1{{font-size:60px;font-weight:800;margin:6px 0 10px;font-family:ui-monospace,'SF Mono',Menlo,monospace}}
.sub{{color:#94a3b8;font-size:22px}}
.row{{display:flex;gap:28px;margin-top:40px}}
.card{{flex:1;background:#111a2e;border:1px solid #1f2a44;border-top:6px solid var(--a);border-radius:18px;padding:28px 30px;height:380px;display:flex;flex-direction:column}}
.mode{{font:800 36px ui-monospace,'SF Mono',Menlo,monospace;color:var(--a)}}
.role{{font-size:21px;color:#cbd5e1;margin:6px 0 18px;font-weight:600}}
ul{{list-style:none}} li{{font-size:20px;line-height:1.35;margin:9px 0;padding-left:22px;position:relative}}
.card li::before{{content:'';position:absolute;left:0;top:10px;width:9px;height:9px;border-radius:50%;background:var(--a)}}
.tool{{margin-top:auto;font-size:18px;color:#94a3b8;border-top:1px solid #1f2a44;padding-top:14px}}
.bot{{display:flex;gap:28px;margin-top:28px}}
.box{{background:#111a2e;border:1px solid #1f2a44;border-radius:18px;padding:24px 30px}}
.rails{{flex:1.55}} .rails li{{margin:7px 0}} code{{white-space:nowrap;font-family:ui-monospace,Menlo,monospace;color:#e2e8f0}}
.rails li::before{{content:'✓';position:absolute;left:0;color:#34d399;font-weight:800}}
.exits{{flex:1}} h3{{font-size:20px;color:#94a3b8;margin-bottom:12px;font-weight:700}}
.ex{{display:flex;align-items:center;gap:14px;margin:7px 0;font-size:20px}}
.ex b{{font:800 22px ui-monospace,Menlo,monospace;background:#1f2a44;border-radius:8px;width:40px;text-align:center;padding:3px 0}}
.gate{{margin-top:26px;font-size:20px;color:#34d399}} .foot{{margin-top:8px;font-size:17px;color:#64748b}}
</style><div class=k>{t['kicker']}</div><h1>🛡️&#8202;{t['title']}</h1><div class=sub>{t['sub']}</div>
<div class=row>{cards}</div>
<div class=bot><div class="box rails"><h3>{t['rails_t']}</h3><ul>{rails}</ul></div><div class="box exits"><h3>{t['exit_t']}</h3>{exits}</div></div>
<div class=gate>{t['gate']}</div><div class=foot>{t['foot']}</div>"""


for lang, t in T.items():
    h = D / f"infographic-{lang}.html"
    h.write_text(html(t))
    png = D / f"infographic-{lang}.png"
    r = subprocess.run([CHROME, "--headless", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        "--window-size=1600,1000", f"--screenshot={png}", h.as_uri()], capture_output=True, text=True)
    assert png.exists() and png.stat().st_size > 50_000, (lang, r.stderr[-300:])
    h.unlink()  # PNG is the artifact; this script is the source
    print(lang, png.stat().st_size)
