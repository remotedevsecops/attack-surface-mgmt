"""S6: ASM 대시보드. 타겟별로 '무엇에 무슨 단계를 수행해 무엇이 나왔나'를 보여준다.

python -m asmkit.report  →  data/asm_report.html
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from jinja2 import Template

from asmkit.common import load_config, rel

TEMPLATE = Template(r"""<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASM 리포트</title>
<style>
:root{--bg:#f7f7f5;--surface:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;--accent:#2f5bd3;--crit:#c8372d;--crit-bg:#fbeceb;--warn:#b25e09;--warn-bg:#fcf1e3;--ok:#2d7a46;--ok-bg:#e7f3ea;--info:#2f5bd3;--info-bg:#e9effc;--violet:#6a4bc4;--violet-bg:#efebfa;--neutral-bg:#efefec;}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#151514;--surface:#1e1e1c;--ink:#ecece8;--muted:#a2a29b;--line:#34342f;--accent:#7d9cf0;--crit:#f0857b;--crit-bg:#3a1f1c;--warn:#e9a55a;--warn-bg:#382816;--ok:#7cc495;--ok-bg:#1d3324;--info:#7d9cf0;--info-bg:#1f2840;--violet:#b3a0f0;--violet-bg:#2a2340;--neutral-bg:#2a2a27;}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard","Segoe UI",sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0}
.sub{color:var(--muted);font-size:13px}
.tgt{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:0;margin-top:18px;overflow:hidden}
.tgthead{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;padding:16px;background:var(--neutral-bg);border-bottom:1px solid var(--line)}
.tgthead .name{font-size:17px;font-weight:650}
.tgthead .kind{font-size:12px;padding:2px 9px;border-radius:999px;background:var(--surface);border:1px solid var(--line);color:var(--muted)}
.tgthead .role{color:var(--muted);font-size:13px;flex-basis:100%}
.tgthead .stages{margin-left:auto;font:12px ui-monospace,Menlo,monospace;color:var(--muted)}
.sec{padding:14px 16px;border-bottom:1px solid var(--line)}.sec:last-child{border-bottom:none}
.sec h3{font-size:13px;margin:0 0 10px;color:var(--muted);font-weight:600}
.sec h3 .step{display:inline-block;font:11px ui-monospace,Menlo,monospace;background:var(--info-bg);color:var(--info);padding:1px 6px;border-radius:4px;margin-right:6px}
.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:460px}
th{font-size:12px;color:var(--muted);font-weight:600;text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
.p{font:12.5px ui-monospace,Menlo,monospace;word-break:break-all}
.b{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;margin:0 2px 2px 0;white-space:nowrap}
.ok{background:var(--ok-bg);color:var(--ok)}.crit{background:var(--crit-bg);color:var(--crit)}.warn{background:var(--warn-bg);color:var(--warn)}.muted{background:var(--neutral-bg);color:var(--muted)}.info{background:var(--info-bg);color:var(--info)}
.empty{color:var(--muted);padding:8px 0;font-size:13px}
.kv{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;margin-bottom:4px}
.kv b{font-size:18px;font-weight:650}.kv .crit{background:none;color:var(--crit)}.kv .warn{background:none;color:var(--warn)}.kv .ok{background:none;color:var(--ok)}
.secbar{display:flex;gap:3px;flex-wrap:wrap}.secbar span{font-size:11px;padding:1px 6px;border-radius:4px}
.yes{background:var(--ok-bg);color:var(--ok)}.no{background:var(--crit-bg);color:var(--crit)}
.note{color:var(--muted);font-size:12px;margin-top:8px;line-height:1.5}
.flowline{font-size:12.5px;color:var(--muted);margin-top:6px}.flowline b{color:var(--ink)}
.foot{color:var(--muted);font-size:12px;margin-top:20px;line-height:1.6}
</style></head><body><div class="wrap">
<h1>ASM 리포트</h1>
<div class="sub">생성 {{ gen }} · 타겟 {{ targets|length }}개 · 대상별로 수행 단계와 결과를 분리</div>

{% for t in targets %}
<div class="tgt">
  <div class="tgthead">
    <span class="name">{{ t.name }}</span>
    <span class="kind">{{ t.kind }}</span>
    <span class="stages">{{ t.stages|join(' · ') }}</span>
    <span class="role">{{ t.role }}</span>
  </div>

  {% if t.kind == 'external-domain' %}
  <div class="sec">
    <h3><span class="step">S0 발견</span><span class="step">S1 프로브</span><span class="step">S2 탈취</span>외부 자산</h3>
    <div class="kv">
      <span>발견 <b>{{ t.assets|length }}</b></span>
      <span>살아있음 <b class="ok">{{ t.alive }}</b></span>
      <span>탈취 위험 <b class="{{ 'crit' if t.takeover_vuln else '' }}">{{ t.takeover_vuln }}</b></span>
    </div>
    <div class="tablewrap"><table>
    <thead><tr><th>호스트</th><th>상태</th><th>기술스택</th><th>CNAME</th><th>탈취</th><th>보안헤더</th></tr></thead><tbody>
    {% for a in t.assets %}<tr>
      <td class="p">{{ a.host }}</td>
      <td>{% if a.alive %}<span class="b ok">live</span>{% else %}<span class="b muted">dead</span>{% endif %}</td>
      <td>{% for tech in (t.probe_by_host.get(a.host, {}).get('tech') or []) %}<span class="b muted">{{ tech }}</span>{% endfor %}</td>
      <td class="p">{{ a.cname or '' }}</td>
      <td>{% set tk = t.takeover_by_host.get(a.host) %}{% if tk %}<span class="b crit">{{ tk.service }}</span>{% endif %}</td>
      <td>{% set ph = t.probe_by_host.get(a.host) %}{% if ph and ph.security_headers %}<div class="secbar">{% for h,v in ph.security_headers.items() %}<span class="{{ 'yes' if v else 'no' }}" title="{{ h }}">{{ h.split('-')[0][:4] }}</span>{% endfor %}</div>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
    <div class="note">S0는 CT로그·DNS만(요청 없음). S1 프로브와 S2 탈취 HTTP 확인은 이 도메인 범위만. 빨간 보안헤더 = 누락.</div>
  </div>

  {% else %}
  <div class="sec">
    <h3><span class="step">S3 시크릿</span>소스에서 유출 시크릿 ({{ t.secrets|length }}건)</h3>
    {% if t.secrets %}<div class="tablewrap"><table>
    <thead><tr><th>종류</th><th>파일 위치 (흐름)</th><th>검증 상태</th><th>값</th></tr></thead><tbody>
    {% for s in t.secrets %}<tr>
      <td><span class="b warn">{{ s.detector }}</span></td>
      <td class="p">{{ s.target_short }} › {{ s.file_short }}{% if s.line %}:{{ s.line }}{% endif %}</td>
      <td>{% if s.verify_status == 'verified' %}<span class="b crit">검증됨(활성)</span>
          {% elif s.verify_status == 'unknown' %}<span class="b warn" title="{{ s.verify_error }}">검증 시도·실패</span>
          {% else %}<span class="b muted">미검증(검증대상 없음)</span>{% endif %}</td>
      <td class="p">{{ s.secret_masked }}</td>
    </tr>{% endfor %}
    </tbody></table></div>
    <div class="note">검증 상태: <b>검증됨</b>=발급처 API로 활성 확인 · <b>검증 시도·실패</b>=발급처에 접속했으나 도달 못함(i/o timeout 등) · <b>미검증</b>=자체서명 키 등 검증할 외부 대상이 없음. crAPI는 로컬 DB·자체 인증서라 활성 검증이 불가능한 게 정상.</div>
    {% else %}<div class="empty">유출 시크릿 없음</div>{% endif %}
  </div>

  <div class="sec">
    <h3><span class="step">S4 API 표면</span><span class="step">S5 능동 검증</span>crAPI 툴킷 통합</h3>
    {% if t.apisurface %}
    <div class="kv">
      <span>엔드포인트 <b>{{ t.apisurface.total_endpoints }}</b></span>
      <span>Shadow <b class="warn">{{ t.apisurface.shadow }}</b></span>
      <span>확정 취약 <b class="crit">{{ t.apisurface.confirmed_vulns }}</b></span>
    </div>
    <div class="tablewrap"><table>
    <thead><tr><th>서비스</th><th>엔드포인트</th><th>Shadow</th><th>무인증</th><th>BOLA</th><th>PII</th><th>확정 취약(M3)</th></tr></thead><tbody>
    {% for s in t.apisurface.api_services %}<tr>
      <td>{{ s.service }}</td><td>{{ s.endpoints }}</td><td>{{ s.shadow or '' }}</td>
      <td>{% if s.no_auth %}<span class="b crit">{{ s.no_auth }}</span>{% endif %}</td>
      <td>{% if s.bola %}<span class="b warn">{{ s.bola }}</span>{% endif %}</td>
      <td>{{ s.pii or '' }}</td>
      <td>{% if s.confirmed %}<span class="b crit">{{ s.confirmed }}</span>{% endif %}</td>
    </tr>{% endfor %}
    </tbody></table></div>
    <div class="flowline">흐름: <b>S4</b> 코드·스펙·트래픽으로 Shadow/무인증/BOLA 후보 식별(M1) → <b>S5</b> 실제 요청 차분 테스트로 확정(M3). 확정 {{ t.apisurface.confirmed_vulns }}건은 BOLA/무인증을 실증한 것.</div>
    {% else %}<div class="empty">API 표면 데이터 없음 (crAPI 툴킷 먼저 실행)</div>{% endif %}
  </div>
  {% endif %}
</div>
{% endfor %}

<div class="foot">
외부 자산은 공개 데이터(CT로그·DNS)와 스코프 내 프로브로만 수집. 서브도메인 탈취는 지문 확인까지만(리소스 선점 안 함).<br>
시크릿·API 능동 검증은 본인 소유/허가 범위에 한정. API 능동 검증(S5)은 로컬 crAPI 실습 앱 대상.
</div>
</div></body></html>
""")


def main() -> None:
    cfg = load_config()
    d = rel(cfg, cfg["output_dir"])

    def load(name, default):
        p = d / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default

    assets = load("assets.json", {"assets": []})["assets"]
    takeover = load("takeover.json", {"findings": []})["findings"]
    probe = load("probe.json", {"probe": []})["probe"]
    secrets = load("secrets.json", {"findings": []})["findings"]
    apisurface = load("apisurface.json", None)

    for s in secrets:
        f = str(s.get("file") or "")
        s["file_short"] = "/".join(f.split("/")[-2:]) if f else "?"
        tgt = str(s.get("target") or "")
        s["target_short"] = tgt.split("/")[-1] if tgt else "?"

    # config의 targets 정의에 각 단계 결과를 매핑
    targets = []
    for t in cfg.get("targets", []):
        rec = dict(t)
        if t["kind"] == "external-domain":
            rec["assets"] = assets
            rec["alive"] = sum(1 for a in assets if a["alive"])
            rec["takeover_vuln"] = sum(1 for x in takeover if x.get("takeover_possible"))
            rec["probe_by_host"] = {p["host"]: p for p in probe}
            rec["takeover_by_host"] = {x["host"]: x for x in takeover}
        else:
            rec["secrets"] = secrets
            rec["apisurface"] = apisurface
        targets.append(rec)

    html = TEMPLATE.render(gen=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), targets=targets)
    out = d / "asm_report.html"
    out.write_text(html, encoding="utf-8")
    print(f"[report] → {out}")


if __name__ == "__main__":
    main()
