"""S4/S5: API 표면 + 능동 검증.

ASM이 발견한 'API를 가진 대상'을 crAPI 툴킷(M1 Shadow 판정 + M3 능동 검증)으로 넘긴다.
crAPI 툴킷을 서브프로세스로 호출하고 그 산출물(endpoints.json / findings.json)을
ASM 인벤토리에 'API 자산'으로 통합한다.

대상별 역할 분담:
  - Next.js 등 정적 프론트 도메인: 외부 API 표면이 거의 없음 → S0~S2로 충분
  - API 중심 대상(crAPI 등): M1으로 Shadow/Zombie, M3로 BOLA/무인증 실증
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from asmkit.common import rel


def collect_from_toolkit(cfg: dict[str, Any]) -> dict[str, Any] | None:
    """crAPI 툴킷의 M1/M3 결과를 ASM API 자산으로 변환.

    config.apisurface.toolkit_data = crAPI 툴킷 data 디렉터리 경로.
    이미 M1~M3가 돌아간 결과(enriched_endpoints.json, findings.json)를 읽어 요약한다.
    """
    conf = cfg.get("apisurface") or {}
    data_dir = conf.get("toolkit_data")
    if not data_dir:
        print("[apisurface] apisurface.toolkit_data 미설정 — S4/S5 생략")
        return None
    base = rel(cfg, data_dir)
    enriched = base / "enriched_endpoints.json"
    findings = base / "findings.json"
    if not enriched.exists():
        print(f"[apisurface] {enriched} 없음 — crAPI 툴킷을 먼저 실행")
        return None

    import re
    edoc = json.loads(enriched.read_text(encoding="utf-8"))
    eps = edoc["endpoints"]
    fdoc = json.loads(findings.read_text(encoding="utf-8")) if findings.exists() else {"findings": []}
    confirmed = [f for f in fdoc["findings"] if f["verdict"].startswith("vulnerable")]

    # findings의 확정 취약을 서비스별로 매핑 (URL 경로의 서비스 접두사로)
    def svc_of_url(url: str) -> str:
        path = url.split("8888")[-1]
        m = re.match(r"/(\w+)/", path)
        return m.group(1) if m else "unknown"

    confirmed_by_svc: dict[str, set] = {}
    for f in confirmed:
        svc = svc_of_url(f["url"])
        tmpl = re.sub(r"[0-9a-f-]{8,}|/\d+$", "/{id}", f["url"].split("8888")[-1])
        confirmed_by_svc.setdefault(svc, set()).add((f["method"], tmpl))

    # 서비스(호스트)별로 엔드포인트를 묶어 'API 자산'으로
    by_service: dict[str, dict] = {}
    for e in eps:
        svc = e.get("service") or "unknown"
        s = by_service.setdefault(svc, {"service": svc, "endpoints": 0, "shadow": 0,
                                        "no_auth": 0, "bola": 0, "pii": 0, "confirmed": 0})
        s["endpoints"] += 1
        if e["lifecycle"] == "shadow":
            s["shadow"] += 1
        if "NO_AUTH" in e["flags"]:
            s["no_auth"] += 1
        if "BOLA_CANDIDATE" in e["flags"]:
            s["bola"] += 1
        if e.get("pii_findings"):
            s["pii"] += 1
    for svc, confset in confirmed_by_svc.items():
        if svc in by_service:
            by_service[svc]["confirmed"] = len(confset)
    summary = {
        "source": str(base),
        "api_services": list(by_service.values()),
        "total_endpoints": len(eps),
        "shadow": sum(1 for e in eps if e["lifecycle"] == "shadow"),
        "confirmed_vulns": len({(f["method"], f["url"].split("8888")[-1].rsplit("/", 1)[0]) for f in confirmed}),
    }
    print(f"[apisurface] crAPI 툴킷 통합: API 서비스 {len(by_service)}개, "
          f"엔드포인트 {len(eps)}개, 확정 취약 {summary['confirmed_vulns']}건")
    return summary


def run_toolkit(cfg: dict[str, Any]) -> bool:
    """crAPI 툴킷을 직접 실행(scan→verify). config.apisurface.toolkit_cmd 필요."""
    conf = cfg.get("apisurface") or {}
    cmd = conf.get("toolkit_cmd")
    if not cmd:
        return False
    print(f"[apisurface] crAPI 툴킷 실행: {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[apisurface] 툴킷 실행 실패: {r.stderr[-200:]}")
        return False
    return True
