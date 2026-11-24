"""S2: 서브도메인 탈취 스캔.

판정 3단계:
  1. CNAME이 알려진 외부 서비스 패턴을 가리키는가 (DNS 사실, 요청 없음)
  2. 그 CNAME 대상이 NXDOMAIN인가 (dangling, 요청 없음)
  3. HTTP로 서비스별 지문 문자열이 나오는가 (스코프 가드 통과 시에만)

리소스 선점·등록은 절대 하지 않는다. "탈취 가능 후보"까지만 보고한다.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from asmkit.common import Cache, in_scope, rel


def _load_fingerprints(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    path = rel(cfg, cfg["takeover"]["fingerprints"])
    return json.loads(path.read_text(encoding="utf-8"))["services"]


def _match_service(cname: str, services: list[dict]) -> dict | None:
    for svc in services:
        if any(pat in cname for pat in svc["cname"]):
            return svc
    return None


def scan(cfg: dict[str, Any], cache: Cache, assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    services = _load_fingerprints(cfg)
    findings = []
    for a in assets:
        cname = a.get("cname")
        if not cname:
            continue
        svc = _match_service(cname, services)
        if not svc:
            continue

        host = a["host"]
        verdict = "candidate"      # 기본: CNAME이 외부 서비스를 가리킴
        evidence = {"cname": cname, "service": svc["service"]}
        confidence = "low"

        # 2단계: dangling (CNAME 대상이 NXDOMAIN)
        if a.get("dangling_nxdomain"):
            verdict = "likely"
            confidence = "medium"
            evidence["dangling"] = "CNAME 대상이 NXDOMAIN"

        # 3단계: HTTP 지문 (스코프 가드)
        if in_scope(cfg, host):
            hit = _http_fingerprint(host, svc["fingerprint"])
            if hit:
                verdict = "confirmed_fingerprint"
                confidence = "high"
                evidence["fingerprint_matched"] = hit
        else:
            evidence["http_check"] = "스코프 밖이라 생략"

        findings.append({
            "host": host, "service": svc["service"],
            "takeover_possible": svc["vulnerable"],
            "verdict": verdict, "confidence": confidence, "evidence": evidence,
        })
    print(f"[takeover] CNAME 외부서비스 매칭 {len(findings)}건")
    for f in findings:
        print(f"  [{f['confidence']}] {f['host']} → {f['service']} ({f['verdict']})")
    return findings


def _http_fingerprint(host: str, fingerprints: list[str]) -> str | None:
    """지문 문자열만 확인. 리소스를 건드리지 않는 단순 GET."""
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=8, follow_redirects=True,
                          headers={"User-Agent": "asm-toolkit"})
            body = r.text or ""
            for fp in fingerprints:
                if fp in body:
                    return fp
        except httpx.HTTPError:
            continue
    return None
