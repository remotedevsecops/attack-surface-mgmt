"""S1: 능동 프로브. 살아있는 호스트에 HTTP로 붙어 상태·헤더·기술스택·TLS를 수집.

대상에 실제 요청을 보내는 단계 — 스코프 가드를 반드시 통과한다.
레이트 제한을 걸고, 호스트당 요청을 최소화한다(루트 GET 1회 + TLS 1회).
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from asmkit.common import in_scope

# 서버 헤더·본문에서 기술스택을 추정하는 간단한 핑거프린트
TECH_HINTS = [
    ("Vercel", ["vercel", "x-vercel-id"]),
    ("Cloudflare", ["cloudflare", "cf-ray"]),
    ("Nginx", ["nginx"]),
    ("Apache", ["apache"]),
    ("AWS", ["amazons3", "x-amz", "awselb"]),
    ("Netlify", ["netlify"]),
    ("Next.js", ["x-powered-by: next", "__next"]),
    ("WordPress", ["wp-content", "wp-json"]),
]


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    hay = " ".join(f"{k}: {v}" for k, v in headers.items()).lower() + " " + body[:4000].lower()
    return [name for name, pats in TECH_HINTS if any(p in hay for p in pats)]


def _tls_info(host: str, port: int = 443) -> dict[str, Any] | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "tls_version": ssock.version(),
                    "subject_cn": dict(x[0] for x in cert.get("subject", [])).get("commonName"),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:10],
                }
    except (OSError, ssl.SSLError, socket.timeout):
        return None


def probe(cfg: dict[str, Any], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not cfg["probe"].get("enabled"):
        print("[probe] probe.enabled=false — S1 생략 (명시적으로 켜야 요청이 나감)")
        return []
    rate = cfg["probe"].get("rate_per_sec", 5)
    gap = 1.0 / rate if rate > 0 else 0
    timeout = cfg["probe"].get("timeout", 10)
    out = []
    last = 0.0
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "asm-toolkit"}) as cli:
        for a in assets:
            host = a["host"]
            if not a.get("alive"):
                continue
            if not in_scope(cfg, host):
                print(f"[probe] 스코프 밖 차단: {host}")
                continue
            # 레이트 제한
            wait = last + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            last = time.monotonic()

            rec: dict[str, Any] = {"host": host}
            try:
                r = cli.get(f"https://{host}")
                rec["status"] = r.status_code
                rec["final_url"] = str(r.url)
                rec["server"] = r.headers.get("server")
                rec["tech"] = _detect_tech(dict(r.headers), r.text or "")
                rec["title"] = _title(r.text or "")
                rec["security_headers"] = _sec_headers(dict(r.headers))
            except httpx.HTTPError as e:
                rec["status"] = -1
                rec["error"] = f"{type(e).__name__}"
            rec["tls"] = _tls_info(host)
            out.append(rec)
            print(f"  {host:<28} {rec.get('status')} {','.join(rec.get('tech', [])) or '-'}")
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    print(f"[probe] {len(out)}개 호스트 프로브 완료")
    return out


def _title(body: str) -> str | None:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return (m.group(1).strip()[:80]) if m else None


SEC_HEADERS = ["strict-transport-security", "content-security-policy",
               "x-frame-options", "x-content-type-options"]


def _sec_headers(headers: dict[str, str]) -> dict[str, bool]:
    low = {k.lower(): v for k, v in headers.items()}
    return {h: (h in low) for h in SEC_HEADERS}
