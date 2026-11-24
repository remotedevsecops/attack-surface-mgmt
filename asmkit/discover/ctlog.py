"""S0: CT 로그(crt.sh) 기반 수동 발견. 공개 데이터만 읽는다 — 안전.

인증서 투명성 로그에 등록된 도메인에서 서브도메인을 수집한다.
결과는 캐시해 개발 중 반복 요청을 막는다.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from asmkit.common import Cache

CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
# crt.sh의 name_value는 여러 줄·와일드카드를 포함할 수 있다
_WILDCARD = re.compile(r"^\*\.")


def _clean_names(raw: list[dict[str, Any]], root: str) -> set[str]:
    out: set[str] = set()
    for row in raw:
        for field in ("name_value", "common_name"):
            val = row.get(field) or ""
            for name in val.split("\n"):
                name = _WILDCARD.sub("", name.strip().lower()).rstrip(".")
                if name and (name == root or name.endswith("." + root)):
                    out.add(name)
    return out


def collect(cfg: dict[str, Any], cache: Cache) -> list[str]:
    root = cfg["target"]["root_domain"].lower()
    if not cfg["discover"].get("crtsh", True):
        return []
    cached = cache.get("crtsh", root)
    if cached is not None:
        print(f"[ctlog] 캐시 사용: {root} ({len(cached)}개)")
        return cached
    names = _from_crtsh(root)
    if not names:
        names = _from_certspotter(root)  # 대안 소스
    names = sorted(names)
    if names:
        cache.put("crtsh", root, names)
    print(f"[ctlog] CT로그: {root} → 서브도메인 {len(names)}개")
    return names


def _retry_get(url: str, tries: int = 4) -> httpx.Response | None:
    """crt.sh는 과부하로 502/503을 자주 준다 — 지수 백오프 재시도."""
    import time
    for i in range(tries):
        try:
            r = httpx.get(url, timeout=40, headers={"User-Agent": "asm-toolkit"})
            if r.status_code in (502, 503, 504, 429):
                time.sleep(2 * (i + 1))
                continue
            r.raise_for_status()
            return r
        except httpx.HTTPError:
            time.sleep(2 * (i + 1))
    return None


def _from_crtsh(root: str) -> set[str]:
    r = _retry_get(CRTSH.format(domain=root))
    if r is None:
        print("[ctlog] crt.sh 응답 없음 (재시도 소진) — 대안 소스 시도")
        return set()
    try:
        return _clean_names(r.json(), root)
    except ValueError:
        return set()


def _from_certspotter(root: str) -> set[str]:
    """certspotter 공개 API (crt.sh 대안)."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={root}"
           f"&include_subdomains=true&expand=dns_names")
    try:
        r = httpx.get(url, timeout=30, headers={"User-Agent": "asm-toolkit"})
        r.raise_for_status()
        out: set[str] = set()
        for cert in r.json():
            for name in cert.get("dns_names", []):
                name = name.lstrip("*.").lower().rstrip(".")
                if name == root or name.endswith("." + root):
                    out.add(name)
        return out
    except (httpx.HTTPError, ValueError) as e:
        print(f"[ctlog] certspotter도 실패: {e}")
        return set()
