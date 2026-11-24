"""S0/S1 경계: 서브도메인의 DNS 레코드 조회.

CNAME·A·NS를 해석해 (1) 살아있는지 (2) 외부 서비스를 가리키는지(탈취 재료) 파악.
DNS 조회는 리졸버에 질의하는 수동적 행위라 대상 호스트에 직접 요청하지 않는다.
"""
from __future__ import annotations

from typing import Any

import dns.resolver
import dns.exception

from asmkit.common import Cache


def _resolver(cfg: dict[str, Any]) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = cfg["discover"]["dns_resolvers"]
    r.lifetime = 5.0
    r.timeout = 3.0
    return r


def _query(res: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        ans = res.resolve(name, rtype)
        return [str(r).rstrip(".").lower() for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except dns.exception.DNSException:
        return []


def resolve_all(cfg: dict[str, Any], cache: Cache, hosts: list[str]) -> list[dict[str, Any]]:
    """각 호스트의 CNAME/A/NXDOMAIN 상태를 반환."""
    res = _resolver(cfg)
    out = []
    for h in hosts:
        cached = cache.get("dns", h)
        if cached is not None:
            out.append(cached)
            continue
        cname = _query(res, h, "CNAME")
        a = _query(res, h, "A")
        # NXDOMAIN 판정: CNAME은 있는데 그 대상이 안 풀리는 경우 탈취 후보
        nxdomain = False
        if cname and not a:
            try:
                res.resolve(cname[0], "A")
            except dns.resolver.NXDOMAIN:
                nxdomain = True
            except dns.exception.DNSException:
                pass
        rec = {
            "host": h,
            "cname": cname[0] if cname else None,
            "a": a,
            "alive": bool(a),
            "dangling_nxdomain": nxdomain,
        }
        cache.put("dns", h, rec)
        out.append(rec)
    alive = sum(1 for r in out if r["alive"])
    cnames = sum(1 for r in out if r["cname"])
    print(f"[dns] {len(out)}개 조회: 살아있음 {alive}, CNAME {cnames}")
    return out
