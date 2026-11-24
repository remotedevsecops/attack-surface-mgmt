"""S0 수동 발견 실행: python -m asmkit.discover [--config config.yaml]

출력: data/assets.json (서브도메인 인벤토리 + DNS 상태)
외부 요청은 crt.sh(공개 CT로그)와 DNS 리졸버뿐. 대상 호스트에 직접 요청하지 않는다.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from asmkit.common import Cache, load_config, rel
from asmkit.discover import ctlog, dnsx


def main() -> None:
    ap = argparse.ArgumentParser(description="S0: 수동 발견 (CT로그 + DNS)")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg = load_config(args.config)
    cache = Cache(cfg)

    root = cfg["target"]["root_domain"]
    print(f"[S0] 대상: {root}")
    subs = ctlog.collect(cfg, cache)
    # 루트도 포함
    hosts = sorted(set(subs) | {root})
    dns_records = dnsx.resolve_all(cfg, cache, hosts)

    assets = []
    for rec in dns_records:
        assets.append({
            "host": rec["host"],
            "source": ["ct-log"] if rec["host"] in subs else ["seed"],
            "cname": rec["cname"],
            "a": rec["a"],
            "alive": rec["alive"],
            "dangling_nxdomain": rec["dangling_nxdomain"],
        })

    out_dir = rel(cfg, cfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root_domain": root,
        "counts": {"total": len(assets), "alive": sum(a["alive"] for a in assets),
                   "with_cname": sum(1 for a in assets if a["cname"]),
                   "dangling": sum(a["dangling_nxdomain"] for a in assets)},
    }
    (out_dir / "assets.json").write_text(
        json.dumps({"meta": meta, "assets": assets}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"\n[S0] 자산 {len(assets)}개 → {out_dir / 'assets.json'}")
    print(f"     {meta['counts']}")


if __name__ == "__main__":
    main()
