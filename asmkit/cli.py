"""asm — ASM 툴킷 단일 CLI.

  asm discover   S0 수동 발견 (CT로그 + DNS)        → assets.json
  asm takeover   S2 서브도메인 탈취 스캔            → takeover.json
  asm probe      S1 능동 프로브 (스코프 가드)       → probe.json
  asm run        discover → takeover → probe 일괄

대상 교체는 config.yaml 하나로. 능동 단계(probe)는 config.probe.enabled와
scope.allowed_suffixes 가드를 모두 통과해야 요청이 나간다.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from asmkit.common import Cache, load_config, rel
from asmkit.discover import ctlog, dnsx
from asmkit import takeover as takeover_mod
from asmkit import probe as probe_mod
from asmkit import apisurface as apisurface_mod
from asmkit import secrets as secrets_mod
from asmkit import report as report_mod


def _discover(cfg, cache):
    root = cfg["target"]["root_domain"]
    subs = ctlog.collect(cfg, cache)
    hosts = sorted(set(subs) | {root})
    recs = dnsx.resolve_all(cfg, cache, hosts)
    assets = [{"host": r["host"], "source": ["ct-log"] if r["host"] in subs else ["seed"],
               "cname": r["cname"], "a": r["a"], "alive": r["alive"],
               "dangling_nxdomain": r["dangling_nxdomain"]} for r in recs]
    return assets


def _write(cfg, name, payload):
    out = rel(cfg, cfg["output_dir"]) / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"     → {out}")


def _load(cfg, name):
    p = rel(cfg, cfg["output_dir"]) / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def cmd_discover(cfg, cache, args):
    assets = _discover(cfg, cache)
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "root_domain": cfg["target"]["root_domain"],
            "counts": {"total": len(assets), "alive": sum(a["alive"] for a in assets),
                       "with_cname": sum(1 for a in assets if a["cname"])}}
    _write(cfg, "assets.json", {"meta": meta, "assets": assets})
    return assets


def cmd_takeover(cfg, cache, args):
    data = _load(cfg, "assets.json")
    if not data:
        raise SystemExit("assets.json 없음 — 먼저 asm discover")
    findings = takeover_mod.scan(cfg, cache, data["assets"])
    _write(cfg, "takeover.json", {"findings": findings})
    return findings


def cmd_probe(cfg, cache, args):
    data = _load(cfg, "assets.json")
    if not data:
        raise SystemExit("assets.json 없음 — 먼저 asm discover")
    res = probe_mod.probe(cfg, data["assets"])
    _write(cfg, "probe.json", {"probe": res})
    return res


def cmd_apisurface(cfg, cache, args):
    s = apisurface_mod.collect_from_toolkit(cfg)
    if s:
        _write(cfg, "apisurface.json", s)
    return s


def cmd_secrets(cfg, cache, args):
    targets = (cfg.get("secrets") or {}).get("scan_targets") or []
    all_f = []
    for t in targets:
        tp = rel(cfg, t)
        if tp.exists():
            all_f += secrets_mod.scan_filesystem(cfg, tp)
    summary = secrets_mod.summarize(all_f)
    print(f"[secrets] {summary['total']}건 (검증됨 {summary['verified']}) {summary['by_detector']}")
    _write(cfg, "secrets.json", {"findings": all_f, "summary": summary})
    return all_f


def cmd_report(cfg, cache, args):
    report_mod.main()


def cmd_run(cfg, cache, args):
    print("[S0] 수동 발견"); cmd_discover(cfg, cache, args)
    print("[S2] 서브도메인 탈취"); cmd_takeover(cfg, cache, args)
    print("[S1] 능동 프로브"); cmd_probe(cfg, cache, args)
    print("[S3] 시크릿 스캔"); cmd_secrets(cfg, cache, args)
    print("[S4/S5] API 표면·능동 검증"); cmd_apisurface(cfg, cache, args)
    print("[S6] 대시보드"); cmd_report(cfg, cache, args)


def main():
    p = argparse.ArgumentParser(prog="asm", description="ASM 툴킷")
    p.add_argument("--config")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, help_ in [("discover", cmd_discover, "S0 수동 발견"),
                            ("takeover", cmd_takeover, "S2 서브도메인 탈취"),
                            ("probe", cmd_probe, "S1 능동 프로브"),
                            ("secrets", cmd_secrets, "S3 시크릿 스캔"),
                            ("apisurface", cmd_apisurface, "S4/S5 API 표면"),
                            ("report", cmd_report, "S6 대시보드"),
                            ("run", cmd_run, "전체 일괄")]:
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
    args = p.parse_args()
    cfg = load_config(args.config)
    cache = Cache(cfg)
    args.func(cfg, cache, args)


if __name__ == "__main__":
    main()
