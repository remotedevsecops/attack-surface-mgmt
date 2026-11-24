"""ASM 공통: 설정 로드, 스코프 가드, 캐시."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import yaml

KIT_ROOT = Path(__file__).resolve().parent.parent


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else KIT_ROOT / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    cfg["_root"] = p.resolve().parent
    return cfg


def rel(cfg: dict[str, Any], p: str) -> Path:
    return (cfg["_root"] / p).resolve()


def in_scope(cfg: dict[str, Any], host: str) -> bool:
    """능동 스캔 허용 여부: 허용 접미사(도메인)의 하위만."""
    host = host.lower().rstrip(".")
    for suf in cfg["scope"]["allowed_suffixes"]:
        suf = suf.lower().lstrip(".")
        if host == suf or host.endswith("." + suf):
            return True
    return False


class Cache:
    """외부 조회 결과 캐시 (crt.sh, DNS). 개발 중 반복 요청 방지 + 재현성."""

    def __init__(self, cfg: dict[str, Any]):
        self.dir = rel(cfg, cfg["cache"]["dir"])
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = cfg["cache"]["ttl_hours"] * 3600

    def _path(self, kind: str, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.dir / f"{kind}_{h}.json"

    def get(self, kind: str, key: str) -> Any | None:
        p = self._path(kind, key)
        if not p.exists():
            return None
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - doc.get("_ts", 0) > self.ttl:
            return None
        return doc.get("data")

    def put(self, kind: str, key: str, data: Any) -> None:
        p = self._path(kind, key)
        p.write_text(json.dumps({"_ts": time.time(), "key": key, "data": data},
                                ensure_ascii=False, indent=2), encoding="utf-8")
