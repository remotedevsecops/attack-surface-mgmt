"""S3: 시크릿 스캔 (TruffleHog 메인).

발견한 자산의 소스(git 레포·로컬 디렉터리·파일)에서 유출된 키·토큰을 찾는다.
TruffleHog의 핵심은 '검증(verification)' — 발급 API를 호출해 키가 아직 살아있는지 확인.
단순 탐지가 아니라 '살아있는 키'를 구분하는 게 M3의 '후보→실증' 철학과 같다.

입력 유형:
  - filesystem: 로컬 디렉터리/파일 (crAPI 소스 등)
  - git: 공개 레포 URL (커밋 히스토리 포함)
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from asmkit.common import rel


def _bin(cfg: dict[str, Any]) -> str | None:
    name = (cfg.get("secrets") or {}).get("trufflehog", "trufflehog")
    return shutil.which(name)


def scan_filesystem(cfg: dict[str, Any], target: Path) -> list[dict[str, Any]]:
    """로컬 디렉터리/파일 스캔."""
    th = _bin(cfg)
    if not th:
        print("[secrets] trufflehog 미설치 — S3 생략")
        return []
    # 검증 상태를 모두 받는다: verified(활성 확인) / unverified(미시도) / unknown(시도했으나 실패)
    proc = subprocess.run(
        [th, "filesystem", str(target),
         "--results=verified,unverified,unknown", "--json", "--no-update"],
        capture_output=True, text=True,
    )
    findings = _parse(proc.stdout)
    for f in findings:
        f["target"] = str(target)
    return findings


def scan_git(cfg: dict[str, Any], repo_url: str) -> list[dict[str, Any]]:
    th = _bin(cfg)
    if not th:
        return []
    proc = subprocess.run(
        [th, "git", repo_url, "--json", "--no-update"],
        capture_output=True, text=True,
    )
    return _parse(proc.stdout)


# 빌드 산출물·바이너리는 소스 유출이 아니므로 제외 (같은 시크릿이 중복 집계됨)
_SKIP_EXT = (".jar", ".war", ".tar", ".zip", ".class", ".pyc", ".gz")


def _parse(stdout: str, dedup: bool = True) -> list[dict[str, Any]]:
    """TruffleHog JSONL → 정규화된 finding. 빌드 산출물 제외, 동일 시크릿 중복 제거."""
    out = []
    seen: set[tuple] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        src = r.get("SourceMetadata", {}).get("Data", {})
        loc = src.get("Filesystem") or src.get("Git") or {}
        fpath = loc.get("file") or loc.get("repository") or ""
        if fpath.lower().endswith(_SKIP_EXT):
            continue
        secret = r.get("Raw", "")
        if dedup:
            k = (r.get("DetectorName"), secret)
            if k in seen:
                continue
            seen.add(k)
        verr = r.get("VerificationError") or ""
        # 검증 상태 3분류: verified(활성) / unknown(시도했으나 실패) / unverified(미시도)
        if r.get("Verified"):
            vstatus = "verified"
        elif verr:
            vstatus = "unknown"
        else:
            vstatus = "unverified"
        out.append({
            "detector": r.get("DetectorName"),
            "verified": r.get("Verified", False),
            "verify_status": vstatus,
            "verify_error": verr[:80] if verr else None,
            "file": fpath,
            "line": loc.get("line"),
            "commit": loc.get("commit"),
            "secret_masked": _mask(secret),
        })
    return out


def _mask(s: str) -> str:
    if not s:
        return ""
    return s[:4] + "***" + s[-2:] if len(s) > 8 else s[0] + "***"


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    verified = [f for f in findings if f["verified"]]
    by_detector: dict[str, int] = {}
    for f in findings:
        by_detector[f["detector"]] = by_detector.get(f["detector"], 0) + 1
    return {
        "total": len(findings),
        "verified": len(verified),
        "by_detector": by_detector,
    }
