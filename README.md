# ASM 툴킷 (Attack Surface Management)

> ⚠️ 대상은 본인 소유 도메인 또는 명시적 허가 범위(버그바운티)만. 실서비스 금지.

외부에서 보이는 공격표면을 발견·추적하고, 발견한 API를
[API 보안 가시화 툴킷](https://github.com/remotedevsecops/api-security-visualizer)의
런타임 검증(M3)으로 능동 확정한다.

## 결과 샘플

본인 소유 도메인을 대상으로 실제 실행한 결과를 **비식별화**한 예시입니다.

- 🔗 **[렌더된 대시보드 바로 보기](https://raw.githack.com/remotedevsecops/attack-surface-mgmt/main/data/sample/asm_report.html)** — 외부 도메인(S0~S2) + 로컬 crAPI(S3~S5)를 타겟별로 분리한 단일 HTML 리포트
- 원본·설명: [`data/sample/`](data/sample/) (대시보드 HTML, 발견 자산·프로브 JSON)

> GitHub에선 `.html`이 소스로만 보여 위 링크는 githack 프록시로 렌더합니다. 비식별: 도메인 → `example.com`, 공인 IP → 문서화용 대역(RFC 5737).

## 핵심 설계

- **발견만 하는 ASM과 다른 점**: CT로그·DNS로 자산을 찾는 데서 멈추지 않고,
  TruffleHog 시크릿은 **발급처 API로 활성 여부를 검증**하고, 발견한 API는
  **실제 요청 차분 테스트로 취약을 확정**한다 — "후보 목록"이 아니라 "실증된 노출".
- **성격이 다른 대상을 한 파이프라인, 리포트는 타겟별 분리**: 외부 도메인(블랙박스)은
  S0~S2, 소스를 가진 API 앱(화이트박스)은 S3~S5. 어느 대상에 무엇을 수행했는지 섞지 않는다.
- **스코프 가드가 모든 능동 요청 앞단**: `scope.allowed_suffixes` 밖으로는 요청이 나가지 않는다.

## 파이프라인 (S0~S6)

| 단계 | 내용 | 상태 |
| --- | --- | --- |
| S0 수동 발견 | CT로그(crt.sh) + DNS. 요청 없음, 안전 | 구현됨 |
| S2 서브도메인 탈취 | CNAME → 지문 DB 매칭 + dangling + HTTP 지문 | 구현됨 |
| S1 능동 프로브 | 살아있는 호스트·TLS·기술스택·보안헤더 | 구현됨 |
| S3 시크릿 | TruffleHog (설치됨) | 구현됨 |
| S4 API 표면 | crAPI 툴킷 M1 결과 통합 | 구현됨 |
| S5 능동 검증 | crAPI 툴킷 M3 확정 취약 통합 | 구현됨 |
| S6 대시보드 | 전 단계 결과 단일 HTML (asm_report.html) | 구현됨 |

## 실행

```bash
# config.yaml의 root_domain을 본인 소유 도메인으로 설정
~/.venvs/apisec/bin/python -m asmkit.cli run   # S0~S6 전체 → data/asm_report.html
# 개별: asm discover / takeover / probe / secrets / apisurface / report
```

## 안전 설계

- S0는 공개 데이터(CT로그·DNS 리졸버)만 읽는다 — 대상 호스트에 직접 요청 안 함.
- 능동 스캔(S1~)과 탈취 HTTP 확인은 `scope.allowed_suffixes` 안의 호스트만 (common.in_scope).
- 서브도메인 탈취는 **지문 확인까지만**. 리소스 선점·등록은 구현하지 않는다.
- 외부 조회(crt.sh·DNS)는 `data/cache`에 캐시 — 개발 중 반복 요청 방지 + 재현성.

## 구조

```
asm/
  asmkit/
    common.py            설정·스코프 가드·캐시
    discover/ {ctlog,dnsx}.py   S0 CT로그 + DNS
    takeover/            S2 서브도메인 탈취 (지문 DB 매칭, 선점 안 함)
    probe/               S1 능동 프로브 (기술스택·TLS·보안헤더)
    secrets/             S3 TruffleHog (3상태 검증: verified/unknown/unverified)
    apisurface/          S4·S5 API 보안 가시화 툴킷 M1/M3 통합
    report/              S6 타겟별 분리 단일 HTML
    cli.py               asm 단일 CLI
  data/
    takeover_fingerprints.json  can-i-take-over-xyz 기반 지문 (참조용, 커밋됨)
    # 실제 스캔 결과(assets/probe/secrets/report)는 .gitignore — 본인 도메인 데이터
  config.yaml            타겟·스코프·출처
```
