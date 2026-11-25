# 예시 결과 (비식별화)

본인 소유 도메인을 대상으로 실제 실행한 ASM 결과를 **비식별화**한 예시입니다.

- 도메인 → `example.com` / `www.example.com`
- 공인 IP → 문서화용 대역(RFC 5737, `203.0.113.0/24`)
- CNAME 해시·서비스 제목 등 식별 가능한 값 → 플레이스홀더로 치환

| 파일 | 내용 |
| --- | --- |
| `asm_report.html` | 타겟별 분리 대시보드 (외부 도메인 S0~S2 + 로컬 crAPI S3~S5) |
| `assets.json` | S0 발견 자산 (CT로그·DNS) |
| `probe.json` | S1 능동 프로브 (기술스택·TLS·보안헤더) |

> `asm_report.html`은 GitHub에서 소스로만 보입니다. 렌더된 화면을 보려면 내려받아 브라우저로 열거나 GitHub Pages로 배포하세요.
