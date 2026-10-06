"""
Teste local do scanner DAST do CodeShield.

Pré-requisitos:
1. Docker Desktop em execução.
2. Frontend local rodando em http://localhost:3000
   ou altere TARGET abaixo para outra aplicação AUTORIZADA.
"""

from pprint import pprint

from app.scanners.zap import (
    normalizar_todos_findings_zap,
    run_zap,
)


TARGET = "http://localhost:3000"


raw = run_zap(
    TARGET,
    spider_minutes=1,
    timeout_minutes=8,
)

findings = normalizar_todos_findings_zap(
    raw,
    TARGET,
)

print("\n========================================")
print("CODESHIELD - TESTE DAST / OWASP ZAP")
print("========================================")
print(f"Target:   {TARGET}")
print(f"Alerts:   {len(raw)}")
print(f"Findings: {len(findings)}")
print("========================================")

for finding in findings[:10]:
    pprint(
        {
            "fonte": finding.get("fonte"),
            "tipo": finding.get("tipo"),
            "rule_id": finding.get("rule_id"),
            "file_path": finding.get("file_path"),
            "message": finding.get("message"),
        }
    )
    print("----------------------------------------")
