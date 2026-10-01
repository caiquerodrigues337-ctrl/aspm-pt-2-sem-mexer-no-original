import json
from pathlib import Path

ARQUIVO_TRIVY = Path("trivy-report.json")
ARQUIVO_SAIDA = Path("codeshield-findings.json")


def carregar_relatorio():
    if not ARQUIVO_TRIVY.exists():
        print(f"[ERRO] Arquivo {ARQUIVO_TRIVY} não encontrado.")
        return None

    with open(ARQUIVO_TRIVY, "r", encoding="utf-8") as arquivo:
        return json.load(arquivo)


def processar_vulnerabilidades(relatorio):
    findings = []

    for resultado in relatorio.get("Results", []):
        target = resultado.get("Target", "Desconhecido")
        tipo = resultado.get("Type", "Desconhecido")

        vulnerabilidades = resultado.get("Vulnerabilities") or []

        for vuln in vulnerabilidades:
            finding = {
                "source": "Trivy",
                "scanner_type": "SCA",
                "target": target,
                "type": tipo,
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "vulnerability_id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "title": vuln.get("Title"),
                "description": vuln.get("Description"),
                "primary_url": vuln.get("PrimaryURL"),
                "status": vuln.get("Status")
            }

            findings.append(finding)

    return findings


def salvar_findings(findings):
    with open(ARQUIVO_SAIDA, "w", encoding="utf-8") as arquivo:
        json.dump(findings, arquivo, indent=4, ensure_ascii=False)


def exibir_resumo(findings):
    severidades = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    for finding in findings:
        severidade = finding.get("severity", "UNKNOWN")

        if severidade not in severidades:
            severidade = "UNKNOWN"

        severidades[severidade] += 1

    print("\n===== CodeShield - Resultado Trivy =====")
    print(f"Total de vulnerabilidades: {len(findings)}")
    print(f"Critical: {severidades['CRITICAL']}")
    print(f"High:     {severidades['HIGH']}")
    print(f"Medium:   {severidades['MEDIUM']}")
    print(f"Low:      {severidades['LOW']}")
    print(f"Unknown:  {severidades['UNKNOWN']}")
    print("========================================")


def main():
    print("[CodeShield] Lendo relatório do Trivy...")

    relatorio = carregar_relatorio()

    if relatorio is None:
        return

    findings = processar_vulnerabilidades(relatorio)

    salvar_findings(findings)

    exibir_resumo(findings)

    print(f"\n[OK] Findings salvos em: {ARQUIVO_SAIDA}")


if __name__ == "__main__":
    main()