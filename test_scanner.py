from backend.app.scanners.trivy import (
    run_trivy,
    normalizar_todos_findings_trivy
)


def main():
    print("\n===== TESTE DO SCANNER TRIVY =====\n")

    # "." significa analisar a raiz atual do CodeShield-ASPM
    findings_raw = run_trivy(".")

    print(f"\nFindings brutos encontrados: {len(findings_raw)}")

    if not findings_raw:
        print("[ERRO] Nenhuma vulnerabilidade retornada pelo Trivy.")
        return

    findings_normalizados = normalizar_todos_findings_trivy(
        findings_raw,
        "local://CodeShield-ASPM"
    )

    print(
        f"Findings normalizados: "
        f"{len(findings_normalizados)}"
    )

    print("\n===== PRIMEIRO FINDING =====")

    primeiro = findings_normalizados[0]

    for chave, valor in primeiro.items():
        print(f"{chave}: {valor}")

    print("\n[OK] Scanner Trivy funcionando no CodeShield.")


if __name__ == "__main__":
    main()