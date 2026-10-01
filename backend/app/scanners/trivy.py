"""
Scanner SCA da CodeShield ASPM.

Utiliza o Trivy para encontrar vulnerabilidades conhecidas
nas dependências utilizadas pelo projeto.
"""

import subprocess
import json
import os
import shutil


# Primeiro tenta encontrar o Trivy pelo PATH.
# Caso não encontre, utiliza o caminho padrão configurado no Windows.
TRIVY_EXE = shutil.which("trivy")

if not TRIVY_EXE:
    caminho_windows = r"C:\Tools\Trivy\trivy.exe"

    if os.path.exists(caminho_windows):
        TRIVY_EXE = caminho_windows
    else:
        TRIVY_EXE = "trivy"


def run_trivy(repo_path: str) -> list:
    """
    Executa o Trivy no repositório.

    O objetivo é SCA:
    procurar dependências com vulnerabilidades conhecidas.
    """

    # Verifica se o Trivy está funcionando.
    try:
        verificacao = subprocess.run(
            [TRIVY_EXE, "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if verificacao.returncode != 0:
            print("[ERRO] Trivy foi encontrado, mas não pôde ser executado.")

            if verificacao.stderr:
                print(f"[DEBUG] {verificacao.stderr[:500]}")

            return []

    except FileNotFoundError:
        print("[ERRO] Trivy não foi encontrado no sistema.")
        return []

    except subprocess.TimeoutExpired:
        print("[ERRO] Trivy demorou demais para responder.")
        return []

    except Exception as erro:
        print(f"[ERRO] Falha ao verificar o Trivy: {erro}")
        return []

    # Executa o scan SCA.
    try:
        resultado = subprocess.run(
            [
                TRIVY_EXE,
                "fs",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--quiet",
                repo_path
            ],
            capture_output=True,
            text=True,
            timeout=600
        )

        if resultado.returncode != 0:
            print(
                f"[ERRO] Trivy terminou com código "
                f"{resultado.returncode}."
            )

            if resultado.stderr:
                print(f"[DEBUG] Trivy stderr: {resultado.stderr[:1000]}")

            return []

        if not resultado.stdout.strip():
            print("[INFO] Trivy não retornou resultados.")

            if resultado.stderr:
                print(f"[DEBUG] Trivy stderr: {resultado.stderr[:500]}")

            return []

        dados = json.loads(resultado.stdout)

        findings = []

        # O Trivy agrupa os resultados por arquivo/dependência.
        for resultado_trivy in dados.get("Results", []):
            vulnerabilidades = (
                resultado_trivy.get("Vulnerabilities") or []
            )

            for vulnerabilidade in vulnerabilidades:
                findings.append(
                    {
                        "target": resultado_trivy.get("Target", ""),
                        "type": resultado_trivy.get("Type", ""),
                        "vulnerability": vulnerabilidade
                    }
                )

        print(
            f"[OK] Trivy encontrou "
            f"{len(findings)} vulnerabilidade(s) em dependências."
        )

        return findings

    except subprocess.TimeoutExpired:
        print("[ERRO] Trivy demorou mais de 10 minutos.")
        return []

    except json.JSONDecodeError as erro:
        print(f"[ERRO] JSON inválido retornado pelo Trivy: {erro}")
        return []

    except Exception as erro:
        print(f"[ERRO] Falha no Trivy: {erro}")
        return []


def normalizar_severidade_trivy(severidade: str) -> str:
    """
    Normaliza a severidade retornada pelo Trivy
    para o padrão utilizado pela CodeShield.
    """

    severidades_validas = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    }

    severidade = (severidade or "").upper()

    if severidade in severidades_validas:
        return severidade

    # Mantemos LOW porque o schema atual da CodeShield
    # trabalha com as quatro severidades acima.
    return "LOW"


def normalizar_finding_trivy(
    finding_raw: dict,
    repo_url: str
) -> dict | None:
    """
    Converte uma vulnerabilidade do Trivy para o schema
    interno utilizado pela CodeShield.
    """

    try:
        vulnerabilidade = finding_raw.get(
            "vulnerability",
            {}
        )

        rule_id = vulnerabilidade.get(
            "VulnerabilityID",
            ""
        )

        if not rule_id:
            return None

        pacote = vulnerabilidade.get(
            "PkgName",
            "pacote desconhecido"
        )

        versao = vulnerabilidade.get(
            "InstalledVersion",
            "desconhecida"
        )

        versao_corrigida = vulnerabilidade.get(
            "FixedVersion",
            ""
        )

        severidade = normalizar_severidade_trivy(
            vulnerabilidade.get(
                "Severity",
                "LOW"
            )
        )

        titulo = (
            vulnerabilidade.get("Title")
            or vulnerabilidade.get("Description")
            or "Vulnerabilidade encontrada em dependência."
        )

        mensagem = (
            f"{titulo} | "
            f"Pacote: {pacote} | "
            f"Versão instalada: {versao}"
        )

        if versao_corrigida:
            mensagem += (
                f" | Versão corrigida: "
                f"{versao_corrigida}"
            )

        primary_url = vulnerabilidade.get(
            "PrimaryURL",
            ""
        )

        status = vulnerabilidade.get(
            "Status",
            ""
        )

        return {
            "fonte": "trivy",
            "tipo": severidade,
            "repo_url": repo_url,
            "rule_id": rule_id,
            "file_path": finding_raw.get(
                "target",
                ""
            ),
            "line": 0,
            "message": mensagem,
            "detalhes": (
                f"package={pacote} "
                f"installed={versao} "
                f"fixed={versao_corrigida or 'não informado'} "
                f"status={status or 'não informado'} "
                f"url={primary_url or 'não informado'}"
            ),
        }

    except Exception as erro:
        print(
            f"[ERRO] Falha ao normalizar "
            f"finding do Trivy: {erro}"
        )
        return None


def normalizar_todos_findings_trivy(
    findings_raw: list,
    repo_url: str
) -> list:
    """
    Normaliza todos os findings encontrados pelo Trivy.
    """

    normalizados = []

    for i, finding in enumerate(
        findings_raw,
        start=1
    ):
        resultado = normalizar_finding_trivy(
            finding,
            repo_url
        )

        if resultado:
            normalizados.append(resultado)
        else:
            print(
                f"[AVISO] Finding Trivy {i} "
                f"inválido — ignorado."
            )

    return normalizados