"""
Scanner SAST da CodeShield ASPM.

Responsável por:
- Localizar o executável do Semgrep
- Executar múltiplas configurações de análise
- Coletar findings válidos mesmo quando uma configuração falha
- Remover findings duplicados
- Normalizar severidades
- Converter findings para o padrão interno da CodeShield
- Disponibilizar uma execução detalhada para validação de fixes
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


# ============================================================
# CONFIGURAÇÃO
# ============================================================

SEMGREP_CONFIGS = [
    "auto",
    "p/python",
]


# ============================================================
# LOCALIZAR SEMGREP
# ============================================================

def localizar_semgrep() -> str:
    caminho_path = shutil.which("semgrep")

    if caminho_path:
        return caminho_path

    pasta_python = Path(
        sys.executable
    ).parent

    candidatos = [
        pasta_python / "semgrep.exe",
        pasta_python / "Scripts" / "semgrep.exe",
    ]

    for candidato in candidatos:
        if candidato.exists():
            return str(candidato)

    return "semgrep"


SEMGREP_EXE = localizar_semgrep()


# ============================================================
# NORMALIZAÇÃO DE SEVERIDADE
# ============================================================

def normalizar_severidade(
    sev_raw: str
) -> str:
    mapeamento = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    severidade = (
        sev_raw or "INFO"
    ).upper()

    return mapeamento.get(
        severidade,
        "LOW",
    )


# ============================================================
# VALIDAR SEMGREP
# ============================================================

def verificar_semgrep() -> bool:
    try:
        resultado = subprocess.run(
            [
                SEMGREP_EXE,
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if resultado.returncode != 0:
            print(
                "[ERRO] Semgrep foi encontrado, "
                "mas não executou corretamente."
            )

            if resultado.stderr:
                print(
                    "[DEBUG] "
                    f"{resultado.stderr[:500]}"
                )

            return False

        print(
            f"[INFO] Semgrep executável: "
            f"{SEMGREP_EXE}"
        )

        return True

    except FileNotFoundError:
        print(
            "[ERRO] Semgrep não encontrado."
        )
        print(
            "[INFO] Instale com: "
            "pip install semgrep"
        )
        return False

    except Exception as erro:
        print(
            "[ERRO] Falha ao verificar "
            f"Semgrep: {erro}"
        )
        return False


# ============================================================
# EXECUÇÃO DETALHADA
# ============================================================

def executar_config_semgrep_detalhado(
    repo_path: str,
    config: str,
) -> dict:
    """
    Executa uma configuração e retorna findings, errors e
    arquivos efetivamente escaneados.

    Esta versão detalhada é usada pelo re-scan determinístico.
    """
    print(
        "\n----------------------------------------"
    )
    print(
        f"[INFO] Semgrep config: {config}"
    )
    print(
        "----------------------------------------"
    )

    comando = [
        SEMGREP_EXE,
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        "--timeout",
        "60",
        ".",
    ]

    try:
        resultado = subprocess.run(
            comando,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,
        )

    except subprocess.TimeoutExpired:
        print(
            f"[ERRO] Semgrep ({config}) "
            "demorou mais de 5 minutos."
        )

        return {
            "executado": False,
            "findings": [],
            "errors": [
                {
                    "message": "timeout",
                }
            ],
            "scanned": [],
        }

    except Exception as erro:
        print(
            f"[ERRO] Falha no Semgrep "
            f"({config}): {erro}"
        )

        return {
            "executado": False,
            "findings": [],
            "errors": [
                {
                    "message": str(erro),
                }
            ],
            "scanned": [],
        }

    if not resultado.stdout.strip():
        print(
            f"[INFO] Semgrep ({config}) "
            "não retornou JSON."
        )

        if resultado.stderr.strip():
            print("[DEBUG] stderr:")
            print(resultado.stderr[:1000])

        return {
            "executado": False,
            "findings": [],
            "errors": [
                {
                    "message": (
                        resultado.stderr.strip()
                        or "Sem JSON"
                    )
                }
            ],
            "scanned": [],
        }

    try:
        dados = json.loads(
            resultado.stdout
        )

    except json.JSONDecodeError as erro:
        print(
            f"[ERRO] JSON inválido "
            f"no Semgrep ({config}): {erro}"
        )

        return {
            "executado": False,
            "findings": [],
            "errors": [
                {
                    "message": (
                        f"JSON inválido: {erro}"
                    )
                }
            ],
            "scanned": [],
        }

    findings = (
        dados.get("results")
        or []
    )

    erros = (
        dados.get("errors")
        or []
    )

    paths = (
        dados.get("paths")
        or {}
    )

    scanned = (
        paths.get("scanned")
        or []
    )

    print(
        f"[OK] Config {config}: "
        f"{len(findings)} finding(s)."
    )

    if erros:
        print(
            f"[AVISO] Config {config} retornou "
            f"{len(erros)} erro(s) não fatal(is)."
        )

        for i, erro in enumerate(
            erros[:3],
            start=1,
        ):
            print(
                f"[DEBUG] Erro {i}: {erro}"
            )

    return {
        "executado": True,
        "findings": findings,
        "errors": erros,
        "scanned": scanned,
    }


# ============================================================
# EXECUTAR UMA CONFIGURAÇÃO
# ============================================================

def executar_config_semgrep(
    repo_path: str,
    config: str,
) -> list:
    """
    Mantém a interface antiga usada pelo scanner principal.
    """
    resultado = executar_config_semgrep_detalhado(
        repo_path,
        config,
    )

    return resultado["findings"]


# ============================================================
# CHAVE PARA DEDUPLICAÇÃO
# ============================================================

def chave_finding(
    finding: dict
) -> tuple:
    start = finding.get(
        "start",
        {},
    )

    end = finding.get(
        "end",
        {},
    )

    return (
        finding.get(
            "check_id",
            "",
        ),
        finding.get(
            "path",
            "",
        ),
        start.get(
            "line",
            0,
        ),
        start.get(
            "col",
            0,
        ),
        end.get(
            "line",
            0,
        ),
        end.get(
            "col",
            0,
        ),
    )


# ============================================================
# EXECUTAR SEMGREP COMPLETO
# ============================================================

def run_semgrep(
    repo_path: str
) -> list:
    repo_path = os.path.abspath(
        repo_path
    )

    if not os.path.isdir(repo_path):
        print(
            "[ERRO] Repositório não encontrado: "
            f"{repo_path}"
        )
        return []

    if not verificar_semgrep():
        return []

    print(
        f"[INFO] Semgrep analisando: "
        f"{repo_path}"
    )

    print(
        "[INFO] Configurações: "
        + ", ".join(SEMGREP_CONFIGS)
    )

    todos_findings = []

    for config in SEMGREP_CONFIGS:
        findings_config = (
            executar_config_semgrep(
                repo_path,
                config,
            )
        )

        todos_findings.extend(
            findings_config
        )

    findings_unicos = []
    chaves_vistas = set()

    for finding in todos_findings:
        chave = chave_finding(
            finding
        )

        if chave in chaves_vistas:
            continue

        chaves_vistas.add(
            chave
        )

        findings_unicos.append(
            finding
        )

    duplicados = (
        len(todos_findings)
        -
        len(findings_unicos)
    )

    print(
        "\n========================================"
    )
    print(
        "SEMGREP - RESULTADO FINAL"
    )
    print(
        "========================================"
    )
    print(
        f"Brutos:      "
        f"{len(todos_findings)}"
    )
    print(
        f"Duplicados:  "
        f"{duplicados}"
    )
    print(
        f"Únicos:      "
        f"{len(findings_unicos)}"
    )
    print(
        "========================================"
    )

    return findings_unicos


# ============================================================
# RE-SCAN DETERMINÍSTICO
# ============================================================

def verificar_rule_id_no_diretorio(
    repo_path: str,
    rule_id: str,
) -> dict:
    """
    Executa o mesmo conjunto de configurações do scanner SAST
    e verifica especificamente se a rule_id original reaparece.

    Para considerar o re-scan utilizável, pelo menos uma
    configuração precisa ter realmente escaneado o arquivo.
    """
    repo_path = os.path.abspath(
        repo_path
    )

    if not os.path.isdir(repo_path):
        return {
            "executado": False,
            "rule_encontrada": False,
            "motivo": (
                "Diretório temporário de validação "
                "não existe."
            ),
        }

    if not verificar_semgrep():
        return {
            "executado": False,
            "rule_encontrada": False,
            "motivo": (
                "Semgrep não está disponível."
            ),
        }

    alguma_config_escaneou = False
    avisos = []

    for config in SEMGREP_CONFIGS:
        resultado = executar_config_semgrep_detalhado(
            repo_path,
            config,
        )

        if not resultado["executado"]:
            avisos.append(
                f"{config}: execução falhou"
            )
            continue

        if resultado["scanned"]:
            alguma_config_escaneou = True

        if resultado["errors"]:
            avisos.append(
                f"{config}: "
                f"{len(resultado['errors'])} erro(s)"
            )

        for finding in resultado["findings"]:
            if finding.get("check_id") == rule_id:
                return {
                    "executado": True,
                    "rule_encontrada": True,
                    "motivo": (
                        "A mesma rule_id voltou a ser "
                        "detectada após o re-scan."
                    ),
                    "avisos": avisos,
                }

    if not alguma_config_escaneou:
        return {
            "executado": False,
            "rule_encontrada": False,
            "motivo": (
                "Nenhuma configuração do Semgrep "
                "confirmou que o arquivo temporário "
                "foi escaneado."
            ),
            "avisos": avisos,
        }

    return {
        "executado": True,
        "rule_encontrada": False,
        "motivo": (
            "A rule_id original não foi detectada "
            "no código corrigido."
        ),
        "avisos": avisos,
    }


# ============================================================
# NORMALIZAR UM FINDING
# ============================================================

def normalizar_finding(
    finding_raw: dict,
    repo_url: str
) -> dict | None:
    try:
        extra = finding_raw.get(
            "extra",
            {},
        )

        rule_id = finding_raw.get(
            "check_id",
            "",
        )

        if not rule_id:
            return None

        severity_raw = extra.get(
            "severity",
            "INFO",
        )

        severity = normalizar_severidade(
            severity_raw
        )

        file_path = finding_raw.get(
            "path",
            "",
        )

        file_path = (
            file_path or ""
        ).replace(
            "\\",
            "/",
        )

        linha = (
            finding_raw
            .get("start", {})
            .get("line", 0)
        )

        mensagem = extra.get(
            "message",
            "",
        )

        if not mensagem:
            mensagem = (
                "Vulnerabilidade identificada "
                "pelo Semgrep."
            )

        return {
            "fonte": "semgrep",
            "tipo": severity,
            "repo_url": repo_url,
            "rule_id": rule_id,
            "file_path": file_path,
            "line": linha,
            "message": mensagem,
            "detalhes": (
                f"rule={rule_id} "
                f"file={file_path}"
            ),
        }

    except Exception as erro:
        print(
            "[ERRO] Falha ao normalizar "
            f"finding Semgrep: {erro}"
        )
        return None


# ============================================================
# NORMALIZAR TODOS
# ============================================================

def normalizar_todos_findings(
    findings_raw: list,
    repo_url: str
) -> list:
    normalizados = []

    for i, finding in enumerate(
        findings_raw,
        start=1,
    ):
        resultado = normalizar_finding(
            finding,
            repo_url,
        )

        if resultado:
            normalizados.append(
                resultado
            )
        else:
            print(
                f"[AVISO] Finding Semgrep {i} "
                "inválido — ignorado."
            )

    print(
        f"[OK] Semgrep normalizou "
        f"{len(normalizados)} finding(s)."
    )

    return normalizados
