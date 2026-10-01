"""
Scanner SAST da CodeShield ASPM.

Responsável por:
- Localizar o executável do Semgrep
- Executar múltiplas configurações de análise
- Coletar findings válidos mesmo quando uma configuração falha
- Remover findings duplicados
- Normalizar severidades
- Converter findings para o padrão interno da CodeShield
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

# O "auto" tenta descobrir regras automaticamente.
# O "p/python" garante cobertura das regras Python,
# que foi a configuração que encontrou os findings no teste manual.
SEMGREP_CONFIGS = [
    "auto",
    "p/python",
]


# ============================================================
# LOCALIZAR SEMGREP
# ============================================================

def localizar_semgrep() -> str:
    """
    Localiza o executável do Semgrep.

    Ordem:
    1. PATH
    2. Ambiente virtual atual
    3. fallback para "semgrep"
    """

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
    """
    Converte severidades do Semgrep
    para o padrão da CodeShield.
    """

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
    """
    Confirma que o executável está disponível.
    """

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
            "[INFO] Instale com:"
        )

        print(
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
# EXECUTAR UMA CONFIGURAÇÃO
# ============================================================

def executar_config_semgrep(
    repo_path: str,
    config: str,
) -> list:
    """
    Executa uma configuração específica do Semgrep.

    Exemplo:
    auto
    p/python
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

            # Muito importante:
            # executa dentro do repositório analisado.
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

        return []

    except Exception as erro:
        print(
            f"[ERRO] Falha no Semgrep "
            f"({config}): {erro}"
        )

        return []

    # ========================================================
    # SEM JSON
    # ========================================================

    if not resultado.stdout.strip():
        print(
            f"[INFO] Semgrep ({config}) "
            "não retornou JSON."
        )

        if resultado.stderr.strip():
            print(
                "[DEBUG] stderr:"
            )

            print(
                resultado.stderr[:1000]
            )

        return []

    # ========================================================
    # PARSE JSON
    # ========================================================

    try:
        dados = json.loads(
            resultado.stdout
        )

    except json.JSONDecodeError as erro:
        print(
            f"[ERRO] JSON inválido "
            f"no Semgrep ({config}): {erro}"
        )

        return []

    findings = (
        dados.get("results")
        or []
    )

    erros = (
        dados.get("errors")
        or []
    )

    print(
        f"[OK] Config {config}: "
        f"{len(findings)} finding(s)."
    )

    # ========================================================
    # ERROS NÃO FATAIS
    # ========================================================

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

    # Os findings válidos continuam sendo retornados,
    # mesmo que existam erros de parsing em outros arquivos.
    return findings


# ============================================================
# CHAVE PARA DEDUPLICAÇÃO
# ============================================================

def chave_finding(
    finding: dict
) -> tuple:
    """
    Cria uma chave única aproximada para remover
    findings duplicados entre múltiplas configurações.
    """

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
    """
    Executa todas as configurações definidas
    em SEMGREP_CONFIGS.

    Os resultados são combinados e deduplicados.
    """

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

    # ========================================================
    # EXECUTAR CONFIGURAÇÕES
    # ========================================================

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

    # ========================================================
    # REMOVER DUPLICADOS
    # ========================================================

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
# NORMALIZAR UM FINDING
# ============================================================

def normalizar_finding(
    finding_raw: dict,
    repo_url: str
) -> dict | None:
    """
    Converte o formato bruto do Semgrep
    para o formato interno da CodeShield.
    """

    try:
        extra = finding_raw.get(
            "extra",
            {},
        )

        # ====================================================
        # RULE ID
        # ====================================================

        rule_id = finding_raw.get(
            "check_id",
            "",
        )

        if not rule_id:
            return None

        # ====================================================
        # SEVERIDADE
        # ====================================================

        severity_raw = extra.get(
            "severity",
            "INFO",
        )

        severity = normalizar_severidade(
            severity_raw
        )

        # ====================================================
        # ARQUIVO
        # ====================================================

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

        # ====================================================
        # LINHA
        # ====================================================

        linha = (
            finding_raw
            .get("start", {})
            .get("line", 0)
        )

        # ====================================================
        # MENSAGEM
        # ====================================================

        mensagem = extra.get(
            "message",
            "",
        )

        if not mensagem:
            mensagem = (
                "Vulnerabilidade identificada "
                "pelo Semgrep."
            )

        # ====================================================
        # RESULTADO PADRONIZADO
        # ====================================================

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
    """
    Normaliza todos os findings encontrados.

    Findings inválidos são ignorados sem
    interromper o scan completo.
    """

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