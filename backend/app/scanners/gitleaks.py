"""
Scanner de segredos da CodeShield ASPM.

Utiliza o Gitleaks para localizar credenciais, tokens e outros
segredos presentes no histórico Git do repositório.

Cuidados importantes:
- O scan usa --redact para não expor o segredo nos logs.
- A normalização NUNCA salva os campos Secret ou Match no banco.
- O módulo tenta o comando moderno "gitleaks git" e mantém
  fallback para "gitleaks detect" em versões mais antigas.
"""

import json
import os
import shutil
import subprocess
import tempfile


GITLEAKS_EXE = (
    os.getenv("GITLEAKS_EXE")
    or shutil.which("gitleaks")
    or "gitleaks"
)


def verificar_gitleaks() -> bool:
    comandos_versao = [
        [GITLEAKS_EXE, "version"],
        [GITLEAKS_EXE, "--version"],
    ]

    ultimo_erro = ""

    for comando in comandos_versao:
        try:
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if resultado.returncode == 0:
                versao = (
                    resultado.stdout.strip()
                    or resultado.stderr.strip()
                )

                print(
                    f"[INFO] Gitleaks disponível: "
                    f"{versao}"
                )

                return True

            ultimo_erro = (
                resultado.stderr.strip()
                or resultado.stdout.strip()
            )

        except FileNotFoundError:
            print(
                "[ERRO] Gitleaks não encontrado."
            )
            print(
                "[INFO] Instale o Gitleaks e "
                "garanta que ele esteja no PATH."
            )
            return False

        except Exception as erro:
            ultimo_erro = str(erro)

    print(
        "[ERRO] Não foi possível executar "
        f"o Gitleaks: {ultimo_erro}"
    )

    return False


def _ler_relatorio_json(
    caminho_relatorio: str
) -> list:
    try:
        if not os.path.exists(caminho_relatorio):
            return []

        if os.path.getsize(caminho_relatorio) == 0:
            return []

        with open(
            caminho_relatorio,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as arquivo:
            dados = json.load(arquivo)

        if isinstance(dados, list):
            return dados

        return []

    except json.JSONDecodeError as erro:
        print(
            "[ERRO] JSON inválido retornado "
            f"pelo Gitleaks: {erro}"
        )
        return []

    except Exception as erro:
        print(
            "[ERRO] Falha ao ler relatório "
            f"do Gitleaks: {erro}"
        )
        return []


def _executar_gitleaks_moderno(
    repo_path: str,
    caminho_relatorio: str,
):
    return subprocess.run(
        [
            GITLEAKS_EXE,
            "git",
            ".",
            "--report-format",
            "json",
            "--report-path",
            caminho_relatorio,
            "--redact",
            "--no-banner",
        ],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _executar_gitleaks_legado(
    repo_path: str,
    caminho_relatorio: str,
):
    return subprocess.run(
        [
            GITLEAKS_EXE,
            "detect",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            caminho_relatorio,
            "--redact",
            "--no-banner",
        ],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=600,
    )


def run_gitleaks(
    repo_path: str
) -> list:
    repo_path = os.path.abspath(repo_path)

    if not os.path.isdir(repo_path):
        print(
            "[ERRO] Caminho do repositório "
            f"não existe: {repo_path}"
        )
        return []

    if not os.path.isdir(
        os.path.join(repo_path, ".git")
    ):
        print(
            "[ERRO] Gitleaks precisa de um "
            "repositório Git válido."
        )
        return []

    if not verificar_gitleaks():
        return []

    fd, caminho_relatorio = tempfile.mkstemp(
        prefix="codeshield_gitleaks_",
        suffix=".json",
    )
    os.close(fd)

    try:
        os.remove(caminho_relatorio)
    except OSError:
        pass

    try:
        print(
            "[INFO] Gitleaks analisando "
            "o histórico Git..."
        )

        resultado = _executar_gitleaks_moderno(
            repo_path,
            caminho_relatorio,
        )

        if (
            resultado.returncode not in (0, 1)
            and (
                "unknown command" in (
                    resultado.stderr or ""
                ).lower()
                or "unknown flag" in (
                    resultado.stderr or ""
                ).lower()
                or "invalid command" in (
                    resultado.stderr or ""
                ).lower()
            )
        ):
            print(
                "[INFO] Versão antiga do Gitleaks "
                "detectada. Tentando modo detect..."
            )

            try:
                if os.path.exists(caminho_relatorio):
                    os.remove(caminho_relatorio)
            except OSError:
                pass

            resultado = _executar_gitleaks_legado(
                repo_path,
                caminho_relatorio,
            )

        if resultado.returncode not in (0, 1):
            print("[ERRO] Gitleaks falhou.")

            if resultado.stderr:
                print("[DEBUG] Gitleaks stderr:")
                print(resultado.stderr[:1000])

            return []

        findings = _ler_relatorio_json(
            caminho_relatorio
        )

        print(
            f"[OK] Gitleaks encontrou "
            f"{len(findings)} possível(is) "
            "segredo(s)."
        )

        return findings

    except subprocess.TimeoutExpired:
        print(
            "[ERRO] Gitleaks demorou "
            "mais de 10 minutos."
        )
        return []

    except Exception as erro:
        print(
            "[ERRO] Falha no Gitleaks: "
            f"{erro}"
        )
        return []

    finally:
        try:
            if os.path.exists(caminho_relatorio):
                os.remove(caminho_relatorio)
        except OSError:
            pass


def normalizar_finding_gitleaks(
    finding_raw: dict,
    repo_url: str
) -> dict | None:
    try:
        rule_id = (
            finding_raw.get("RuleID")
            or "gitleaks.secret"
        )

        descricao = (
            finding_raw.get("Description")
            or "Possível segredo detectado no histórico Git."
        )

        file_path = (
            finding_raw.get("File")
            or ""
        ).replace("\\", "/")

        linha = (
            finding_raw.get("StartLine")
            or 0
        )

        commit = (
            finding_raw.get("Commit")
            or ""
        )

        fingerprint = (
            finding_raw.get("Fingerprint")
            or ""
        )

        mensagem = descricao

        if commit:
            mensagem += (
                f" | Commit: "
                f"{commit[:12]}"
            )

        return {
            "fonte": "gitleaks",
            "tipo": "HIGH",
            "repo_url": repo_url,
            "rule_id": rule_id,
            "file_path": file_path,
            "line": linha,
            "message": mensagem,
            "detalhes": (
                f"rule={rule_id} "
                f"commit={commit[:12] if commit else 'não informado'} "
                f"fingerprint={fingerprint or 'não informado'}"
            ),
        }

    except Exception as erro:
        print(
            "[ERRO] Falha ao normalizar "
            f"finding Gitleaks: {erro}"
        )
        return None


def normalizar_todos_findings_gitleaks(
    findings_raw: list,
    repo_url: str
) -> list:
    normalizados = []

    for i, finding in enumerate(
        findings_raw,
        start=1,
    ):
        resultado = (
            normalizar_finding_gitleaks(
                finding,
                repo_url,
            )
        )

        if resultado:
            normalizados.append(resultado)
        else:
            print(
                f"[AVISO] Finding Gitleaks {i} "
                "inválido — ignorado."
            )

    print(
        "[OK] Gitleaks normalizou "
        f"{len(normalizados)} finding(s)."
    )

    return normalizados
