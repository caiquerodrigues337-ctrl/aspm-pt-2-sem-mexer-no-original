"""
Scanner DAST básico do CodeShield ASPM usando OWASP ZAP Baseline.

Características:
- Executa ZAP via Docker.
- Usa zap-baseline.py (spider + passive scan).
- Não executa active scan.
- Gera relatório JSON.
- Normaliza alerts para o formato de findings do CodeShield.
- Não usa shell=True.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid
from urllib.parse import urlparse, urlunparse


ZAP_IMAGE = os.getenv(
    "ZAP_DOCKER_IMAGE",
    "ghcr.io/zaproxy/zaproxy:stable",
)

ZAP_REPORT_NAME = "zap-report.json"


def _texto_limpo(valor: object) -> str:
    texto = html.unescape(str(valor or ""))
    texto = re.sub(r"<[^>]+>", " ", texto)
    texto = re.sub(r"\s+", " ", texto)
    return texto.strip()


def _validar_target_url(target_url: str) -> str:
    target = (target_url or "").strip()

    if not target:
        raise ValueError("Informe a URL da aplicação para o DAST.")

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "A URL do DAST deve começar com http:// ou https://."
        )

    if not parsed.hostname:
        raise ValueError("URL de DAST inválida.")

    if parsed.username or parsed.password:
        raise ValueError(
            "Não informe usuário ou senha diretamente na URL do DAST."
        )

    return target


def _target_para_docker(target_url: str) -> str:
    parsed = urlparse(target_url)

    if parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        return target_url

    host = "host.docker.internal"

    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    else:
        netloc = host

    return urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def verificar_docker() -> bool:
    docker = shutil.which("docker")

    if not docker:
        print("[ERRO] Docker não foi encontrado no PATH.")
        return False

    try:
        resultado = subprocess.run(
            [
                docker,
                "version",
                "--format",
                "{{.Server.Version}}",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )

        if resultado.returncode != 0:
            print(
                "[ERRO] Docker foi encontrado, "
                "mas o Docker Engine não respondeu."
            )

            if resultado.stderr:
                print(
                    "[DEBUG] Docker stderr: "
                    f"{resultado.stderr[:800]}"
                )

            return False

        versao = (resultado.stdout or "").strip()

        print(
            "[INFO] Docker disponível"
            + (f": {versao}" if versao else ".")
        )

        return True

    except Exception as erro:
        print(f"[ERRO] Falha ao verificar Docker: {erro}")
        return False


def verificar_imagem_zap() -> bool:
    docker = shutil.which("docker")

    if not docker:
        return False

    inspect = subprocess.run(
        [
            docker,
            "image",
            "inspect",
            ZAP_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if inspect.returncode == 0:
        print(f"[INFO] Imagem ZAP disponível: {ZAP_IMAGE}")
        return True

    print(
        "[INFO] Imagem OWASP ZAP ainda não está local. "
        "Baixando..."
    )

    try:
        pull = subprocess.run(
            [
                docker,
                "pull",
                ZAP_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        if pull.returncode != 0:
            print("[ERRO] Não foi possível baixar a imagem do ZAP.")

            if pull.stderr:
                print(
                    "[DEBUG] Docker pull stderr: "
                    f"{pull.stderr[:1200]}"
                )

            return False

        print("[OK] Imagem OWASP ZAP baixada.")
        return True

    except subprocess.TimeoutExpired:
        print(
            "[ERRO] Download da imagem OWASP ZAP "
            "excedeu 15 minutos."
        )
        return False


def _ler_relatorio_zap(caminho: Path) -> list[dict]:
    if not caminho.is_file():
        print(
            "[ERRO] O ZAP terminou sem gerar "
            "o relatório JSON esperado."
        )
        return []

    try:
        dados = json.loads(
            caminho.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        )
    except Exception as erro:
        print(
            "[ERRO] Não foi possível ler "
            f"o relatório JSON do ZAP: {erro}"
        )
        return []

    alerts: list[dict] = []

    for site in dados.get("site", []) or []:
        site_name = (
            site.get("@name")
            or site.get("name")
            or ""
        )

        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue

            item = dict(alert)
            item["_codeshield_site"] = site_name
            alerts.append(item)

    return alerts


def run_zap(
    target_url: str,
    spider_minutes: int = 1,
    timeout_minutes: int = 8,
) -> list[dict]:
    """
    Executa OWASP ZAP Baseline contra uma URL autorizada.
    Retorna a lista bruta de alerts do relatório JSON.
    """

    target = _validar_target_url(target_url)

    if not verificar_docker():
        return []

    if not verificar_imagem_zap():
        return []

    spider_minutes = max(
        1,
        min(int(spider_minutes), 10),
    )

    timeout_minutes = max(
        3,
        min(int(timeout_minutes), 30),
    )

    target_docker = _target_para_docker(target)
    docker = shutil.which("docker")

    with tempfile.TemporaryDirectory(
        prefix="codeshield_zap_"
    ) as tmp:
        workdir = Path(tmp).resolve()
        report_path = workdir / ZAP_REPORT_NAME
        volume = f"{workdir}:/zap/wrk/:rw"

        container_name = (
            "codeshield-zap-"
            + uuid.uuid4().hex[:10]
        )

        comando = [
            docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "-v",
            volume,
            ZAP_IMAGE,
            "zap-baseline.py",
            "-t",
            target_docker,
            "-J",
            ZAP_REPORT_NAME,
            "-I",
            "-m",
            str(spider_minutes),
            "-T",
            str(timeout_minutes),
            "--autooff",
        ]

        print(
            "[INFO] OWASP ZAP Baseline analisando: "
            f"{target}"
        )

        if target_docker != target:
            print(
                "[INFO] URL usada pelo container: "
                f"{target_docker}"
            )

        try:
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=(timeout_minutes + 5) * 60,
            )

        except subprocess.TimeoutExpired:
            print(
                "[ERRO] OWASP ZAP excedeu "
                "o tempo máximo configurado."
            )

            try:
                subprocess.run(
                    [
                        docker,
                        "rm",
                        "-f",
                        container_name,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                print(
                    "[INFO] Container ZAP temporário "
                    "foi removido."
                )

            except Exception as erro_cleanup:
                print(
                    "[AVISO] Não foi possível remover "
                    "o container ZAP automaticamente: "
                    f"{erro_cleanup}"
                )

            return []

        if resultado.returncode not in (0, 1, 2):
            print(
                "[ERRO] OWASP ZAP terminou "
                f"com código {resultado.returncode}."
            )

            saida = (
                resultado.stderr
                or resultado.stdout
                or ""
            )

            if saida:
                print(
                    "[DEBUG] ZAP: "
                    f"{saida[-1800:]}"
                )

            return []

        alerts = _ler_relatorio_zap(
            report_path
        )

        print(
            "[OK] OWASP ZAP encontrou "
            f"{len(alerts)} alert(s)."
        )

        return alerts


def _severidade_zap(alert: dict) -> str:
    riskcode = str(
        alert.get("riskcode")
        or ""
    ).strip()

    if riskcode == "3":
        return "HIGH"

    if riskcode == "2":
        return "MEDIUM"

    if riskcode == "1":
        return "LOW"

    riskdesc = _texto_limpo(
        alert.get("riskdesc")
        or alert.get("risk")
    ).lower()

    if "high" in riskdesc:
        return "HIGH"

    if "medium" in riskdesc:
        return "MEDIUM"

    return "LOW"


def normalizar_finding_zap(
    alert: dict,
    target_url: str,
) -> dict | None:
    try:
        plugin_id = str(
            alert.get("pluginid")
            or alert.get("alertRef")
            or "unknown"
        ).strip()

        nome = _texto_limpo(
            alert.get("alert")
            or alert.get("name")
            or "OWASP ZAP alert"
        )

        descricao = _texto_limpo(
            alert.get("desc")
        )

        solucao = _texto_limpo(
            alert.get("solution")
        )

        cwe = str(
            alert.get("cweid")
            or ""
        ).strip()

        instances = (
            alert.get("instances")
            or []
        )

        instancia = (
            instances[0]
            if instances
            and isinstance(instances[0], dict)
            else {}
        )

        uri = (
            instancia.get("uri")
            or alert.get("_codeshield_site")
            or target_url
        )

        metodo = (
            instancia.get("method")
            or ""
        )

        parametro = (
            instancia.get("param")
            or ""
        )

        qtd = (
            alert.get("count")
            or len(instances)
            or 1
        )

        partes = [nome]

        if descricao:
            partes.append(descricao)

        partes.append(
            f"URL: {uri}"
        )

        if metodo:
            partes.append(
                f"Método: {metodo}"
            )

        if parametro:
            partes.append(
                f"Parâmetro: {parametro}"
            )

        if solucao:
            partes.append(
                f"Remediação: {solucao}"
            )

        partes.append(
            f"Ocorrências: {qtd}"
        )

        mensagem = " | ".join(
            partes
        )

        if len(mensagem) > 3500:
            mensagem = mensagem[:3497] + "..."

        detalhes = (
            f"plugin_id={plugin_id}"
            + (
                f" cwe={cwe}"
                if cwe
                else ""
            )
            + f" target={target_url}"
        )

        return {
            "fonte": "zap",
            "tipo": _severidade_zap(alert),
            "repo_url": target_url,
            "rule_id": f"ZAP-{plugin_id}",
            "file_path": uri,
            "line": 0,
            "message": mensagem,
            "detalhes": detalhes,
        }

    except Exception as erro:
        print(
            "[ERRO] Falha ao normalizar "
            f"finding ZAP: {erro}"
        )
        return None


def normalizar_todos_findings_zap(
    alerts_raw: list,
    target_url: str,
) -> list:
    normalizados = []

    for i, alert in enumerate(
        alerts_raw,
        start=1,
    ):
        finding = normalizar_finding_zap(
            alert,
            target_url,
        )

        if finding:
            normalizados.append(
                finding
            )
        else:
            print(
                f"[AVISO] Alert ZAP {i} "
                "inválido — ignorado."
            )

    print(
        "[OK] OWASP ZAP normalizou "
        f"{len(normalizados)} finding(s)."
    )

    return normalizados
