"""
Validação determinística de fixes da CodeShield ASPM.

Nível 1:
- Extrai o bloco de código gerado pela IA
- Escreve o código em diretório temporário
- Executa novamente o Semgrep
- Verifica se a mesma rule_id reaparece

Nenhum código é executado. Apenas análise estática é realizada.
"""

from pathlib import Path
import re
import tempfile

from app.scanners.semgrep import (
    verificar_rule_id_no_diretorio,
)


def extrair_bloco_codigo(
    ai_fix: str
) -> str | None:
    """
    Extrai um único bloco Markdown ```...``` da resposta da IA.

    Se não houver bloco ou se houver conteúdo vazio, a validação
    não é realizada automaticamente.
    """
    if not ai_fix:
        return None

    blocos = re.findall(
        r"```(?:[A-Za-z0-9_+\-.]+)?\s*(.*?)```",
        ai_fix,
        flags=re.DOTALL,
    )

    blocos = [
        bloco.strip()
        for bloco in blocos
        if bloco.strip()
    ]

    if not blocos:
        return None

    # O prompt pede exatamente um bloco. Se o modelo retornar
    # vários, escolhemos o primeiro e deixamos registrado em log.
    if len(blocos) > 1:
        print(
            "[AVISO] A IA retornou mais de um bloco "
            "de código. Será usado apenas o primeiro."
        )

    return blocos[0]


def obter_nome_temporario(
    file_path: str
) -> str:
    """
    Preserva a extensão do arquivo original para que o Semgrep
    identifique corretamente a linguagem.
    """
    caminho = Path(
        file_path or "fix.py"
    )

    sufixo = caminho.suffix

    if not sufixo:
        sufixo = ".py"

    nome = caminho.stem or "fix"

    return f"{nome}_codeshield_fix{sufixo}"


def validar_fix_re_scan(
    ai_fix: str,
    rule_id: str,
    file_path: str = "",
) -> dict:
    """
    Retorna:
    {
        "validado": True | False | None,
        "motivo": str
    }

    True  -> Semgrep escaneou o código e a rule_id sumiu.
    False -> A mesma rule_id continua presente.
    None  -> Não foi possível validar de forma confiável.
    """
    if not ai_fix:
        return {
            "validado": None,
            "motivo": (
                "Não existe correção de IA para validar."
            ),
        }

    if not rule_id:
        return {
            "validado": None,
            "motivo": (
                "Finding sem rule_id; validação impossível."
            ),
        }

    codigo_corrigido = extrair_bloco_codigo(
        ai_fix
    )

    if not codigo_corrigido:
        return {
            "validado": None,
            "motivo": (
                "A resposta da IA não contém um bloco "
                "de código corrigido."
            ),
        }

    nome_arquivo = obter_nome_temporario(
        file_path
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="codeshield_fix_"
        ) as tmp:
            caminho = (
                Path(tmp)
                / nome_arquivo
            )

            caminho.write_text(
                codigo_corrigido,
                encoding="utf-8",
            )

            resultado = (
                verificar_rule_id_no_diretorio(
                    tmp,
                    rule_id,
                )
            )

            if not resultado.get(
                "executado",
                False,
            ):
                return {
                    "validado": None,
                    "motivo": (
                        "O re-scan não pôde confirmar "
                        "a análise: "
                        f"{resultado.get('motivo', '')}"
                    ),
                }

            if resultado.get(
                "rule_encontrada",
                False,
            ):
                return {
                    "validado": False,
                    "motivo": (
                        "Fix NÃO validado: a mesma "
                        "rule_id continua sendo detectada."
                    ),
                }

            return {
                "validado": True,
                "motivo": (
                    "Fix validado no Nível 1: "
                    "a rule_id original não foi detectada "
                    "no re-scan estático."
                ),
            }

    except Exception as erro:
        print(
            "[ERRO] Falha ao validar fix "
            f"por re-scan: {erro}"
        )

        return {
            "validado": None,
            "motivo": (
                "Erro interno durante a validação "
                f"do fix: {erro}"
            ),
        }
