"""
Validação determinística de fixes da CodeShield ASPM.

Objetivo:
- Reproduzir a mesma rule_id no código original (baseline)
- Aplicar o fix sugerido pela IA somente em uma cópia temporária
- Validar sintaxe/estrutura Python com AST quando aplicável
- Executar novamente o Semgrep
- Confirmar se a mesma rule_id desapareceu

IMPORTANTE:
- O repositório original nunca é alterado.
- Nenhum código recebido da IA é executado.
- A validação usa somente análise estática e ast.parse().
"""

from pathlib import Path
import ast
import re
import tempfile
import textwrap

from app.scanners.semgrep import (
    verificar_rule_id_no_diretorio,
)

from app.validators.ast_validator import (
    validar_diff_ast,
)


# ============================================================
# CAMINHOS / ARQUIVO ORIGINAL
# ============================================================

def resolver_caminho_original(
    repo_path: str,
    file_path: str,
) -> Path | None:
    """
    Resolve o arquivo do finding dentro do clone temporário.

    Evita aceitar um caminho que escape do diretório do repositório.
    """

    if not repo_path or not file_path:
        return None

    try:
        raiz = Path(repo_path).resolve()

        caminho_relativo = Path(
            str(file_path)
            .replace("\\", "/")
            .lstrip("/")
        )

        candidato = (
            raiz
            / caminho_relativo
        ).resolve()

        try:
            candidato.relative_to(raiz)

        except ValueError:
            return None

        if not candidato.is_file():
            return None

        return candidato

    except Exception:
        return None


def ler_codigo_original_completo(
    repo_path: str,
    file_path: str,
) -> str | None:
    caminho = resolver_caminho_original(
        repo_path,
        file_path,
    )

    if caminho is None:
        return None

    try:
        return caminho.read_text(
            encoding="utf-8",
            errors="ignore",
        )

    except Exception:
        return None


# ============================================================
# EXTRAÇÃO DO FIX DA RESPOSTA DA IA
# ============================================================

def listar_blocos_codigo(
    ai_fix: str,
) -> list[dict]:
    """
    Retorna todos os blocos Markdown de código da resposta da IA.
    """

    if not ai_fix:
        return []

    encontrados = re.findall(
        (
            r"```"
            r"([A-Za-z0-9_+\-.]*)"
            r"\s*"
            r"(.*?)"
            r"```"
        ),
        ai_fix,
        flags=re.DOTALL,
    )

    blocos = []

    for linguagem, codigo in encontrados:
        codigo = (
            codigo
            or ""
        ).strip()

        if not codigo:
            continue

        blocos.append(
            {
                "linguagem": (
                    linguagem
                    or ""
                ).lower().strip(),
                "codigo": codigo,
            }
        )

    return blocos


def linguagem_esperada(
    file_path: str,
) -> set[str]:
    extensao = (
        Path(
            file_path
            or ""
        )
        .suffix
        .lower()
        .lstrip(".")
    )

    mapa = {
        "py": {
            "python",
            "py",
        },
        "js": {
            "javascript",
            "js",
        },
        "jsx": {
            "javascript",
            "jsx",
        },
        "ts": {
            "typescript",
            "ts",
        },
        "tsx": {
            "typescript",
            "tsx",
        },
        "java": {
            "java",
        },
        "go": {
            "go",
        },
        "php": {
            "php",
        },
        "rb": {
            "ruby",
            "rb",
        },
    }

    return mapa.get(
        extensao,
        set(),
    )


def extrair_bloco_codigo(
    ai_fix: str,
    file_path: str = "",
    simbolo_esperado: str = "",
) -> str | None:
    """
    Escolhe o bloco de código mais provável de conter o fix.

    Critérios:
    - linguagem compatível com a extensão
    - presença do nome da função/classe original
    - maior bloco como critério de desempate
    """

    blocos = listar_blocos_codigo(
        ai_fix
    )

    if not blocos:
        return None

    if len(blocos) > 1:
        print(
            "[AVISO] A IA retornou mais de um bloco "
            "de código."
        )

    linguagens = linguagem_esperada(
        file_path
    )

    def pontuar(
        bloco: dict,
    ) -> tuple[int, int]:

        pontos = 0

        linguagem = bloco[
            "linguagem"
        ]

        codigo = bloco[
            "codigo"
        ]

        if (
            linguagem
            and linguagem in linguagens
        ):
            pontos += 5

        if simbolo_esperado:
            padroes = [
                rf"\bdef\s+{re.escape(simbolo_esperado)}\b",
                rf"\basync\s+def\s+{re.escape(simbolo_esperado)}\b",
                rf"\bclass\s+{re.escape(simbolo_esperado)}\b",
            ]

            if any(
                re.search(
                    padrao,
                    codigo,
                )
                for padrao in padroes
            ):
                pontos += 20

        return (
            pontos,
            len(codigo),
        )

    escolhido = max(
        blocos,
        key=pontuar,
    )

    return escolhido[
        "codigo"
    ]


# ============================================================
# BLOCO ESTRUTURAL PYTHON
# ============================================================

def encontrar_bloco_python(
    codigo: str,
    line: int,
) -> dict | None:
    """
    Localiza a menor função, método ou classe Python que contém
    a linha do finding.
    """

    if not codigo or not line:
        return None

    try:
        arvore = ast.parse(
            codigo
        )

    except SyntaxError:
        return None

    candidatos = []

    for no in ast.walk(
        arvore
    ):
        if not isinstance(
            no,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        ):
            continue

        inicio = getattr(
            no,
            "lineno",
            None,
        )

        fim = getattr(
            no,
            "end_lineno",
            None,
        )

        if (
            inicio is None
            or fim is None
            or not (
                inicio
                <= int(line)
                <= fim
            )
        ):
            continue

        inicio_real = inicio

        decoradores = getattr(
            no,
            "decorator_list",
            [],
        )

        if decoradores:
            inicio_real = min(
                [
                    inicio,
                    *[
                        getattr(
                            decorador,
                            "lineno",
                            inicio,
                        )
                        for decorador
                        in decoradores
                    ],
                ]
            )

        candidatos.append(
            {
                "inicio": inicio_real,
                "fim": fim,
                "nome": getattr(
                    no,
                    "name",
                    "",
                ),
                "tipo": type(
                    no
                ).__name__,
                "tamanho": (
                    fim
                    - inicio_real
                ),
            }
        )

    if not candidatos:
        return None

    return min(
        candidatos,
        key=lambda item: item[
            "tamanho"
        ],
    )


def obter_indentacao_linha(
    linha: str,
) -> str:
    return linha[
        :len(linha)
        - len(
            linha.lstrip(
                " \t"
            )
        )
    ]


def ajustar_indentacao(
    codigo: str,
    indentacao: str,
) -> str:
    """
    Normaliza a indentação externa do bloco retornado pela IA
    e o recoloca no mesmo nível do bloco original.
    """

    codigo = textwrap.dedent(
        codigo
        or ""
    ).strip()

    if not codigo:
        return ""

    linhas = codigo.splitlines()

    return "\n".join(
        (
            indentacao
            + linha
            if linha.strip()
            else ""
        )
        for linha in linhas
    )


def substituir_bloco_python(
    codigo_original: str,
    codigo_corrigido: str,
    bloco: dict,
) -> str:
    """
    Substitui somente a unidade estrutural que contém o finding.
    """

    linhas = codigo_original.splitlines(
        keepends=True
    )

    inicio = int(
        bloco["inicio"]
    )

    fim = int(
        bloco["fim"]
    )

    indice_inicio = max(
        0,
        inicio - 1,
    )

    indice_fim = min(
        len(linhas),
        fim,
    )

    linha_inicio = (
        linhas[
            indice_inicio
        ]
        if indice_inicio
        < len(linhas)
        else ""
    )

    indentacao = obter_indentacao_linha(
        linha_inicio
    )

    bloco_corrigido = ajustar_indentacao(
        codigo_corrigido,
        indentacao,
    )

    if not bloco_corrigido:
        return codigo_original

    if not bloco_corrigido.endswith(
        "\n"
    ):
        bloco_corrigido += "\n"

    return (
        "".join(
            linhas[:indice_inicio]
        )
        + bloco_corrigido
        + "".join(
            linhas[indice_fim:]
        )
    )


# ============================================================
# TEMPORÁRIO / SEMGREP
# ============================================================

def obter_nome_temporario(
    file_path: str,
) -> str:
    caminho = Path(
        file_path
        or "fix.py"
    )

    sufixo = (
        caminho.suffix
        or ".py"
    )

    nome = (
        caminho.stem
        or "fix"
    )

    return (
        f"{nome}"
        f"_codeshield_fix"
        f"{sufixo}"
    )


def executar_re_scan(
    codigo: str,
    file_path: str,
    rule_id: str,
) -> dict:
    """
    Escreve somente uma cópia temporária e executa o Semgrep.
    """

    nome_arquivo = obter_nome_temporario(
        file_path
    )

    with tempfile.TemporaryDirectory(
        prefix="codeshield_poc_"
    ) as tmp:

        caminho = (
            Path(tmp)
            / nome_arquivo
        )

        caminho.write_text(
            codigo,
            encoding="utf-8",
        )

        return verificar_rule_id_no_diretorio(
            tmp,
            rule_id,
        )


# ============================================================
# VALIDAÇÃO AST
# ============================================================

def validar_ast_se_aplicavel(
    codigo_original: str,
    codigo_corrigido: str,
    file_path: str,
) -> dict | None:
    """
    Validação AST somente para arquivos Python.
    """

    if not str(
        file_path
    ).lower().endswith(
        ".py"
    ):
        return None

    try:
        return validar_diff_ast(
            codigo_original,
            codigo_corrigido,
        )

    except Exception as erro:
        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": (
                "Falha durante a validação AST: "
                f"{erro}"
            ),
        }


# ============================================================
# VALIDAÇÃO PRINCIPAL
# ============================================================

def validar_fix_re_scan(
    ai_fix: str,
    rule_id: str,
    file_path: str = "",
    codigo_original: str = "",
    repo_path: str = "",
    line: int = 0,
) -> dict:
    """
    Validação determinística A/B.

    Preferência:
    1. Se repo_path + file_path estiverem disponíveis:
       usa o arquivo original COMPLETO.
    2. Caso contrário:
       mantém compatibilidade com testes isolados usando
       codigo_original.

    Resultado:
    {
        "validado": True | False | None,
        "baseline_confirmado": bool,
        "rule_original_encontrada": bool,
        "rule_corrigida_encontrada": bool | None,
        "ast": dict | None,
        "modo": str,
        "motivo": str,
    }
    """

    resultado = {
        "validado": None,
        "baseline_confirmado": False,
        "rule_original_encontrada": False,
        "rule_corrigida_encontrada": None,
        "ast": None,
        "modo": "",
        "motivo": "",
    }

    if not ai_fix:
        resultado[
            "motivo"
        ] = (
            "Não existe correção de IA "
            "para validar."
        )

        return resultado

    if not rule_id:
        resultado[
            "motivo"
        ] = (
            "Finding sem rule_id; "
            "validação impossível."
        )

        return resultado

    codigo_arquivo = (
        ler_codigo_original_completo(
            repo_path,
            file_path,
        )
    )

    # ========================================================
    # MODO PRINCIPAL: ARQUIVO COMPLETO
    # ========================================================

    if codigo_arquivo is not None:

        resultado[
            "modo"
        ] = "arquivo_completo"

        bloco_python = None
        simbolo = ""

        if str(
            file_path
        ).lower().endswith(
            ".py"
        ):
            bloco_python = encontrar_bloco_python(
                codigo_arquivo,
                int(line or 0),
            )

            if bloco_python:
                simbolo = (
                    bloco_python.get(
                        "nome",
                        "",
                    )
                )

        codigo_fix = extrair_bloco_codigo(
            ai_fix=ai_fix,
            file_path=file_path,
            simbolo_esperado=simbolo,
        )

        if not codigo_fix:
            resultado[
                "motivo"
            ] = (
                "A resposta da IA não contém "
                "um bloco de código corrigido."
            )

            return resultado

        print(
            "[POC] Executando baseline em "
            "arquivo completo da rule: "
            f"{rule_id}"
        )

        baseline = executar_re_scan(
            codigo=codigo_arquivo,
            file_path=file_path,
            rule_id=rule_id,
        )

        if not baseline.get(
            "executado",
            False,
        ):
            resultado[
                "motivo"
            ] = (
                "O Semgrep não conseguiu executar "
                "o baseline no arquivo completo: "
                f"{baseline.get('motivo', '')}"
            )

            return resultado

        regra_original = baseline.get(
            "rule_encontrada",
            False,
        )

        resultado[
            "rule_original_encontrada"
        ] = regra_original

        if not regra_original:
            resultado[
                "motivo"
            ] = (
                "Baseline não confirmado mesmo usando "
                "o arquivo original completo. O fix não "
                "será marcado como válido."
            )

            return resultado

        resultado[
            "baseline_confirmado"
        ] = True

        print(
            "[POC] Baseline confirmado no "
            "arquivo completo."
        )

        # Para Python, substitui a unidade estrutural inteira.
        if (
            str(
                file_path
            ).lower().endswith(
                ".py"
            )
            and bloco_python
        ):
            codigo_corrigido = substituir_bloco_python(
                codigo_original=codigo_arquivo,
                codigo_corrigido=codigo_fix,
                bloco=bloco_python,
            )

        else:
            # Não há parser estrutural para esta linguagem ainda.
            # Evitamos marcar como válido por uma substituição incerta.
            resultado[
                "motivo"
            ] = (
                "Baseline confirmado, mas a aplicação "
                "determinística do fix em arquivo completo "
                "ainda está implementada apenas para Python."
            )

            return resultado

        resultado_ast = validar_ast_se_aplicavel(
            codigo_original=codigo_arquivo,
            codigo_corrigido=codigo_corrigido,
            file_path=file_path,
        )

        resultado[
            "ast"
        ] = resultado_ast

        if (
            resultado_ast is not None
            and not resultado_ast.get(
                "valido",
                False,
            )
        ):
            resultado[
                "validado"
            ] = False

            resultado[
                "motivo"
            ] = (
                "Fix reprovado na validação AST "
                "do arquivo completo: "
                f"{resultado_ast.get('motivo', '')}"
            )

            return resultado

        print(
            "[POC] Executando re-scan do "
            "arquivo completo corrigido."
        )

        corrigido = executar_re_scan(
            codigo=codigo_corrigido,
            file_path=file_path,
            rule_id=rule_id,
        )

        if not corrigido.get(
            "executado",
            False,
        ):
            resultado[
                "motivo"
            ] = (
                "O baseline foi confirmado, mas "
                "o Semgrep não conseguiu analisar "
                "o arquivo corrigido: "
                f"{corrigido.get('motivo', '')}"
            )

            return resultado

        regra_corrigida = corrigido.get(
            "rule_encontrada",
            False,
        )

        resultado[
            "rule_corrigida_encontrada"
        ] = regra_corrigida

        if regra_corrigida:
            resultado[
                "validado"
            ] = False

            resultado[
                "motivo"
            ] = (
                "Fix NÃO validado: a mesma rule_id "
                "continua presente no arquivo completo "
                "após a correção."
            )

            print(
                "[POC] ❌ FIX REPROVADO"
            )

            return resultado

        resultado[
            "validado"
        ] = True

        resultado[
            "motivo"
        ] = (
            "Fix validado deterministicamente: "
            "a vulnerabilidade foi reproduzida no "
            "arquivo original completo e a mesma "
            "rule_id desapareceu após aplicar a "
            "correção na cópia temporária."
        )

        print(
            "[POC] ✅ FIX VALIDADO"
        )

        return resultado

    # ========================================================
    # FALLBACK: TESTE ISOLADO CONTROLADO
    # ========================================================

    resultado[
        "modo"
    ] = "trecho_isolado"

    if not codigo_original:
        resultado[
            "motivo"
        ] = (
            "O arquivo original não pôde ser lido "
            "e nenhum código original foi fornecido."
        )

        return resultado

    codigo_original = textwrap.dedent(
        codigo_original
    ).strip()

    codigo_fix = extrair_bloco_codigo(
        ai_fix=ai_fix,
        file_path=file_path,
    )

    if not codigo_fix:
        resultado[
            "motivo"
        ] = (
            "A resposta da IA não contém "
            "um bloco de código corrigido."
        )

        return resultado

    codigo_fix = textwrap.dedent(
        codigo_fix
    ).strip()

    resultado_ast = validar_ast_se_aplicavel(
        codigo_original=(
            codigo_original
        ),
        codigo_corrigido=(
            codigo_fix
        ),
        file_path=file_path,
    )

    resultado[
        "ast"
    ] = resultado_ast

    if (
        resultado_ast is not None
        and not resultado_ast.get(
            "valido",
            False,
        )
    ):
        resultado[
            "validado"
        ] = False

        resultado[
            "motivo"
        ] = (
            "Fix reprovado na validação AST: "
            f"{resultado_ast.get('motivo', '')}"
        )

        return resultado

    print(
        "[POC] Executando baseline da rule: "
        f"{rule_id}"
    )

    baseline = executar_re_scan(
        codigo=codigo_original,
        file_path=file_path,
        rule_id=rule_id,
    )

    if not baseline.get(
        "executado",
        False,
    ):
        resultado[
            "motivo"
        ] = (
            "O Semgrep não conseguiu executar "
            "o baseline: "
            f"{baseline.get('motivo', '')}"
        )

        return resultado

    regra_original = baseline.get(
        "rule_encontrada",
        False,
    )

    resultado[
        "rule_original_encontrada"
    ] = regra_original

    if not regra_original:
        resultado[
            "motivo"
        ] = (
            "Baseline não confirmado: a rule_id "
            "original não foi reproduzida no trecho. "
            "O fix não será marcado como válido."
        )

        return resultado

    resultado[
        "baseline_confirmado"
    ] = True

    print(
        "[POC] Baseline confirmado."
    )

    print(
        "[POC] Executando re-scan "
        "do código corrigido."
    )

    corrigido = executar_re_scan(
        codigo=codigo_fix,
        file_path=file_path,
        rule_id=rule_id,
    )

    if not corrigido.get(
        "executado",
        False,
    ):
        resultado[
            "motivo"
        ] = (
            "O Semgrep não conseguiu analisar "
            "o código corrigido: "
            f"{corrigido.get('motivo', '')}"
        )

        return resultado

    regra_corrigida = corrigido.get(
        "rule_encontrada",
        False,
    )

    resultado[
        "rule_corrigida_encontrada"
    ] = regra_corrigida

    if regra_corrigida:
        resultado[
            "validado"
        ] = False

        resultado[
            "motivo"
        ] = (
            "Fix NÃO validado: a mesma rule_id "
            "continua sendo detectada."
        )

        print(
            "[POC] ❌ FIX REPROVADO"
        )

        return resultado

    resultado[
        "validado"
    ] = True

    resultado[
        "motivo"
    ] = (
        "Fix validado no modo isolado: "
        "a rule_id original foi reproduzida "
        "e desapareceu após a correção."
    )

    print(
        "[POC] ✅ FIX VALIDADO"
    )

    return resultado
