"""
Validador estrutural AST da CodeShield ASPM.

Objetivo:
- Comparar código Python original e corrigido
- Verificar se ambos possuem sintaxe válida
- Medir quanto a estrutura mudou
- Identificar alterações pequenas ou reescritas muito grandes

IMPORTANTE:
Este módulo NÃO executa o código analisado.
Usa somente ast.parse().
"""

import ast
from collections import Counter


# ============================================================
# AUXILIARES
# ============================================================

def extrair_tipos_nos(arvore: ast.AST) -> list[str]:
    """
    Retorna os tipos de nós presentes na AST.

    Exemplo:
    FunctionDef, arguments, Return, Call, Name...
    """

    return [
        type(no).__name__
        for no in ast.walk(arvore)
    ]


def calcular_similaridade_ast(
    arvore_original: ast.AST,
    arvore_corrigida: ast.AST,
) -> float:
    """
    Compara a quantidade dos tipos de nós existentes
    nas duas árvores.

    Retorna valor entre 0.0 e 1.0.
    """

    nos_original = Counter(
        extrair_tipos_nos(arvore_original)
    )

    nos_corrigidos = Counter(
        extrair_tipos_nos(arvore_corrigida)
    )

    total_original = sum(
        nos_original.values()
    )

    total_corrigido = sum(
        nos_corrigidos.values()
    )

    if total_original == 0 and total_corrigido == 0:
        return 1.0

    intersecao = sum(
        (
            nos_original
            &
            nos_corrigidos
        ).values()
    )

    maior_total = max(
        total_original,
        total_corrigido,
    )

    if maior_total == 0:
        return 0.0

    return round(
        intersecao / maior_total,
        3,
    )


# ============================================================
# VALIDAÇÃO PRINCIPAL
# ============================================================

def validar_diff_ast(
    codigo_original: str,
    codigo_corrigido: str,
) -> dict:
    """
    Compara estruturalmente dois códigos Python.

    Retorno:

    {
        "valido": bool,
        "mudanca_cirurgica": bool,
        "similaridade": float,
        "motivo": str
    }
    """

    if not codigo_original.strip():
        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": "Código original vazio.",
        }

    if not codigo_corrigido.strip():
        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": "Código corrigido vazio.",
        }

    # --------------------------------------------------------
    # AST ORIGINAL
    # --------------------------------------------------------

    try:
        arvore_original = ast.parse(
            codigo_original
        )

    except SyntaxError as erro:
        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": (
                "Código original possui erro "
                f"de sintaxe: {erro}"
            ),
        }

    # --------------------------------------------------------
    # AST CORRIGIDA
    # --------------------------------------------------------

    try:
        arvore_corrigida = ast.parse(
            codigo_corrigido
        )

    except SyntaxError as erro:
        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": (
                "Código corrigido possui erro "
                f"de sintaxe: {erro}"
            ),
        }

    # --------------------------------------------------------
    # COMPARAÇÃO
    # --------------------------------------------------------

    similaridade = calcular_similaridade_ast(
        arvore_original,
        arvore_corrigida,
    )

    quantidade_original = len(
        list(
            ast.walk(
                arvore_original
            )
        )
    )

    quantidade_corrigida = len(
        list(
            ast.walk(
                arvore_corrigida
            )
        )
    )

    # Consideramos >= 70% uma alteração estrutural
    # suficientemente próxima para este Nível 2.
    mudanca_cirurgica = (
        similaridade >= 0.70
    )

    if mudanca_cirurgica:
        motivo = (
            "A estrutura principal foi preservada. "
            "A alteração parece localizada."
        )

    else:
        motivo = (
            "A estrutura mudou significativamente. "
            "O fix deve ser revisado manualmente."
        )

    return {
        "valido": True,
        "mudanca_cirurgica": mudanca_cirurgica,
        "similaridade": similaridade,
        "nos_original": quantidade_original,
        "nos_corrigido": quantidade_corrigida,
        "motivo": motivo,
    }


# ============================================================
# TESTE LOCAL
# ============================================================

if __name__ == "__main__":

    original = """
def executar(x):
    return eval(x)
"""

    corrigido = """
def executar(x):
    return int(x)
"""

    resultado = validar_diff_ast(
        original,
        corrigido,
    )

    print(
        "\\n===== AST VALIDATOR =====\\n"
    )

    print(resultado)