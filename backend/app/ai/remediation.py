"""
Integração de remediação com a Anthropic para a CodeShield ASPM.

Mantém compatibilidade com o pipeline já existente:
- usa REACT_APP_ANTHROPIC_KEY, conforme exigido pelo projeto;
- mantém MODEL e client exportados;
- mantém generate_fix() com a mesma assinatura;
- adiciona extração robusta de texto e uma segunda tentativa quando
  a API retorna conteúdo sem bloco textual utilizável.
"""

from pathlib import Path
import os

import anthropic
from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_PATH = BACKEND_DIR / ".env"

load_dotenv(ENV_PATH)

MODEL = "claude-sonnet-5"
AI_ENV_VAR = "REACT_APP_ANTHROPIC_KEY"

ANTHROPIC_KEY = ""
client = None


def obter_chave_ia() -> str:
    """
    Lê a chave sem expor o valor em logs.
    """
    return (
        os.getenv(AI_ENV_VAR)
        or ""
    ).strip()


def obter_cliente():
    """
    Retorna o cliente Anthropic.

    Se a chave mudar após um reload do backend, o cliente é recriado.
    A variável global `client` é mantida para compatibilidade com
    trechos antigos do projeto.
    """
    global client
    global ANTHROPIC_KEY

    chave_atual = obter_chave_ia()

    if not chave_atual:
        client = None
        ANTHROPIC_KEY = ""
        return None

    if (
        client is None
        or chave_atual != ANTHROPIC_KEY
    ):
        ANTHROPIC_KEY = chave_atual
        client = anthropic.Anthropic(
            api_key=ANTHROPIC_KEY,
        )

    return client


def extrair_texto_resposta(
    response,
) -> str:
    """
    Extrai todos os blocos textuais retornados pela Anthropic.

    Não depende exclusivamente de bloco.type == "text", evitando o
    caso em que uma resposta válida existe, mas o código antigo cai em
    "Sem resposta disponível.".
    """
    textos = []

    for bloco in (
        getattr(response, "content", None)
        or []
    ):
        texto = None

        if isinstance(bloco, dict):
            texto = bloco.get("text")

        else:
            texto = getattr(
                bloco,
                "text",
                None,
            )

        if (
            isinstance(texto, str)
            and texto.strip()
        ):
            textos.append(
                texto.strip()
            )

    return "\n".join(textos).strip()


def solicitar_texto(
    prompt: str,
    max_tokens: int = 1000,
    tentativas: int = 2,
) -> str | None:
    """
    Faz uma chamada textual ao Claude.

    Se a primeira resposta vier sem texto utilizável, realiza apenas
    mais uma tentativa com uma instrução explícita para retornar texto.
    Isso evita loops e chamadas desnecessárias.
    """
    cliente = obter_cliente()

    if cliente is None:
        return None

    tentativas = max(
        1,
        min(
            int(tentativas),
            2,
        ),
    )

    prompt_base = (
        prompt
        or ""
    ).strip()

    for tentativa in range(
        1,
        tentativas + 1,
    ):
        prompt_atual = prompt_base

        if tentativa > 1:
            prompt_atual += (
                "\n\nIMPORTANTE: responda com conteúdo textual "
                "direto. Não retorne uma resposta vazia."
            )

        response = cliente.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            messages=[
                {
                    "role": "user",
                    "content": prompt_atual,
                }
            ],
        )

        texto = extrair_texto_resposta(
            response
        )

        if texto:
            return texto

        print(
            "[AVISO] Claude retornou resposta sem texto "
            f"(tentativa {tentativa}/{tentativas})."
        )

        print(
            "[DEBUG] stop_reason: "
            f"{getattr(response, 'stop_reason', None)}"
        )

        print(
            "[DEBUG] tipos de blocos: "
            + ", ".join(
                str(
                    getattr(
                        bloco,
                        "type",
                        type(bloco).__name__,
                    )
                )
                for bloco in (
                    getattr(response, "content", None)
                    or []
                )
            )
        )

    return None


# Inicializa o cliente para preservar a variável pública `client`.
obter_cliente()


def generate_fix(
    rule_id: str,
    severity: str,
    file_path: str,
    message: str,
    code_snippet: str,
) -> str | None:
    """
    Gera uma sugestão de correção usando a API da Anthropic.

    A assinatura permanece compatível com scans.py.
    Se a IA estiver indisponível, retorna None sem interromper
    Semgrep, Trivy, Gitleaks, histórico ou validação determinística.
    """
    cliente = obter_cliente()

    if cliente is None:
        print(
            "[AVISO] IA desativada: "
            "REACT_APP_ANTHROPIC_KEY não configurada."
        )
        return None

    prompt = f"""
Você é um especialista em segurança de aplicações trabalhando na
plataforma CodeShield ASPM.

Analise o finding abaixo e proponha uma correção segura, objetiva e
aplicável ao código.

REGRA / CVE:
{rule_id}

SEVERIDADE:
{severity}

ARQUIVO:
{file_path}

PROBLEMA:
{message}

TRECHO DE CÓDIGO:
{code_snippet or "Trecho de código não disponível."}

Responda em português.

Forneça:
1. Explicação curta da vulnerabilidade.
2. Código corrigido ou exemplo seguro, quando aplicável.
3. Explicação curta do motivo pelo qual a correção reduz o risco.

Regras:
- Não invente arquivos, dependências, versões ou contexto.
- Se o trecho não for suficiente para produzir um patch exato,
  forneça um exemplo seguro e deixe isso explícito.
- Não repita segredos eventualmente presentes no conteúdo.
- Retorne conteúdo textual direto.
"""

    try:
        return solicitar_texto(
            prompt=prompt,
            max_tokens=1200,
            tentativas=2,
        )

    except anthropic.AuthenticationError as erro:
        print(
            "[ERRO] Falha de autenticação na Claude API: "
            f"{erro}"
        )
        return None

    except anthropic.RateLimitError as erro:
        print(
            "[ERRO] Limite da Claude API atingido: "
            f"{erro}"
        )
        return None

    except anthropic.APIConnectionError as erro:
        print(
            "[ERRO] Falha de conexão com a Claude API: "
            f"{erro}"
        )
        return None

    except Exception as erro:
        print(
            "[ERRO] Falha ao gerar correção com IA: "
            f"{erro}"
        )
        return None
