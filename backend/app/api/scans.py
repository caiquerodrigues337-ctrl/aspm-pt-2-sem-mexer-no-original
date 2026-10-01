"""
Módulo de rotas da CodeShield ASPM.

Responsável por:
- Clonar repositórios
- Executar Semgrep (SAST)
- Executar Trivy (SCA)
- Normalizar findings
- Calcular score
- Gerar remediação com IA quando disponível
- Salvar findings no banco
- Disponibilizar endpoints para o frontend
"""

from collections import Counter
import os
import shutil
import subprocess
import tempfile

from dotenv import load_dotenv
from fastapi import APIRouter
from pydantic import BaseModel

from app.database import SessionLocal
from app.models import Finding

from app.scanners.semgrep import (
    run_semgrep,
    normalizar_todos_findings,
)

from app.scanners.trivy import (
    run_trivy,
    normalizar_todos_findings_trivy,
)


load_dotenv()

router = APIRouter()


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def normalizar_repo_url(repo_url: str) -> str:
    """
    Normaliza a URL usada para identificar um repositório.

    Estas URLs passam a representar o mesmo repositório:

    https://github.com/user/projeto
    https://github.com/user/projeto/
    https://github.com/user/projeto.git
    """

    url = (repo_url or "").strip().rstrip("/")

    if url.lower().endswith(".git"):
        url = url[:-4]

    return url


def extrair_trecho_codigo(
    repo_path: str,
    file_path: str,
    line: int,
    contexto: int = 3,
) -> str:
    """
    Lê o arquivo vulnerável e extrai algumas linhas ao redor
    do problema.

    É usado principalmente para findings do Semgrep.
    """

    try:
        caminho_completo = os.path.join(
            repo_path,
            file_path,
        )

        with open(
            caminho_completo,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as arquivo:
            linhas = arquivo.readlines()

        linha_idx = max(
            0,
            int(line) - 1,
        )

        inicio = max(
            0,
            linha_idx - contexto,
        )

        fim = min(
            len(linhas),
            linha_idx + contexto + 1,
        )

        return "".join(
            linhas[inicio:fim]
        ).strip()

    except Exception as erro:
        print(
            "[AVISO] Não foi possível extrair "
            f"trecho de código: {erro}"
        )

        return ""


def limpar_caminho_arquivo(
    file_path: str,
    tmp: str,
) -> str:
    """
    Remove o caminho absoluto da pasta temporária
    e mantém apenas o caminho relativo do arquivo.
    """

    try:
        caminho_limpo = (
            file_path or ""
        ).replace(
            tmp,
            "",
        )

        caminho_limpo = caminho_limpo.lstrip(
            "\\/"
        )

        caminho_limpo = caminho_limpo.replace(
            "\\",
            "/",
        )

        return caminho_limpo or file_path

    except Exception:
        return file_path


def ia_disponivel() -> bool:
    """
    Verifica se existe uma chave da Anthropic configurada.

    A ausência da chave não impede os scans.
    """

    return bool(
        os.getenv("ANTHROPIC_API_KEY")
    )


# ============================================================
# SCAN PRINCIPAL
# ============================================================

@router.post("/scan")
def scan_repo(repo_url: str):
    """
    Executa o pipeline principal da CodeShield.

    Git Repository
        ↓
    Semgrep (SAST)
        +
    Trivy (SCA)
        ↓
    Normalização
        ↓
    Pride Score
        ↓
    Remediação IA opcional
        ↓
    PostgreSQL
    """

    repo_url_recebida = (
        repo_url or ""
    ).strip()

    repo_url_normalizada = normalizar_repo_url(
        repo_url_recebida
    )

    if not repo_url_normalizada:

        return {
            "erro": (
                "Informe uma URL "
                "de repositório válida."
            )
        }

    tmp = tempfile.mkdtemp()

    db = None

    try:

        # ========================================================
        # 1. CLONAR REPOSITÓRIO
        # ========================================================

        print("\n========================================")
        print("CODE SHIELD ASPM - NOVO SCAN")
        print("========================================")

        print(
            f"[INFO] Repositório: "
            f"{repo_url_normalizada}"
        )

        clone = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                repo_url_recebida,
                tmp,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if clone.returncode != 0:

            print(
                "[ERRO] Não foi possível "
                "clonar o repositório."
            )

            return {
                "erro": "Não foi possível clonar",
                "detalhe": clone.stderr,
            }

        print(
            "[OK] Repositório clonado "
            "com sucesso."
        )

        # ========================================================
        # 2. SEMGREP - SAST
        # ========================================================

        print("\n----------------------------------------")
        print("SEMGREP - SAST")
        print("----------------------------------------")

        try:

            semgrep_raw = run_semgrep(
                tmp
            )

        except Exception as erro:

            print(
                f"[ERRO] Semgrep falhou: {erro}"
            )

            semgrep_raw = []

        print(
            "[DEBUG] Semgrep retornou "
            f"{len(semgrep_raw)} findings brutos."
        )

        try:

            semgrep_findings = (
                normalizar_todos_findings(
                    semgrep_raw,
                    repo_url_normalizada,
                )
            )

        except Exception as erro:

            print(
                "[ERRO] Falha ao normalizar "
                f"Semgrep: {erro}"
            )

            semgrep_findings = []

        print(
            "[DEBUG] Semgrep normalizado: "
            f"{len(semgrep_findings)} findings."
        )

        # ========================================================
        # 3. TRIVY - SCA
        # ========================================================

        print("\n----------------------------------------")
        print("TRIVY - SCA")
        print("----------------------------------------")

        try:

            trivy_raw = run_trivy(
                tmp
            )

        except Exception as erro:

            print(
                f"[ERRO] Trivy falhou: {erro}"
            )

            trivy_raw = []

        print(
            "[DEBUG] Trivy retornou "
            f"{len(trivy_raw)} findings brutos."
        )

        try:

            trivy_findings = (
                normalizar_todos_findings_trivy(
                    trivy_raw,
                    repo_url_normalizada,
                )
            )

        except Exception as erro:

            print(
                "[ERRO] Falha ao normalizar "
                f"Trivy: {erro}"
            )

            trivy_findings = []

        print(
            "[DEBUG] Trivy normalizado: "
            f"{len(trivy_findings)} findings."
        )

        # ========================================================
        # 4. COMBINAR FINDINGS
        # ========================================================

        findings = (
            semgrep_findings
            +
            trivy_findings
        )

        print("\n========================================")
        print("RESUMO DOS SCANNERS")
        print("========================================")

        print(
            f"Semgrep (SAST): "
            f"{len(semgrep_findings)}"
        )

        print(
            f"Trivy   (SCA):  "
            f"{len(trivy_findings)}"
        )

        print(
            f"Total:          "
            f"{len(findings)}"
        )

        print(
            "========================================"
        )

        # ========================================================
        # 5. ABRIR BANCO
        # ========================================================

        db = SessionLocal()

        # ========================================================
        # 5.1 REMOVER RESULTADOS ANTIGOS DO MESMO REPOSITÓRIO
        # ========================================================

        removidos = (
            db.query(Finding)
            .filter(
                Finding.repo_url
                ==
                repo_url_normalizada
            )
            .delete(
                synchronize_session=False
            )
        )

        print(
            f"[INFO] {removidos} finding(s) antigo(s) "
            f"removido(s) deste repositório."
        )

        # ========================================================
        # 5.2 SE O NOVO SCAN NÃO ACHOU NADA
        # ========================================================

        if not findings:

            db.commit()

            print(
                "[INFO] Nenhum finding encontrado "
                "no novo scan."
            )

            return {
                "repo": repo_url_normalizada,
                "total": 0,
                "semgrep": 0,
                "trivy": 0,
                "ia": (
                    "ativada"
                    if ia_disponivel()
                    else "desativada"
                ),
            }

        salvos = 0

        # ========================================================
        # 6. PROCESSAR FINDINGS
        # ========================================================

        for i, finding in enumerate(
            findings,
            start=1,
        ):

            fonte = finding.get(
                "fonte",
                "desconhecida",
            )

            print(
                f"[DEBUG] Processando finding "
                f"{i}/{len(findings)} "
                f"[{fonte}]"
            )

            # ====================================================
            # SCORE
            # ====================================================

            try:

                from app.ai.scorer import (
                    calculate_pride_score,
                )

                score = calculate_pride_score(
                    finding["tipo"],
                    finding["rule_id"],
                )

            except Exception as erro:

                print(
                    "[AVISO] Scorer falhou "
                    f"no finding {i}: {erro}"
                )

                score = 0.0

            # ====================================================
            # CAMINHO DO ARQUIVO
            # ====================================================

            file_path_limpo = (
                limpar_caminho_arquivo(
                    finding.get(
                        "file_path",
                        "",
                    ),
                    tmp,
                )
            )

            # ====================================================
            # TRECHO DE CÓDIGO
            # ====================================================

            trecho = ""

            if (
                fonte == "semgrep"
                and finding.get(
                    "line",
                    0,
                ) > 0
            ):

                trecho = extrair_trecho_codigo(
                    tmp,
                    finding.get(
                        "file_path",
                        "",
                    ),
                    finding.get(
                        "line",
                        0,
                    ),
                )

            # ====================================================
            # IA DE REMEDIAÇÃO - OPCIONAL
            # ====================================================

            ai_fix = None

            if (
                score >= 4.0
                and ia_disponivel()
            ):

                try:

                    from app.ai.remediation import (
                        generate_fix,
                    )

                    ai_fix = generate_fix(
                        rule_id=finding["rule_id"],
                        severity=finding["tipo"],
                        file_path=file_path_limpo,
                        message=finding["message"],
                        code_snippet=trecho,
                    )

                except Exception as erro:

                    print(
                        "[AVISO] IA indisponível "
                        f"no finding {i}: {erro}"
                    )

                    ai_fix = None

            # ====================================================
            # SALVAR FINDING
            # ====================================================

            try:

                novo_finding = Finding(
                    repo_url=repo_url_normalizada,
                    fonte=fonte,
                    rule_id=finding["rule_id"],
                    severity=finding["tipo"],
                    file_path=file_path_limpo,
                    line=finding.get(
                        "line",
                        0,
                    ),
                    message=finding["message"],
                    pride_score=score,
                    ai_fix=ai_fix,
                    fix_validado=None,
                )

                db.add(
                    novo_finding
                )

                salvos += 1

            except Exception as erro:

                print(
                    "[ERRO] Falha ao criar "
                    f"Finding {i}: {erro}"
                )

        # ========================================================
        # 7. COMMIT
        # ========================================================

        print(
            f"[DEBUG] {salvos} findings adicionados "
            f"à sessão."
        )

        print(
            "[INFO] Realizando commit..."
        )

        try:

            db.commit()

            print(
                "[OK] Commit realizado "
                "com sucesso."
            )

            print(
                f"[OK] {salvos} findings salvos."
            )

        except Exception as erro:

            db.rollback()

            print(
                "[ERRO CRÍTICO] "
                f"Commit falhou: {erro}"
            )

            return {
                "erro": (
                    "Falha ao salvar no banco: "
                    f"{erro}"
                )
            }

        # ========================================================
        # 8. RESULTADO FINAL
        # ========================================================

        print("\n========================================")
        print("SCAN FINALIZADO")
        print("========================================")

        print(
            f"Semgrep: "
            f"{len(semgrep_findings)}"
        )

        print(
            f"Trivy:   "
            f"{len(trivy_findings)}"
        )

        print(
            f"Salvos:  "
            f"{salvos}"
        )

        print(
            "IA:      "
            + (
                "ativada"
                if ia_disponivel()
                else "desativada"
            )
        )

        print(
            "========================================"
        )

        return {
            "repo": repo_url_normalizada,
            "total": salvos,
            "semgrep": len(
                semgrep_findings
            ),
            "trivy": len(
                trivy_findings
            ),
            "ia": (
                "ativada"
                if ia_disponivel()
                else "desativada"
            ),
        }

    # ============================================================
    # ERROS GERAIS
    # ============================================================

    except subprocess.TimeoutExpired:

        return {
            "erro": (
                "Clone demorou mais "
                "de 2 minutos"
            )
        }

    except Exception as erro:

        if db:
            db.rollback()

        print(
            "[ERRO CRÍTICO] "
            f"Falha geral no scan: {erro}"
        )

        return {
            "erro": str(erro)
        }

    # ============================================================
    # FINALIZAÇÃO
    # ============================================================

    finally:

        if db:
            db.close()

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )


# ============================================================
# LISTAR FINDINGS
# ============================================================

@router.get("/findings")
def list_findings(
    severity: str = None,
    repo_url: str = None,
):
    """
    Retorna findings armazenados.

    Filtros opcionais:
    - severity
    - repo_url
    """

    db = SessionLocal()

    try:

        query = db.query(
            Finding
        )

        if severity:

            query = query.filter(
                Finding.severity
                ==
                severity.upper()
            )

        if repo_url:

            query = query.filter(
                Finding.repo_url
                ==
                normalizar_repo_url(
                    repo_url
                )
            )

        resultado = (
            query
            .order_by(
                Finding.pride_score.desc()
            )
            .all()
        )

        return resultado

    finally:

        db.close()


# ============================================================
# RESUMO
# ============================================================

@router.get("/resumo")
def resumo(
    repo_url: str = None,
):
    """
    Retorna um resumo dos findings.

    Se repo_url for informado,
    retorna somente o resumo daquele repositório.
    """

    db = SessionLocal()

    try:

        query = db.query(
            Finding
        )

        if repo_url:

            query = query.filter(
                Finding.repo_url
                ==
                normalizar_repo_url(
                    repo_url
                )
            )

        findings = query.all()

        por_severidade = Counter(
            finding.severity
            for finding in findings
        )

        por_fonte = Counter(
            finding.fonte
            for finding in findings
        )

        criticos = sum(
            1
            for finding in findings
            if (
                finding.pride_score or 0
            ) >= 9
        )

        altos = sum(
            1
            for finding in findings
            if (
                7
                <=
                (finding.pride_score or 0)
                <
                9
            )
        )

        return {
            "total": len(findings),

            "por_severidade": dict(
                por_severidade
            ),

            "por_fonte": dict(
                por_fonte
            ),

            "criticos": criticos,

            "altos": altos,
        }

    finally:

        db.close()


# ============================================================
# LIMPAR FINDINGS
# ============================================================

@router.delete("/findings")
def limpar(
    repo_url: str = None,
):
    """
    Remove findings.

    Sem repo_url:
    remove todos.

    Com repo_url:
    remove apenas os findings daquele repositório.
    """

    db = SessionLocal()

    try:

        query = db.query(
            Finding
        )

        if repo_url:

            query = query.filter(
                Finding.repo_url
                ==
                normalizar_repo_url(
                    repo_url
                )
            )

        quantidade = query.delete(
            synchronize_session=False
        )

        db.commit()

        return {
            "mensagem": "Findings removidos",
            "removidos": quantidade,
        }

    except Exception as erro:

        db.rollback()

        return {
            "erro": (
                "Falha ao remover findings: "
                f"{erro}"
            )
        }

    finally:

        db.close()


# ============================================================
# CHATBOT
# ============================================================

class PerguntaRequest(BaseModel):
    pergunta: str
    findings: list


@router.post("/chat")
def chat_findings(
    request: PerguntaRequest,
):
    """
    Chatbot da CodeShield.

    Enquanto não existir uma API key da Anthropic,
    informa que a IA está desativada.
    """

    if not ia_disponivel():

        return {
            "resposta": (
                "O módulo de IA está temporariamente "
                "desativado. Os scanners, scores e "
                "findings continuam funcionando normalmente."
            )
        }

    try:

        from app.ai.remediation import (
            client,
            MODEL,
        )

    except Exception as erro:

        return {
            "resposta": (
                f"IA indisponível: {erro}"
            )
        }

    if client is None:

        return {
            "resposta": (
                "O módulo de IA está desativado."
            )
        }

    findings_contexto = (
        request.findings[:10]
    )

    contexto = "\n".join(
        (
            f"- "
            f"{finding.get('severity') or finding.get('severidade')} | "
            f"Score: "
            f"{finding.get('pride_score') or finding.get('prideScore')} | "
            f"Arquivo: "
            f"{finding.get('file_path') or finding.get('arquivo')} | "
            f"{finding.get('message') or finding.get('problema')}"
        )
        for finding in findings_contexto
    )

    prompt = f"""
Você é um assistente de segurança da plataforma CodeShield ASPM.

Findings encontrados no repositório:

{contexto}

Pergunta do usuário:

{request.pergunta}

Responda em português, de forma curta, clara e direta.
"""

    try:

        response = client.messages.create(
            model=MODEL,
            max_tokens=300,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        for bloco in response.content:

            if bloco.type == "text":

                return {
                    "resposta": bloco.text
                }

        return {
            "resposta": (
                "Sem resposta disponível."
            )
        }

    except Exception as erro:

        print(
            f"[ERRO] Chat falhou: {erro}"
        )

        return {
            "resposta": (
                "Erro ao consultar a IA: "
                f"{erro}"
            )
        }