"""
Módulo de rotas da CodeShield ASPM.

Responsável por:
- Clonar repositórios com histórico Git completo
- Executar Semgrep (SAST)
- Executar Trivy (SCA)
- Executar Gitleaks (Secrets Scanning)
- Criar e manter histórico de scans
- Normalizar findings no mesmo pipeline
- Calcular Pride Score
- Gerar remediação com IA quando disponível
- Salvar findings no PostgreSQL
- Disponibilizar endpoints para o frontend
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.database import SessionLocal
from app.models import Finding, Scan

from app.scanners.semgrep import (
    run_semgrep,
    normalizar_todos_findings,
)
from app.scanners.trivy import (
    run_trivy,
    normalizar_todos_findings_trivy,
)
from app.scanners.gitleaks import (
    run_gitleaks,
    normalizar_todos_findings_gitleaks,
)
from app.validators.fix_validator import (
    validar_fix_re_scan,
)


BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_PATH = BACKEND_DIR / ".env"

load_dotenv(ENV_PATH)

router = APIRouter()

THRESHOLD_IA = 7.0
AI_ENV_VAR = "REACT_APP_ANTHROPIC_KEY"


def agora_utc():
    return datetime.now(timezone.utc)


def normalizar_repo_url(repo_url: str) -> str:
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
    try:
        caminho_completo = os.path.join(repo_path, file_path)
        with open(
            caminho_completo,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as arquivo:
            linhas = arquivo.readlines()

        linha_idx = max(0, int(line) - 1)
        inicio = max(0, linha_idx - contexto)
        fim = min(len(linhas), linha_idx + contexto + 1)

        return "".join(linhas[inicio:fim]).strip()

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
    try:
        caminho_limpo = (file_path or "").replace(tmp, "")
        caminho_limpo = caminho_limpo.lstrip("\\/")
        caminho_limpo = caminho_limpo.replace("\\", "/")
        return caminho_limpo or file_path

    except Exception:
        return file_path


def ia_disponivel() -> bool:
    chave = (
        os.getenv(AI_ENV_VAR)
        or ""
    ).strip()

    return bool(chave)


def obter_ultimo_scan(
    db,
    repo_url: str,
):
    return (
        db.query(Scan)
        .filter(
            Scan.repo_url == normalizar_repo_url(repo_url),
            Scan.status == "completed",
        )
        .order_by(Scan.started_at.desc())
        .first()
    )


def marcar_scan_falhou(
    db,
    scan_id: str | None,
):
    if not db or not scan_id:
        return

    try:
        db.rollback()

        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan:
            scan.status = "failed"
            scan.finished_at = agora_utc()
            db.commit()

    except Exception as erro:
        db.rollback()
        print(
            "[AVISO] Não foi possível marcar "
            f"o scan como failed: {erro}"
        )


@router.post("/scan")
def scan_repo(repo_url: str):
    """
    Executa Semgrep + Trivy + Gitleaks e salva uma nova execução
    no histórico. Findings antigos NÃO são apagados.

    O clone NÃO usa --depth 1 de propósito:
    o Gitleaks precisa do histórico Git para procurar segredos
    presentes em commits antigos.
    """
    repo_url_recebida = (repo_url or "").strip()
    repo_url_normalizada = normalizar_repo_url(repo_url_recebida)

    if not repo_url_normalizada:
        return {"erro": "Informe uma URL de repositório válida."}

    tmp = tempfile.mkdtemp()
    db = SessionLocal()
    scan_id = None

    try:
        scan = Scan(
            repo_url=repo_url_normalizada,
            status="running",
            total=0,
            semgrep_total=0,
            trivy_total=0,
            started_at=agora_utc(),
            finished_at=None,
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan_id = scan.id

        print("\n========================================")
        print("CODE SHIELD ASPM - NOVO SCAN")
        print("========================================")
        print(f"[INFO] Scan ID: {scan_id}")
        print(f"[INFO] Repositório: {repo_url_normalizada}")

        print("\n----------------------------------------")
        print("GIT CLONE - HISTÓRICO COMPLETO")
        print("----------------------------------------")

        clone = subprocess.run(
            [
                "git",
                "clone",
                repo_url_recebida,
                tmp,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if clone.returncode != 0:
            marcar_scan_falhou(db, scan_id)
            return {
                "erro": "Não foi possível clonar",
                "detalhe": clone.stderr,
                "scan_id": scan_id,
            }

        print(
            "[OK] Repositório clonado "
            "com histórico Git completo."
        )

        print("\n----------------------------------------")
        print("SEMGREP - SAST")
        print("----------------------------------------")

        try:
            semgrep_raw = run_semgrep(tmp)
        except Exception as erro:
            print(f"[ERRO] Semgrep falhou: {erro}")
            semgrep_raw = []

        try:
            semgrep_findings = normalizar_todos_findings(
                semgrep_raw,
                repo_url_normalizada,
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

        print("\n----------------------------------------")
        print("TRIVY - SCA")
        print("----------------------------------------")

        try:
            trivy_raw = run_trivy(tmp)
        except Exception as erro:
            print(f"[ERRO] Trivy falhou: {erro}")
            trivy_raw = []

        try:
            trivy_findings = normalizar_todos_findings_trivy(
                trivy_raw,
                repo_url_normalizada,
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

        print("\n----------------------------------------")
        print("GITLEAKS - SECRETS")
        print("----------------------------------------")

        try:
            gitleaks_raw = run_gitleaks(tmp)
        except Exception as erro:
            print(f"[ERRO] Gitleaks falhou: {erro}")
            gitleaks_raw = []

        try:
            gitleaks_findings = normalizar_todos_findings_gitleaks(
                gitleaks_raw,
                repo_url_normalizada,
            )
        except Exception as erro:
            print(
                "[ERRO] Falha ao normalizar "
                f"Gitleaks: {erro}"
            )
            gitleaks_findings = []

        print(
            "[DEBUG] Gitleaks normalizado: "
            f"{len(gitleaks_findings)} findings."
        )

        findings = (
            semgrep_findings
            + trivy_findings
            + gitleaks_findings
        )

        print("\n========================================")
        print("RESUMO DOS SCANNERS")
        print("========================================")
        print(f"Semgrep  (SAST):    {len(semgrep_findings)}")
        print(f"Trivy    (SCA):     {len(trivy_findings)}")
        print(f"Gitleaks (SECRETS): {len(gitleaks_findings)}")
        print(f"Total:              {len(findings)}")
        print("========================================")

        salvos = 0

        for i, finding in enumerate(findings, start=1):
            fonte = finding.get("fonte", "desconhecida")

            print(
                f"[DEBUG] Finding "
                f"{i}/{len(findings)} [{fonte}]"
            )

            try:
                from app.ai.scorer import calculate_pride_score

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

            file_path_limpo = limpar_caminho_arquivo(
                finding.get("file_path", ""),
                tmp,
            )

            trecho = ""

            if (
                fonte == "semgrep"
                and finding.get("line", 0) > 0
            ):
                trecho = extrair_trecho_codigo(
                    tmp,
                    finding.get("file_path", ""),
                    finding.get("line", 0),
                )

            ai_fix = None
            fix_validado = None

            if (
                score >= THRESHOLD_IA
                and ia_disponivel()
            ):
                try:
                    from app.ai.remediation import generate_fix

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

            # ----------------------------------------------------
            # VALIDAÇÃO DETERMINÍSTICA DO FIX - NÍVEL 1
            # ----------------------------------------------------
            # O re-scan é aplicável somente a findings do Semgrep.
            # Trivy e Gitleaks precisam de validadores próprios.
            if (
                fonte == "semgrep"
                and ai_fix
            ):
                try:
                    resultado_validacao = validar_fix_re_scan(
                        ai_fix=ai_fix,
                        rule_id=finding["rule_id"],
                        file_path=file_path_limpo,
                    )

                    fix_validado = (
                        resultado_validacao.get(
                            "validado"
                        )
                    )

                    print(
                        "[VALIDAÇÃO FIX] "
                        f"{resultado_validacao.get('motivo')}"
                    )

                except Exception as erro:
                    print(
                        "[AVISO] Falha ao validar fix "
                        f"do finding {i}: {erro}"
                    )
                    fix_validado = None

            try:
                novo_finding = Finding(
                    scan_id=scan_id,
                    repo_url=repo_url_normalizada,
                    fonte=fonte,
                    rule_id=finding["rule_id"],
                    severity=finding["tipo"],
                    file_path=file_path_limpo,
                    line=finding.get("line", 0),
                    message=finding["message"],
                    pride_score=score,
                    ai_fix=ai_fix,
                    fix_validado=fix_validado,
                )

                db.add(novo_finding)
                salvos += 1

            except Exception as erro:
                print(
                    "[ERRO] Falha ao criar "
                    f"Finding {i}: {erro}"
                )

        scan.total = salvos
        scan.semgrep_total = len(semgrep_findings)
        scan.trivy_total = len(trivy_findings)
        scan.status = "completed"
        scan.finished_at = agora_utc()

        db.commit()

        print("\n========================================")
        print("SCAN FINALIZADO")
        print("========================================")
        print(f"Scan ID:  {scan_id}")
        print(f"Semgrep:  {len(semgrep_findings)}")
        print(f"Trivy:    {len(trivy_findings)}")
        print(f"Gitleaks: {len(gitleaks_findings)}")
        print(f"Salvos:   {salvos}")
        print(
            "IA:       "
            + (
                "ativada"
                if ia_disponivel()
                else "desativada"
            )
        )
        print("========================================")

        return {
            "scan_id": scan_id,
            "repo": repo_url_normalizada,
            "total": salvos,
            "semgrep": len(semgrep_findings),
            "trivy": len(trivy_findings),
            "gitleaks": len(gitleaks_findings),
            "ia": (
                "ativada"
                if ia_disponivel()
                else "desativada"
            ),
        }

    except subprocess.TimeoutExpired:
        marcar_scan_falhou(db, scan_id)

        return {
            "erro": "Clone demorou mais de 5 minutos",
            "scan_id": scan_id,
        }

    except Exception as erro:
        marcar_scan_falhou(db, scan_id)

        print(
            "[ERRO CRÍTICO] "
            f"Falha geral no scan: {erro}"
        )

        return {
            "erro": str(erro),
            "scan_id": scan_id,
        }

    finally:
        db.close()
        shutil.rmtree(tmp, ignore_errors=True)


@router.get("/findings")
def list_findings(
    severity: str = None,
    repo_url: str = None,
    scan_id: str = None,
):
    db = SessionLocal()

    try:
        query = db.query(Finding)

        if severity:
            query = query.filter(
                Finding.severity == severity.upper()
            )

        if scan_id:
            query = query.filter(
                Finding.scan_id == scan_id
            )

        elif repo_url:
            ultimo_scan = obter_ultimo_scan(
                db,
                repo_url,
            )

            if not ultimo_scan:
                return []

            query = query.filter(
                Finding.scan_id == ultimo_scan.id
            )

        return (
            query
            .order_by(Finding.pride_score.desc())
            .all()
        )

    finally:
        db.close()


@router.get("/resumo")
def resumo(
    repo_url: str = None,
    scan_id: str = None,
):
    db = SessionLocal()

    try:
        query = db.query(Finding)
        scan_usado = None

        if scan_id:
            scan_usado = (
                db.query(Scan)
                .filter(Scan.id == scan_id)
                .first()
            )

            query = query.filter(
                Finding.scan_id == scan_id
            )

        elif repo_url:
            scan_usado = obter_ultimo_scan(
                db,
                repo_url,
            )

            if not scan_usado:
                return {
                    "scan_id": None,
                    "total": 0,
                    "por_severidade": {},
                    "por_fonte": {},
                    "criticos": 0,
                    "altos": 0,
                }

            query = query.filter(
                Finding.scan_id == scan_usado.id
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
            if (finding.pride_score or 0) >= 9
        )

        altos = sum(
            1
            for finding in findings
            if 7 <= (finding.pride_score or 0) < 9
        )

        return {
            "scan_id": (
                scan_usado.id
                if scan_usado
                else None
            ),
            "total": len(findings),
            "por_severidade": dict(por_severidade),
            "por_fonte": dict(por_fonte),
            "criticos": criticos,
            "altos": altos,
        }

    finally:
        db.close()


@router.get("/scans")
def listar_scans(
    repo_url: str = None,
    limit: int = 20,
):
    db = SessionLocal()

    try:
        limit = max(
            1,
            min(limit, 100),
        )

        query = db.query(Scan)

        if repo_url:
            query = query.filter(
                Scan.repo_url
                ==
                normalizar_repo_url(repo_url)
            )

        return (
            query
            .order_by(Scan.started_at.desc())
            .limit(limit)
            .all()
        )

    finally:
        db.close()


@router.get("/scans/{scan_id}")
def obter_scan(
    scan_id: str,
):
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan não encontrado.",
            )

        return scan

    finally:
        db.close()


@router.get("/scans/{scan_id}/findings")
def findings_do_scan(
    scan_id: str,
    severity: str = None,
):
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if not scan:
            raise HTTPException(
                status_code=404,
                detail="Scan não encontrado.",
            )

        query = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
        )

        if severity:
            query = query.filter(
                Finding.severity == severity.upper()
            )

        return (
            query
            .order_by(Finding.pride_score.desc())
            .all()
        )

    finally:
        db.close()


@router.delete("/findings")
def limpar_findings(
    repo_url: str = None,
    scan_id: str = None,
):
    db = SessionLocal()

    try:
        query = db.query(Finding)

        if scan_id:
            query = query.filter(
                Finding.scan_id == scan_id
            )

        elif repo_url:
            query = query.filter(
                Finding.repo_url
                ==
                normalizar_repo_url(repo_url)
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
# VALIDAÇÃO AST - NÍVEL 2
# ============================================================

class ValidacaoASTRequest(BaseModel):
    codigo_original: str
    codigo_corrigido: str


@router.post("/validar-ast")
def validar_ast(
    request: ValidacaoASTRequest,
):
    """
    Valida estruturalmente uma alteração de código Python.

    Esta rota:
    - NÃO executa o código recebido;
    - usa somente ast.parse() por meio do ast_validator;
    - compara a estrutura do original com o corrigido;
    - retorna similaridade e indicação de mudança cirúrgica.

    É independente da API da Claude.
    """

    try:
        from app.validators.ast_validator import (
            validar_diff_ast,
        )

        resultado = validar_diff_ast(
            request.codigo_original,
            request.codigo_corrigido,
        )

        return resultado

    except Exception as erro:
        print(
            "[ERRO] Falha na validação AST: "
            f"{erro}"
        )

        return {
            "valido": False,
            "mudanca_cirurgica": False,
            "similaridade": 0.0,
            "motivo": (
                "Falha interna durante "
                f"a validação AST: {erro}"
            ),
        }


# ============================================================
# CHATBOT
# ============================================================

class PerguntaRequest(BaseModel):
    pergunta: str
    findings: list[dict] = Field(default_factory=list)


def montar_contexto_chat(
    findings: list[dict],
    limite: int = 10,
) -> str:
    """
    Monta um contexto pequeno e previsível para o Claude.

    O frontend já prioriza os findings por Pride Score, mas o
    backend também limita a quantidade recebida para evitar
    prompts excessivamente grandes.
    """
    findings_contexto = findings[:limite]

    if not findings_contexto:
        return (
            "Nenhum finding foi enviado no contexto. "
            "Responda somente à pergunta do usuário e deixe claro "
            "quando não houver dados suficientes do scan."
        )

    linhas = []

    for finding in findings_contexto:
        severity = (
            finding.get("severity")
            or finding.get("severidade")
            or "UNKNOWN"
        )

        score = (
            finding.get("pride_score")
            if finding.get("pride_score") is not None
            else finding.get("prideScore")
        )

        fonte = (
            finding.get("fonte")
            or "desconhecida"
        )

        rule_id = (
            finding.get("rule_id")
            or finding.get("ruleId")
            or "N/A"
        )

        arquivo = (
            finding.get("file_path")
            or finding.get("arquivo")
            or "N/A"
        )

        mensagem = (
            finding.get("message")
            or finding.get("problema")
            or "Sem descrição."
        )

        ai_fix = (
            finding.get("ai_fix")
            or finding.get("fixIa")
            or ""
        )

        linha = (
            f"- Severidade: {severity} | "
            f"Score: {score if score is not None else 'N/A'} | "
            f"Fonte: {fonte} | "
            f"Regra/CVE: {rule_id} | "
            f"Arquivo: {arquivo} | "
            f"Problema: {mensagem}"
        )

        if ai_fix:
            linha += (
                " | Correção IA já registrada: "
                f"{ai_fix[:500]}"
            )

        linhas.append(linha)

    return "\n".join(linhas)


@router.post("/chat")
def chat_findings(
    request: PerguntaRequest,
):
    pergunta = (
        request.pergunta
        or ""
    ).strip()

    if not pergunta:
        return {
            "resposta": (
                "Digite uma pergunta para o assistente."
            )
        }

    if not ia_disponivel():
        return {
            "resposta": (
                "O módulo de IA está desativado no backend. "
                "Configure REACT_APP_ANTHROPIC_KEY no arquivo "
                "backend/.env."
            )
        }

    try:
        from app.ai.remediation import (
            obter_cliente,
            solicitar_texto,
            MODEL,
        )

        cliente = obter_cliente()

    except Exception as erro:
        print(
            "[ERRO] Falha ao carregar módulo de IA: "
            f"{erro}"
        )

        return {
            "resposta": (
                "A IA está configurada, mas o backend não conseguiu "
                "inicializar o cliente da Anthropic."
            )
        }

    if cliente is None:
        return {
            "resposta": (
                "A chave da Anthropic não está disponível para o "
                "backend."
            )
        }

    contexto = montar_contexto_chat(
        request.findings,
        limite=10,
    )

    prompt = f"""
Você é o assistente de segurança da plataforma CodeShield ASPM.

Sua tarefa é responder perguntas sobre findings de segurança de
aplicações de forma técnica, objetiva e útil.

CONTEXTO DO SCAN:
{contexto}

PERGUNTA DO USUÁRIO:
{pergunta}

REGRAS DA RESPOSTA:
- Responda em português.
- Use somente os dados disponíveis no contexto quando a pergunta
  depender do scan.
- Não invente CVEs, versões, arquivos, scores ou resultados.
- Quando faltar informação, diga explicitamente que o contexto não
  contém os dados necessários.
- Para perguntas sobre correção, explique a ação recomendada de forma
  prática.
- Se houver vários findings, priorize os de maior severidade e score.
- Retorne texto normal, sem depender de ferramentas externas.
"""

    try:
        resposta = solicitar_texto(
            prompt=prompt,
            max_tokens=1200,
            tentativas=2,
        )

        if resposta:
            return {
                "resposta": resposta
            }

        print(
            "[AVISO] Claude não retornou conteúdo textual "
            f"para o modelo {MODEL}."
        )

        return {
            "resposta": (
                "A IA respondeu à requisição, mas não retornou "
                "conteúdo textual. Tente enviar a pergunta novamente."
            )
        }

    except Exception as erro:
        print(
            f"[ERRO] Chat falhou: {erro}"
        )

        return {
            "resposta": (
                "Não foi possível consultar a IA neste momento. "
                "Verifique a configuração da chave/modelo no backend "
                "e tente novamente."
            )
        }
