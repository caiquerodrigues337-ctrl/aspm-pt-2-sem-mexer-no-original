# CodeShield ASPM

Plataforma acadêmica de **Application Security Posture Management (ASPM)** desenvolvida para o FIAP Challenge em parceria com a Pride Security.

O CodeShield centraliza diferentes técnicas de análise de segurança em uma única esteira, normaliza os resultados, calcula um **Pride Score**, persiste os findings e apresenta tudo em um dashboard React.

## Funcionalidades

- **SAST — Semgrep**
  - análise estática do código;
  - execução com múltiplas configurações;
  - normalização e remoção de duplicados.

- **SCA — Trivy**
  - análise de dependências;
  - identificação de CVEs;
  - versão instalada e versão corrigida quando disponíveis.

- **Secrets Scanning — Gitleaks**
  - análise do histórico Git completo;
  - identificação de possíveis segredos expostos.

- **DAST — OWASP ZAP**
  - ZAP Baseline executado em Docker;
  - análise passiva de uma aplicação em execução;
  - target independente da URL do repositório;
  - localhost convertido para `host.docker.internal` dentro do container.

- **Pride Score**
  - priorização dos findings;
  - unificação dos resultados dos diferentes scanners em uma mesma interface.

- **IA com Anthropic Claude**
  - geração de recomendações de correção;
  - chatbot contextual baseado nos findings;
  - ativação somente quando a chave está disponível.
  - requer créditos válidos na API da Anthropic.

- **Validação determinística de fix — PoC**
  - aplicada aos findings do Semgrep;
  - confirma a vulnerabilidade no arquivo original;
  - aplica a sugestão da IA somente em uma cópia temporária;
  - valida a estrutura Python com AST;
  - executa novamente o Semgrep;
  - aprova somente quando a mesma `rule_id` desaparece;
  - **o código sugerido pela IA não é executado**.

- **Histórico de scans**
  - cada execução recebe um `scan_id`;
  - findings anteriores não são apagados automaticamente;
  - resultados são armazenados no PostgreSQL.

## Arquitetura

```text
Repositório Git
   │
   ├── Semgrep ─── SAST
   ├── Trivy ───── SCA
   └── Gitleaks ── Secrets
                    │
Aplicação em execução
   │
   └── OWASP ZAP ─ DAST
                    │
                    ▼
              Normalização
                    │
                    ▼
               Pride Score
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   Anthropic Claude      PostgreSQL
          │                   │
          └─────────┬─────────┘
                    ▼
             FastAPI Backend
                    │
                    ▼
             React Frontend
```

## Estrutura principal

```text
CodeShield-ASPM/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── remediation.py
│   │   │   └── scorer.py
│   │   ├── api/
│   │   │   └── scans.py
│   │   ├── scanners/
│   │   │   ├── semgrep.py
│   │   │   ├── trivy.py
│   │   │   ├── gitleaks.py
│   │   │   └── zap.py
│   │   ├── validators/
│   │   │   ├── ast_validator.py
│   │   │   └── fix_validator.py
│   │   ├── database.py
│   │   ├── models.py
│   │   └── main.py
│   ├── test_poc_fix.py
│   └── test_zap.py
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── api/
│           └── pride.ts
├── security_samples/
│   └── vulnerable_sample.py
└── docker-compose.yml
```

## Pré-requisitos

- Python 3
- Node.js + npm
- Git
- Docker Desktop
- PostgreSQL
- Semgrep
- Trivy
- Gitleaks
- acesso ao Docker Hub/GHCR para a imagem do OWASP ZAP

## Variáveis de ambiente

O backend utiliza o arquivo:

```text
backend/.env
```

Para a integração com Anthropic, o projeto utiliza:

```env
REACT_APP_ANTHROPIC_KEY=SUA_CHAVE
```

> Nunca envie `backend/.env` ou chaves de API para o Git.

## Executando o projeto

### 1. Infraestrutura

Na raiz:

```powershell
cd C:\Users\caiqu\CodeShield-ASPM
docker compose up -d
docker compose ps
```

### 2. Backend

```powershell
cd C:\Users\caiqu\CodeShield-ASPM\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

### 3. Frontend

Em outro terminal:

```powershell
cd C:\Users\caiqu\CodeShield-ASPM\frontend
npm start
```

Frontend:

```text
http://localhost:3000
```

## Executando um scan

Na interface, informe:

```text
Repositório Git:
https://github.com/usuario/repositorio

Target DAST:
http://localhost:3000
```

O target DAST é opcional. Se estiver vazio, o ZAP não é executado.

Fluxo:

```text
repo_url
 ├─ Semgrep
 ├─ Trivy
 └─ Gitleaks

target_url
 └─ OWASP ZAP
```

## OWASP ZAP

O CodeShield utiliza a imagem:

```text
ghcr.io/zaproxy/zaproxy:stable
```

O scan inicial usa **ZAP Baseline**, com crawling e análise passiva, sem executar um Active Scan agressivo.

Para aplicações locais, o backend converte:

```text
http://localhost:3000
```

para:

```text
http://host.docker.internal:3000
```

dentro do container Docker.

## Validação determinística de correção

O processo de validação de um finding Semgrep é:

```text
Vulnerabilidade original
        │
        ▼
Baseline Semgrep
        │
        ▼
rule_id confirmada
        │
        ▼
Sugestão de fix pela IA
        │
        ▼
Cópia temporária do arquivo
        │
        ▼
Validação AST
        │
        ▼
Re-scan Semgrep
        │
        ├── rule_id desapareceu → FIX VALIDADO
        │
        └── rule_id permaneceu  → FIX REPROVADO
```

A validação não executa o código gerado pela IA.

## Resultado do teste final

Em uma execução de validação final do projeto:

| Scanner | Tipo | Findings |
|---|---|---:|
| Semgrep | SAST | 20 |
| Trivy | SCA | 66 |
| Gitleaks | Secrets | 1 |
| OWASP ZAP | DAST | 14 |
| **Total** |  | **101** |

O resultado confirma a execução ponta a ponta da esteira e a persistência dos findings no CodeShield.

> Os números podem variar conforme o repositório, dependências, versões dos scanners e aplicação analisada.

## Segurança operacional

- Não execute código gerado pela IA.
- Não faça DAST em sistemas sem autorização.
- Não versione `.env`.
- Não versione chaves, tokens ou credenciais.
- O ZAP deve receber apenas aplicações que você tem autorização para testar.
- Findings do Gitleaks devem ser tratados como possíveis exposições até validação manual.

## Estado atual

```text
SAST / Semgrep        ✅
SCA / Trivy           ✅
Secrets / Gitleaks    ✅
DAST / OWASP ZAP      ✅
Pride Score           ✅
PostgreSQL            ✅
Histórico de scans    ✅
PoC determinística    ✅
Frontend              ✅
Claude                ✅ integração implementada
```

A disponibilidade da Claude depende de uma chave válida e de créditos na conta Anthropic.

## Objetivo acadêmico

A evolução implementada expande a plataforma de uma análise predominantemente SAST para uma esteira ASPM com múltiplas fontes de evidência e adiciona uma PoC de validação determinística de correções sugeridas por IA.

Isso permite demonstrar dois pontos principais da entrega:

1. **Ampliação da cobertura de segurança:** SAST + SCA + Secrets + DAST.
2. **Validação de fix:** a sugestão da IA não é aceita apenas por confiança no modelo; ela é submetida a verificações estáticas e re-scan determinístico.
