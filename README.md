# CodeShield ASPM



INTEGRANTES DA CODESHIELD: MAICK ROSARIO YAMASSAKI RM569664 / Caíque dos Santos Rodrigues RM570577 / Davi Almeida Nascimento RM569447 / Amanda Souza Bezerra	RM573911


O **CodeShield ASPM** é um projeto acadêmico desenvolvido para o FIAP Challenge em parceria com a Pride Security. A proposta do projeto é reunir diferentes tipos de análise de segurança em uma única plataforma, facilitando a identificação, priorização e acompanhamento de vulnerabilidades em aplicações.

Nesta etapa do projeto, a plataforma foi ampliada para trabalhar com **SAST, SCA, Secrets Scanning e DAST**, além de uma prova de conceito para validar de forma determinística algumas correções sugeridas por inteligência artificial.

## Objetivo do projeto

O objetivo principal do CodeShield é centralizar informações de segurança encontradas por diferentes ferramentas e apresentar esses resultados de forma organizada no dashboard.

A plataforma recebe uma URL de repositório Git e, quando desejado, também uma URL de uma aplicação em execução. A partir disso, diferentes scanners são executados e seus resultados são transformados em um formato único.

Atualmente o projeto utiliza:

- **Semgrep** para SAST;
- **Trivy** para SCA;
- **Gitleaks** para Secrets Scanning;
- **OWASP ZAP** para DAST;
- **Pride Score** para priorização dos findings;
- **Anthropic Claude** para sugestões de correção e chatbot;
- **PostgreSQL** para persistência dos scans e findings.

## Tecnologias utilizadas

O projeto foi desenvolvido com as seguintes tecnologias:

```text
Backend: Python + FastAPI
Frontend: React + TypeScript
Banco de dados: PostgreSQL
Containerização: Docker
SAST: Semgrep
SCA: Trivy
Secrets Scanning: Gitleaks
DAST: OWASP ZAP
IA: Anthropic Claude
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

## Funcionamento da esteira

O CodeShield trabalha com dois tipos de entrada.

A primeira é a URL do repositório:

```text
repo_url
```

Essa URL é utilizada por:

```text
Semgrep
Trivy
Gitleaks
```

A segunda entrada é opcional:

```text
target_url
```

Ela representa a aplicação que será analisada pelo OWASP ZAP.

O fluxo pode ser representado da seguinte forma:

```text
Repositório Git
   │
   ├── Semgrep  → SAST
   ├── Trivy    → SCA
   └── Gitleaks → Secrets
                    │
Aplicação em execução
   │
   └── OWASP ZAP → DAST
                    │
                    ▼
              Normalização
                    │
                    ▼
               Pride Score
                    │
                    ▼
              PostgreSQL
                    │
                    ▼
              Frontend React
```

Quando a IA está disponível, alguns findings também podem receber uma sugestão de correção gerada pelo Claude.

## Semgrep — SAST

O Semgrep é utilizado para análise estática do código-fonte.

O scanner executa mais de uma configuração e depois remove resultados duplicados antes de enviar os findings para o restante da plataforma.

Os resultados são normalizados com informações como:

```text
fonte
rule_id
severidade
arquivo
linha
mensagem
```

## Trivy — SCA

O Trivy foi adicionado para identificar vulnerabilidades conhecidas em dependências do projeto.

Quando disponível no resultado, o finding também apresenta informações como:

```text
CVE
pacote
versão instalada
versão corrigida
```

## Gitleaks — Secrets Scanning

O Gitleaks procura possíveis segredos expostos no repositório.

Para permitir esse tipo de análise, o CodeShield faz o clone do repositório mantendo o histórico Git completo, pois um segredo pode ter sido removido do código atual, mas ainda continuar presente em commits anteriores.

## OWASP ZAP — DAST

O OWASP ZAP foi integrado usando Docker.

Nesta versão foi utilizado o **ZAP Baseline**, que realiza crawling e análise passiva da aplicação, sem executar o Active Scan.

Exemplo de target:

```text
http://localhost:3000
```

Como o ZAP está sendo executado dentro de um container, o backend converte o localhost para:

```text
http://host.docker.internal:3000
```

Isso permite que o container acesse a aplicação que está rodando no Windows.

O campo de DAST é opcional. Caso nenhuma URL seja informada, o scan continua normalmente com Semgrep, Trivy e Gitleaks.

## Pride Score

Depois da normalização, os findings passam pelo cálculo do Pride Score.

O objetivo é ajudar na priorização das vulnerabilidades, permitindo que os problemas mais importantes apareçam primeiro no dashboard.

## Integração com IA

O CodeShield possui integração com a API da Anthropic.

A variável utilizada pelo backend é:

```env
REACT_APP_ANTHROPIC_KEY=SUA_CHAVE
```

A IA é utilizada para:

- sugerir correções;
- auxiliar na interpretação dos findings;
- responder perguntas no chatbot da plataforma.

A chave deve ficar apenas no arquivo:

```text
backend/.env
```

Esse arquivo não deve ser enviado ao GitHub.

## Validação determinística de fix

Uma das principais implementações desta etapa foi a criação de uma PoC para validar correções sugeridas pela IA em findings do Semgrep.

O processo funciona da seguinte forma:

```text
1. O Semgrep confirma a vulnerabilidade no arquivo original.
2. A IA gera uma sugestão de correção.
3. A correção é aplicada somente em uma cópia temporária.
4. O código Python corrigido passa por validação com AST.
5. O Semgrep é executado novamente.
6. O sistema verifica se a mesma rule_id continua existindo.
```

O resultado pode ser:

```text
FIX VALIDADO
FIX REPROVADO
VALIDAÇÃO INCONCLUSIVA
```

Um ponto importante é que o CodeShield **não executa o código gerado pela IA** durante essa validação.

A validação utiliza análise estática, AST e re-scan com o Semgrep.

## Histórico de scans

Cada execução recebe um identificador próprio:

```text
scan_id
```

Os findings são associados ao scan correspondente e salvos no PostgreSQL.

Dessa forma, o sistema consegue manter o histórico das análises sem precisar apagar automaticamente os findings anteriores.

## Como executar

### Docker

Na raiz do projeto:

```powershell
cd C:\Users\caiqu\CodeShield-ASPM
docker compose up -d
docker compose ps
```

### Backend

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

### Frontend

Em outro terminal:

```powershell
cd C:\Users\caiqu\CodeShield-ASPM\frontend
npm start
```

Frontend:

```text
http://localhost:3000
```

## Exemplo de scan

No dashboard podem ser informados:

```text
Repositório:
https://github.com/usuario/repositorio

Target DAST:
http://localhost:3000
```

O scan executa os scanners correspondentes e, ao final, exibe os resultados no dashboard.

## Resultado do teste final

Durante o teste final realizado no projeto, o resultado foi:

| Scanner | Tipo | Findings |
|---|---|---:|
| Semgrep | SAST | 20 |
| Trivy | SCA | 66 |
| Gitleaks | Secrets | 1 |
| OWASP ZAP | DAST | 14 |
| **Total** |  | **101** |

Esse resultado confirmou que os quatro scanners estavam funcionando dentro da mesma execução e que os findings estavam sendo salvos e exibidos pela plataforma.

Os valores podem mudar dependendo do repositório, das dependências, da aplicação analisada e das versões das ferramentas.

## Cuidados importantes

- não enviar o arquivo `.env` para o GitHub;
- não armazenar chaves de API diretamente no código;
- executar DAST somente em aplicações autorizadas;
- não executar automaticamente código produzido pela IA;
- analisar manualmente possíveis secrets encontrados pelo Gitleaks.

## Estado atual do projeto

```text
Semgrep / SAST        funcionando
Trivy / SCA           funcionando
Gitleaks / Secrets    funcionando
OWASP ZAP / DAST      funcionando
Pride Score           funcionando
PostgreSQL            funcionando
Histórico de scans    funcionando
Validação de fix      funcionando
Frontend              funcionando
Claude                integração implementada
```

A utilização do Claude depende de uma chave válida e de créditos disponíveis na conta Anthropic.

## Conclusão

Com as alterações realizadas nesta etapa, o CodeShield passou a ter uma cobertura de segurança maior do que a versão inicial.

Além da análise estática com Semgrep, agora o projeto também analisa dependências, possíveis segredos e uma aplicação em execução.

A PoC de validação de fix também adiciona uma camada de verificação sobre as respostas geradas pela IA, evitando considerar uma correção como válida apenas porque ela foi sugerida pelo modelo.
