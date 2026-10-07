# Tutorial de Instalação — CodeShield ASPM

## 1. Objetivo

Este documento explica como subir o **CodeShield ASPM** em outro computador, partindo de uma máquina nova.

Ao final do processo, o ambiente deverá estar com:

- Backend FastAPI funcionando;
- Frontend React funcionando;
- PostgreSQL disponível via Docker;
- Semgrep disponível para SAST;
- Trivy disponível para SCA;
- Gitleaks disponível para Secrets Scanning;
- OWASP ZAP disponível via Docker para DAST;
- Integração com Anthropic Claude configurada, quando houver chave e créditos disponíveis.

---

# 2. Requisitos da máquina

Este tutorial considera **Windows 10 ou Windows 11**.

Antes de começar, instale:

- Git
- Python 3
- Node.js
- npm
- Docker Desktop
- Trivy
- Gitleaks
- Visual Studio Code

Também é necessário acesso à internet para:

- clonar o repositório;
- instalar dependências;
- baixar imagens Docker;
- utilizar a API da Anthropic;
- atualizar bases dos scanners.

---

# 3. Verificar as ferramentas instaladas

Abra o **PowerShell** e execute:

```powershell
git --version
python --version
node --version
npm --version
docker --version
```

Se todos os comandos retornarem uma versão, pode continuar.

Exemplo:

```text
git version ...
Python ...
v...
...
Docker version ...
```

---

# 4. Clonar o projeto

Escolha uma pasta para armazenar o projeto.

Exemplo:

```powershell
cd C:\Users\SEU_USUARIO
```

Clone o repositório:

```powershell
git clone https://github.com/caiquerodrigues337-ctrl/aspm-pt-2-sem-mexer-no-original.git CodeShield-ASPM
```

Entre na pasta:

```powershell
cd CodeShield-ASPM
```

Para abrir no VS Code:

```powershell
code .
```

Caso o comando `code` não funcione, abra o VS Code manualmente e escolha:

```text
File
→ Open Folder
→ CodeShield-ASPM
```

---

# 5. Conferir a estrutura principal

A estrutura deve ser parecida com:

```text
CodeShield-ASPM/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   ├── api/
│   │   ├── scanners/
│   │   ├── validators/
│   │   ├── database.py
│   │   ├── models.py
│   │   └── main.py
│   ├── requirements.txt
│   ├── migrate_scan_history.py
│   ├── test_poc_fix.py
│   └── test_zap.py
│
├── frontend/
│   └── src/
│
├── security_samples/
│   └── vulnerable_sample.py
│
├── docs/
├── README.md
└── docker-compose.yml
```

---

# 6. Preparar o backend

Abra um terminal na pasta do backend:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\backend
```

Crie o ambiente virtual:

```powershell
python -m venv .venv
```

Ative o ambiente virtual:

```powershell
.\.venv\Scripts\Activate.ps1
```

Se o PowerShell bloquear a execução de scripts, utilize:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Depois tente novamente:

```powershell
.\.venv\Scripts\Activate.ps1
```

Quando funcionar, o terminal deverá mostrar algo parecido com:

```text
(.venv) PS C:\Users\SEU_USUARIO\CodeShield-ASPM\backend>
```

---

# 7. Instalar as dependências Python

Com a `.venv` ativada:

```powershell
python -m pip install --upgrade pip
```

Depois:

```powershell
pip install -r requirements.txt
```

Verifique se o Semgrep está disponível:

```powershell
semgrep --version
```

Se não estiver:

```powershell
pip install semgrep
```

---

# 8. Configurar a integração com IA

Dentro da pasta:

```text
backend/
```

crie o arquivo:

```text
.env
```

Adicione:

```env
REACT_APP_ANTHROPIC_KEY=SUA_CHAVE_DA_ANTHROPIC
```

Exemplo de localização:

```text
CodeShield-ASPM/
└── backend/
    └── .env
```

## Importante

Nunca envie a chave para o GitHub.

O arquivo `.env` deve permanecer ignorado pelo Git.

Não coloque a chave diretamente no código-fonte.

Para gerar novas correções e utilizar o Claude Chat, a conta Anthropic também precisa possuir créditos disponíveis.

---

# 9. Instalar o Trivy

O CodeShield utiliza o Trivy para SCA.

Depois da instalação, valide com:

```powershell
trivy --version
```

Se o comando não for encontrado, confira se o executável foi adicionado ao `PATH` do Windows.

No ambiente utilizado durante o desenvolvimento, o Trivy também podia ser localizado em:

```text
C:\Tools\Trivy\trivy.exe
```

O importante é que o scanner consiga localizar o executável corretamente.

---

# 10. Instalar o Gitleaks

O Gitleaks é utilizado para Secrets Scanning.

Depois da instalação:

```powershell
gitleaks version
```

Se o comando não funcionar, adicione a pasta que contém `gitleaks.exe` ao `PATH` do Windows.

O Gitleaks precisa estar disponível para o backend executar o scanner.

---

# 11. Instalar e iniciar o Docker Desktop

Abra o **Docker Desktop**.

Espere até o Docker Engine estar funcionando.

Teste:

```powershell
docker version
```

Depois vá para a raiz do projeto:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM
```

Suba a infraestrutura:

```powershell
docker compose up -d
```

Confira:

```powershell
docker compose ps
```

O projeto possui infraestrutura Docker preparada para serviços como:

```text
PostgreSQL
Redis
Neo4j
```

Atualmente, o PostgreSQL é o serviço principal utilizado para persistência dos scans e findings.

---

# 12. Preparar o banco de dados

Com os containers funcionando, inicie o backend normalmente.

Se estiver utilizando uma base antiga que ainda não possui a estrutura de histórico de scans, execute dentro de `backend`:

```powershell
python migrate_scan_history.py
```

Esse script prepara:

```text
tabela scans
scan_id em findings
índices
relacionamento entre findings e scans
```

Em uma instalação nova, confirme primeiro que o backend e o banco iniciaram corretamente.

---

# 13. Preparar o OWASP ZAP

O CodeShield utiliza o OWASP ZAP por Docker.

Baixe a imagem:

```powershell
docker pull ghcr.io/zaproxy/zaproxy:stable
```

Valide:

```powershell
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -cmd -version
```

Se aparecer a versão do ZAP, a imagem está pronta.

A implementação atual utiliza o:

```text
ZAP Baseline
```

Ou seja:

```text
crawling
+
análise passiva
```

Não utiliza Active Scan agressivo nesta versão.

---

# 14. Iniciar o backend

Abra um terminal:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\backend
```

Ative a `.venv`:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Execute:

```powershell
uvicorn app.main:app --reload
```

Se estiver correto, deverá aparecer algo parecido com:

```text
Uvicorn running on http://127.0.0.1:8000
```

Acesse:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

Deixe esse terminal aberto.

---

# 15. Preparar o frontend

Abra outro terminal:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\frontend
```

Instale as dependências:

```powershell
npm install
```

Inicie:

```powershell
npm start
```

Se o PowerShell bloquear o `npm.ps1`, use:

```powershell
npm.cmd start
```

ou libere somente a sessão atual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
npm start
```

O frontend deverá abrir em:

```text
http://localhost:3000
```

---

# 16. Estado esperado antes do primeiro scan

Antes de testar, confirme:

```text
Docker Desktop     → funcionando
PostgreSQL         → container ativo
Backend FastAPI    → http://127.0.0.1:8000
Frontend React     → http://localhost:3000
Semgrep            → funcionando
Trivy              → funcionando
Gitleaks           → funcionando
OWASP ZAP          → imagem Docker disponível
```

Você pode testar:

```powershell
semgrep --version
trivy --version
gitleaks version
docker version
```

---

# 17. Executar o primeiro scan

Abra:

```text
http://localhost:3000
```

No campo de repositório, informe:

```text
https://github.com/caiquerodrigues337-ctrl/aspm-pt-2-sem-mexer-no-original
```

Esse campo é utilizado por:

```text
Semgrep
Trivy
Gitleaks
```

No campo de Target DAST, informe:

```text
http://localhost:3000
```

Esse campo é utilizado pelo:

```text
OWASP ZAP
```

Clique em:

```text
Iniciar Scan
```

---

# 18. Como funciona o fluxo

A execução segue aproximadamente:

```text
Repositório Git
     │
     ├── Semgrep  → SAST
     ├── Trivy    → SCA
     └── Gitleaks → Secrets

Aplicação em execução
     │
     └── OWASP ZAP → DAST

             ↓
       Normalização
             ↓
        Pride Score
             ↓
        IA / Claude
       quando aplicável
             ↓
        PostgreSQL
             ↓
       Dashboard React
```

---

# 19. Observação importante sobre localhost e ZAP

O usuário informa:

```text
http://localhost:3000
```

Porém o ZAP está dentro de um container Docker.

Dentro do container, o backend converte o endereço para:

```text
http://host.docker.internal:3000
```

Isso permite que o ZAP acesse a aplicação que está rodando no Windows.

---

# 20. Resultado esperado

Ao final do scan, o dashboard deve exibir:

```text
TOTAL
SAST
SCA
SECRETS
DAST
CRÍTICOS
ALTOS
MÉDIOS
BAIXOS
```

Durante o teste final do desenvolvimento, foi obtido:

```text
SAST:     20
SCA:      66
SECRETS:   1
DAST:     14
TOTAL:   101
```

Os números podem mudar dependendo:

- do repositório;
- das dependências;
- do histórico Git;
- da aplicação analisada;
- das versões das ferramentas.

---

# 21. Testar a PoC de validação de fix

Dentro de:

```text
backend/
```

com a `.venv` ativa:

```powershell
python test_poc_fix.py
```

Esse teste verifica o fluxo de validação determinística.

O processo utiliza:

```text
finding original
→ baseline Semgrep
→ aplicação do fix em cópia temporária
→ validação AST
→ re-scan Semgrep
→ decisão
```

Possíveis resultados:

```text
FIX VALIDADO
FIX REPROVADO
VALIDAÇÃO INCONCLUSIVA
```

O código produzido pela IA não é executado.

---

# 22. Testar o ZAP isoladamente

Com uma aplicação disponível em:

```text
http://localhost:3000
```

vá para:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\backend
```

Ative a `.venv` e execute:

```powershell
python test_zap.py
```

O teste deve executar o ZAP e retornar findings normalizados.

---

# 23. Verificar o histórico de scans

Com o backend rodando:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/scans?limit=5"
```

Para mostrar de maneira organizada:

```powershell
$scans = Invoke-RestMethod "http://127.0.0.1:8000/api/scans?limit=5"

$scans |
Select-Object id, status, total, semgrep_total, trivy_total, started_at |
Format-Table -AutoSize
```

Cada execução possui um:

```text
scan_id
```

Os findings ficam relacionados ao scan correspondente.

---

# 24. Solução de problemas comuns

## PowerShell bloqueia scripts

Erro parecido com:

```text
a execução de scripts foi desabilitada neste sistema
```

Use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Essa alteração vale apenas para o terminal atual.

---

## npm.ps1 bloqueado

Use:

```powershell
npm.cmd start
```

---

## Docker não está funcionando

Confirme que o Docker Desktop está aberto.

Depois:

```powershell
docker version
docker compose ps
```

Se necessário:

```powershell
wsl --shutdown
```

Depois reabra o Docker Desktop.

Evite apagar volumes ou executar comandos destrutivos se já houver dados importantes no PostgreSQL.

---

## Semgrep não encontrado

Com `.venv` ativa:

```powershell
pip install semgrep
```

Depois:

```powershell
semgrep --version
```

---

## Trivy não encontrado

Verifique:

```powershell
trivy --version
```

Caso necessário, configure o `PATH` ou o caminho do executável.

---

## Gitleaks não encontrado

Verifique:

```powershell
gitleaks version
```

Confirme se `gitleaks.exe` está acessível pelo `PATH`.

---

## ZAP não consegue acessar localhost

O CodeShield já converte:

```text
localhost
```

para:

```text
host.docker.internal
```

Mas a aplicação precisa estar realmente funcionando no host.

Teste primeiro:

```text
http://localhost:3000
```

no navegador.

---

## IA aparece como desativada

Confira se existe:

```text
backend/.env
```

e se ele contém:

```env
REACT_APP_ANTHROPIC_KEY=SUA_CHAVE
```

Depois reinicie o backend.

Mesmo com a chave configurada, a API da Anthropic precisa possuir créditos para gerar novas respostas.

---

# 25. Como desligar o ambiente

Para parar o backend:

```text
Ctrl + C
```

Para parar o frontend:

```text
Ctrl + C
```

Para parar os containers:

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM
docker compose down
```

---

# 26. Como iniciar novamente depois da primeira instalação

Depois que tudo já estiver instalado, não é necessário repetir o tutorial inteiro.

## Terminal 1 — Docker

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM
docker compose up -d
```

## Terminal 2 — Backend

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\backend
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

## Terminal 3 — Frontend

```powershell
cd C:\Users\SEU_USUARIO\CodeShield-ASPM\frontend
npm.cmd start
```

Depois acesse:

```text
http://localhost:3000
```

---

# 27. Checklist final

Antes de considerar a instalação concluída:

```text
[ ] Git instalado
[ ] Python instalado
[ ] Node/npm instalados
[ ] Docker Desktop instalado
[ ] Repositório clonado
[ ] .venv criada
[ ] requirements.txt instalado
[ ] backend/.env configurado
[ ] PostgreSQL funcionando
[ ] Semgrep funcionando
[ ] Trivy funcionando
[ ] Gitleaks funcionando
[ ] Imagem OWASP ZAP disponível
[ ] Backend funcionando
[ ] Frontend funcionando
[ ] Scan SAST funcionando
[ ] Scan SCA funcionando
[ ] Secrets funcionando
[ ] DAST funcionando
[ ] Findings aparecendo no dashboard
[ ] Histórico de scans funcionando
```

---

# 28. Resumo rápido

Depois da primeira instalação, para subir o CodeShield em outro dia:

```text
1. Abrir Docker Desktop
2. docker compose up -d
3. Ativar backend/.venv
4. uvicorn app.main:app --reload
5. npm.cmd start no frontend
6. Abrir http://localhost:3000
7. Informar repo_url
8. Informar target_url, se desejar DAST
9. Iniciar Scan
```

Com isso, o ambiente do CodeShield ASPM estará pronto para uso.
