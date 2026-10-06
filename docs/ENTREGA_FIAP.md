# CodeShield ASPM — Entrega FIAP / Pride Security

## Introdução

Nesta etapa do FIAP Challenge, o nosso trabalho foi continuar o desenvolvimento do **CodeShield ASPM**, uma plataforma voltada para centralização e priorização de vulnerabilidades encontradas em aplicações.

O projeto já possuía uma base funcional com backend em FastAPI, frontend em React, banco PostgreSQL e análise SAST com Semgrep.

A partir dessa base, o foco da etapa foi principalmente ampliar a esteira de segurança e desenvolver uma forma de validar algumas correções sugeridas por inteligência artificial.

## Objetivos da etapa

Os dois objetivos principais foram:

1. ampliar a análise do CodeShield para além de SAST;
2. criar uma prova de conceito para validação determinística de correções.

Ao final da implementação, a plataforma passou a trabalhar com:

```text
SAST
SCA
Secrets Scanning
DAST
```

Além disso, foi adicionada a validação de fix para findings do Semgrep.

## SAST com Semgrep

O Semgrep já fazia parte da estrutura do projeto e continuou sendo utilizado para análise estática.

Durante o desenvolvimento, o scanner foi ajustado para trabalhar com múltiplas configurações e remover findings duplicados.

No teste final foram encontrados:

```text
20 findings SAST
```

## SCA com Trivy

Para expandir a esteira foi integrado o Trivy.

O objetivo foi identificar vulnerabilidades conhecidas nas dependências do projeto.

Os resultados do Trivy são normalizados para o mesmo padrão utilizado pelos demais findings e depois passam pelo Pride Score.

No teste final:

```text
66 findings SCA
```

## Secrets Scanning com Gitleaks

Também foi integrado o Gitleaks para procurar possíveis segredos expostos.

Uma mudança importante foi fazer o clone do repositório mantendo o histórico completo do Git.

Isso é necessário porque um segredo pode ter sido removido do arquivo atual, mas continuar registrado em um commit antigo.

No teste final:

```text
1 finding de Secrets
```

## DAST com OWASP ZAP

Para adicionar análise dinâmica, foi utilizado o OWASP ZAP.

Optamos inicialmente pelo **ZAP Baseline**, executado por Docker.

O usuário pode informar uma URL de aplicação separada da URL do repositório.

Exemplo:

```text
repo_url:
https://github.com/usuario/repositorio

target_url:
http://localhost:3000
```

Essa separação é importante porque o DAST precisa analisar uma aplicação em execução, e não o endereço do repositório Git.

Quando o target utiliza localhost, o backend converte a URL para:

```text
http://host.docker.internal:3000
```

dentro do container.

No teste final:

```text
14 findings DAST
```

## Normalização dos findings

Os findings das ferramentas são convertidos para uma estrutura comum.

Entre os dados armazenados estão:

```text
fonte
rule_id
severity
file_path
line
message
pride_score
ai_fix
fix_validado
scan_id
```

Isso permite que resultados de scanners diferentes sejam apresentados juntos no dashboard.

## Pride Score

Depois da normalização, cada finding recebe um Pride Score.

Esse score é utilizado para ajudar na priorização dos problemas encontrados.

No frontend, os findings podem ser analisados junto com a severidade, origem, regra, arquivo e recomendação de correção.

## Integração com IA

A plataforma possui integração com Anthropic Claude.

A IA é utilizada principalmente para gerar sugestões de correção e para o chatbot do CodeShield.

A variável de ambiente utilizada pelo projeto é:

```env
REACT_APP_ANTHROPIC_KEY
```

A chave fica no backend e não deve ser versionada.

Durante os testes finais, a integração estava implementada, porém algumas chamadas não puderam ser executadas porque a conta da API estava sem créditos. Isso não impediu a execução dos scanners.

## PoC de validação determinística de fix

Outra parte importante da entrega foi a criação de uma prova de conceito para validar correções de findings do Semgrep.

O problema que queríamos evitar era considerar qualquer resposta da IA como correta sem verificar o resultado.

Por isso, o processo de validação foi desenvolvido da seguinte forma:

```text
Finding original
→ confirmação da rule_id no Semgrep
→ geração da correção
→ aplicação em uma cópia temporária
→ validação com AST
→ novo scan do Semgrep
→ comparação do resultado
```

Caso a mesma `rule_id` desapareça após a alteração, o fix pode ser marcado como:

```text
FIX VALIDADO
```

Caso continue presente:

```text
FIX REPROVADO
```

Se não for possível concluir a validação:

```text
VALIDAÇÃO INCONCLUSIVA
```

O código sugerido pela IA não é executado durante o teste.

## Frontend

O frontend foi atualizado para mostrar os diferentes tipos de análise separadamente.

Foram adicionados indicadores para:

```text
SAST
SCA
SECRETS
DAST
```

Também foi criado um campo próprio para informar o target do OWASP ZAP.

Na tabela de findings é possível identificar a origem de cada resultado, por exemplo:

```text
SAST · Semgrep
SCA · Trivy
SECRETS · Gitleaks
DAST · OWASP ZAP
```

Para findings do Semgrep que possuem correção gerada pela IA, o frontend também pode mostrar o resultado da validação.

## Histórico e banco de dados

Os resultados são armazenados no PostgreSQL.

Cada nova análise recebe um:

```text
scan_id
```

Dessa forma, os findings podem ser associados a uma execução específica e o sistema consegue manter o histórico de scans.

## Resultado do teste final

No teste final realizado no projeto, obtivemos:

```text
Semgrep  (SAST):     20
Trivy    (SCA):      66
Gitleaks (SECRETS):   1
OWASP ZAP (DAST):    14
Total:              101
```

Os 101 findings foram processados e salvos pela aplicação.

Esse teste confirmou o funcionamento conjunto dos quatro scanners.

## Principais arquivos criados ou alterados

Durante esta etapa, os principais arquivos envolvidos foram:

```text
backend/app/api/scans.py
backend/app/scanners/trivy.py
backend/app/scanners/gitleaks.py
backend/app/scanners/zap.py
backend/app/validators/fix_validator.py
backend/app/validators/ast_validator.py
backend/app/models.py
backend/app/ai/remediation.py
backend/app/ai/scorer.py
backend/test_poc_fix.py
backend/test_zap.py
frontend/src/App.tsx
frontend/src/api/pride.ts
```

## O que demonstrar na apresentação

Na apresentação, os pontos mais importantes são:

1. mostrar o dashboard com os quatro tipos de scanner;
2. explicar a diferença entre a URL do repositório e o target DAST;
3. mostrar findings de fontes diferentes;
4. explicar o Pride Score;
5. mostrar um caso de `FIX VALIDADO` e um caso de `FIX REPROVADO`;
6. explicar que a validação não executa o código gerado pela IA;
7. mostrar que cada execução recebe um `scan_id`;
8. apresentar o resultado final do scan com 101 findings.

## Conclusão

A principal evolução desta etapa foi transformar o CodeShield em uma esteira de segurança mais completa.

Antes, a análise estava concentrada principalmente em SAST. Com as novas integrações, o projeto passou a analisar também dependências, possíveis segredos e a aplicação em execução.

Além disso, a PoC de validação determinística permite demonstrar uma abordagem mais segura para o uso de IA, pois uma correção pode ser verificada antes de ser considerada válida.
