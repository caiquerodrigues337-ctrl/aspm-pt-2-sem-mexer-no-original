# CodeShield ASPM — Resumo da Entrega FIAP / Pride Security

## 1. Objetivo

A entrega teve dois objetivos centrais:

1. expandir a esteira do CodeShield além de SAST;
2. implementar uma PoC determinística para validar correções sugeridas por IA.

## 2. O que foi adicionado

### SCA com Trivy

Foi adicionado um scanner de composição de software para identificar vulnerabilidades conhecidas em dependências.

Fluxo:

```text
Repositório
→ Trivy
→ normalização
→ Pride Score
→ PostgreSQL
→ frontend
```

### Secrets Scanning com Gitleaks

O clone passou a preservar o histórico Git completo para que o Gitleaks também consiga detectar segredos existentes em commits anteriores.

Fluxo:

```text
Histórico Git
→ Gitleaks
→ normalização
→ Pride Score
→ PostgreSQL
→ frontend
```

### DAST com OWASP ZAP

Foi integrado o OWASP ZAP Baseline por Docker.

O usuário informa separadamente:

```text
repo_url   → scanners de repositório
target_url → OWASP ZAP
```

Isso evita tentar executar DAST contra a URL do GitHub.

Para desenvolvimento local:

```text
localhost
→ host.docker.internal
```

dentro do container ZAP.

O primeiro nível usa Baseline/passive scan, evitando Active Scan agressivo nesta etapa.

### Validação determinística de fix

Foi criada uma PoC para findings Semgrep:

```text
1. confirmar a rule_id no arquivo original;
2. obter a sugestão de correção;
3. aplicar a alteração somente em cópia temporária;
4. validar sintaxe/estrutura Python com AST;
5. executar novamente o Semgrep;
6. verificar se a mesma rule_id desapareceu.
```

Resultados possíveis:

```text
FIX VALIDADO
FIX REPROVADO
VALIDAÇÃO INCONCLUSIVA
```

O código gerado pela IA não é executado.

## 3. Integração com frontend

O dashboard passou a exibir separadamente:

- SAST;
- SCA;
- Secrets;
- DAST;
- quantidade por severidade;
- Pride Score;
- origem do finding;
- estado de validação do fix.

Também foi adicionado um campo separado para o target DAST.

## 4. Persistência e histórico

Cada scan recebe um `scan_id`.

Os findings são armazenados no PostgreSQL e associados à execução correspondente, permitindo consultar scans anteriores sem apagar automaticamente os resultados.

## 5. IA

A integração com Anthropic Claude permanece no backend.

A chave é lida de:

```env
REACT_APP_ANTHROPIC_KEY
```

A IA é utilizada para:

- gerar recomendações de correção;
- responder perguntas contextualizadas sobre findings.

A PoC determinística reduz a dependência de confiança direta na resposta do modelo.

## 6. Evidência do teste final

Execução final:

```text
Semgrep  (SAST):     20
Trivy    (SCA):      66
Gitleaks (SECRETS):   1
OWASP ZAP (DAST):    14
Total:              101
```

O scan concluiu com os 101 findings persistidos.

## 7. Arquivos principais criados ou alterados

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

## 8. Resultado

A plataforma deixa de depender apenas de análise estática e passa a correlacionar diferentes classes de evidência:

```text
SAST + SCA + Secrets + DAST
```

Além disso, a correção sugerida por IA pode passar por validação objetiva antes de ser considerada válida.

## 9. Pontos para demonstração

Durante a apresentação:

1. mostrar os quatro cards de scanners no dashboard;
2. explicar a diferença entre `repo_url` e `target_url`;
3. mostrar um finding de cada fonte;
4. mostrar o Pride Score;
5. demonstrar `FIX VALIDADO` e `FIX REPROVADO`;
6. enfatizar que o código da IA não é executado;
7. mostrar o histórico por `scan_id`;
8. apresentar o resultado final de 101 findings.
