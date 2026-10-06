from pprint import pprint

from app.validators.fix_validator import (
    validar_fix_re_scan,
)


codigo_original = """
from flask import request

def calcular():
    expressao = request.args.get("expressao", "")
    resultado = eval(expressao)
    return str(resultado)
"""


ai_fix = '''
A vulnerabilidade ocorre porque eval() executa diretamente
conteúdo controlado pelo usuário.

Correção sugerida:

```python
import ast
from flask import request

def calcular():
    expressao = request.args.get("expressao", "")
    resultado = ast.literal_eval(expressao)
    return str(resultado)
```

A correção remove o uso de eval() sobre entrada não confiável.
'''


resultado = validar_fix_re_scan(
    ai_fix=ai_fix,
    rule_id=(
        "python.lang.security.audit."
        "eval-detected.eval-detected"
    ),
    file_path="vulnerable_sample.py",
    codigo_original=codigo_original,
)


print("\n========================================")
print("CODESHIELD - TESTE POC")
print("========================================")

pprint(resultado)

print("========================================")
