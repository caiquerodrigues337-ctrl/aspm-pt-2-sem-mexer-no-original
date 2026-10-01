"""
ARQUIVO DE TESTE DO CODESHIELD.

Este arquivo contém padrões propositalmente inseguros
somente para validar o scanner SAST/Semgrep.

NÃO EXECUTAR EM PRODUÇÃO.
"""

import sqlite3
import subprocess

from flask import Flask, request, render_template_string


app = Flask(__name__)


# 1. Hardcoded secret
API_KEY = "super-secret-api-key-123456789"


# 2. Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    subprocess.run(
        f"ping {host}",
        shell=True
    )

    return "Comando executado"


# 3. SQL Injection
@app.route("/usuario")
def usuario():
    user_id = request.args.get("id", "")

    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()

    query = f"SELECT * FROM usuarios WHERE id = {user_id}"

    cursor.execute(query)

    resultado = cursor.fetchall()

    conexao.close()

    return str(resultado)


# 4. Server-Side Template Injection
@app.route("/pagina")
def pagina():
    nome = request.args.get("nome", "")

    return render_template_string(
        "<h1>Olá " + nome + "</h1>"
    )


# 5. Uso inseguro de eval
@app.route("/calcular")
def calcular():
    expressao = request.args.get("expressao", "")

    resultado = eval(expressao)

    return str(resultado)