from flask import Flask, request, make_response
import sqlite3
import os
import subprocess
import json
import logging
import re
import ast
from markupsafe import escape
from typing import Optional
import datetime

app = Flask(__name__)

DB_USER = os.environ.get('DB_USER', 'admin')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'SuperSecret123')
DB_PATH = os.environ.get('DB_PATH', 'app.db')

app.config["DEBUG"] = os.environ.get('DEBUG', 'false').lower() == 'true'

if app.config["DEBUG"]:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

def get_db():
    """Безопасное подключение к БД"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def validate_input(input_str: str, pattern: str = r'^[a-zA-Z0-9_\-\. ]+$') -> bool:
    """Валидация пользовательского ввода с регулярным выражением"""
    return bool(re.match(pattern, input_str)) if input_str else False

def safe_calc(expression: str) -> Optional[float]:
    """Безопасное вычисление математического выражения без eval"""
    try:
        expr = expression.replace(' ', '')

        if not re.match(r'^[\d\+\-\*\/\(\)\.]+$', expr):
            return None

        # safe_globals = {
        #    '__builtins__': None,
        #    'abs': abs,
        #    'round': round,
        #    'min': min,
        #    'max': max,
        #    'sum': sum,
        #    'int': int,
        #    'float': float
        #}

        parsed = ast.parse(expr, mode='eval')

        for node in ast.walk(parsed):
            if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript,
                               ast.Compare, ast.BoolOp, ast.UnaryOp, ast.BinOp,
                               ast.Num, ast.Constant)):
                continue
            if isinstance(node, ast.Expression):
                continue
            return None

        def evaluate(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.Constant):
                return node.value
            elif isinstance(node, ast.BinOp):
                left = evaluate(node.left)
                right = evaluate(node.right)
                if isinstance(node.op, ast.Add):
                    return left + right
                elif isinstance(node.op, ast.Sub):
                    return left - right
                elif isinstance(node.op, ast.Mult):
                    return left * right
                elif isinstance(node.op, ast.Div):
                    if right == 0:
                        raise ZeroDivisionError
                    return left / right
            elif isinstance(node, ast.UnaryOp):
                operand = evaluate(node.operand)
                if isinstance(node.op, ast.USub):
                    return -operand
                elif isinstance(node.op, ast.UAdd):
                    return operand
            raise ValueError("Unsupported operation")

        result = evaluate(parsed.body)
        return result

    except (SyntaxError, ValueError, ZeroDivisionError, TypeError):
        return None

@app.route("/")
def index():
    """ИСПРАВЛЕНИЕ: Убрана версия приложения"""
    return "Secure Application"

@app.route("/user")
def get_user():
    """Безопасный доступ к пользователям с параметризованными запросами"""
    username = request.args.get("name", "")

    if not validate_input(username):
        return {"error": "Invalid input. Only alphanumeric characters allowed"}, 400

    conn = get_db()
    cur = conn.cursor()

    query = "SELECT id, name, email FROM users WHERE name = ?"
    app.logger.debug("Safe SQL query: %s with param: %s", query, username)

    try:
        rows = cur.execute(query, (username,)).fetchall()
        result = [dict(row) for row in rows]
        return {"result": result}
    except sqlite3.Error as e:
        app.logger.error("Database error: %s", str(e))
        return {"error": "Database error"}, 500
    finally:
        conn.close()

@app.route("/search")
def search():
    """Безопасный поиск с экранированием HTML"""
    q = request.args.get("q", "")
    safe_q = escape(q)
    html = f"<h1>Results for: {safe_q}</h1>"
    return make_response(html, 200)

@app.route("/ping")
def ping():
    """ИСПРАВЛЕНИЕ RCE: безопасная команда ping без os.system"""
    host = request.args.get("host", "127.0.0.1")

    if not validate_input(host, r'^[a-zA-Z0-9\.\-]+$'):
        return {"error": "Invalid hostname format"}, 400

    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', host],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            return {"status": "success", "output": result.stdout}, 200
        else:
            return {"status": "failed", "error": result.stderr}, 500

    except subprocess.TimeoutExpired:
        return {"error": "Ping timeout"}, 500
    except FileNotFoundError:
        return {"error": "ping command not found"}, 500
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}, 500

@app.route("/backup")
def backup():
    """Безопасный backup без shell инъекций"""
    target = request.args.get("target", "/tmp/backup.sql")

    allowed_dirs = ['/tmp/', '/var/backups/']
    if not any(target.startswith(dir) for dir in allowed_dirs):
        return {"error": "Backup path must be in allowed directories"}, 400

    try:
        with open(target, 'w') as f:
            result = subprocess.run(
                ['pg_dump', '--no-password', 'mydb'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {"error": f"Backup failed: {result.stderr}"}, 500

            f.write(result.stdout)
            return {"status": "success", "message": f"Backup completed to {target}"}

    except PermissionError:
        return {"error": "Permission denied"}, 403
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/read")
def read_file():
    """ИСПРАВЛЕНИЕ LFI: безопасное чтение файлов с валидацией пути"""
    path = request.args.get("path", "")

    if not path or '..' in path or path.startswith('/'):
        return {"error": "Invalid or unsafe file path"}, 400
    allowed_files = ['app.log', 'readme.txt', 'public_data.txt']
    if path not in allowed_files:
        return {"error": f"File not allowed. Allowed files: 
        {', '.join(allowed_files)}"}, 400

    try:
        if not os.path.exists(path):
            return {"error": "File not found"}, 404

        with open(path, "r", encoding='utf-8') as f:
            data = f.read(10000)

        return {"content": escape(data)}

    except FileNotFoundError:
        return {"error": "File not found"}, 404
    except PermissionError:
        return {"error": "Permission denied"}, 403
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/load")
def load():
    """ИСПРАВЛЕНИЕ небезопасной десериализации: замена pickle на JSON"""
    data = request.args.get("data", "")

    if not data:
        return {"error": "No data provided"}, 400

    try:
        import base64
        decoded_data = base64.b64decode(data).decode('utf-8')

        obj = json.loads(decoded_data)

        if not isinstance(obj, (dict, list, str, int, float, bool, type(None))):
            return {"error": "Unsupported data type"}, 400

        return {"status": "success", "loaded_object": obj}

    except json.JSONDecodeError:
        return {"error": "Invalid JSON data"}, 400
    except UnicodeDecodeError:
        return {"error": "Invalid base64 encoding"}, 400
    except Exception as e:
        return {"error": f"Error: {e}"}, 500

@app.route("/calc")
def calc():
    """ИСПРАВЛЕНИЕ eval: безопасные математические вычисления БЕЗ eval"""
    expr = request.args.get("expr", "")

    if not expr:
        return {"error": "No expression provided"}, 400

    if not validate_input(expr, r'^[0-9\+\-\*\/\(\)\.\s]+$'):
        return {"error": "Invalid characters in expression"}, 400

    try:
        result = safe_calc(expr)

        if result is None:
            return {"error": "Invalid mathematical expression"}, 400

        return {"result": result}

    except ZeroDivisionError:
        return {"error": "Division by zero"}, 400
    except Exception as e:
        return {"error": f"Calculation error: {e}"}, 500

@app.route("/debug")
def debug():
    """Безопасный debug endpoint (ограниченная информация)"""
    if not app.config["DEBUG"]:
        return {"error": "Debug endpoint disabled in production"}, 403

    filtered_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ['authorization', 'cookie', 'x-api-key']:
            filtered_headers[k] = v

    return {
        "message": "Limited debug information",
        "headers": filtered_headers,
        "app_config": {
            "debug": app.config["DEBUG"],
            "environment": os.environ.get('FLASK_ENV', 'production')
        }
    }

@app.route("/health")
def health():
    """Health check для мониторинга"""
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "healthy", "database": "connected",
                "timestamp": str(datetime.datetime.now())}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

@app.errorhandler(404)
def not_found(error):
    return {"error": "Resource not found"}, 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}")
    return {"error": "Internal server error"}, 500

if __name__ == "__main__":
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    debug = app.config["DEBUG"]

    app.logger.info(f"Starting app on {host}:{port} (DEBUG={debug})")
    app.run(host=host, port=port, debug=debug)
