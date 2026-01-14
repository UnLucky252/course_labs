from flask import Flask, request, make_response
import sqlite3
import os
import subprocess
import json
import logging
import re
from markupsafe import escape
from typing import Optional

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
    """Безопасное подключение к базе данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def validate_input(input_str: str, pattern: str = r'^[a-zA-Z0-9_\-\. ]+$') -> bool:
    """Валидация пользовательского ввода"""
    return bool(re.match(pattern, input_str))

@app.route("/")
def index():
    return "Vulnerable lab07 app v1.0"

@app.route("/user")
def get_user():
    username = request.args.get("name", "")

    if not validate_input(username):
        return {"error": "Invalid input"}, 400

    conn = get_db()
    cur = conn.cursor()
    query = "SELECT id, name, email FROM users WHERE name = ?"
    app.logger.debug("Executing safe query: %s with param: %s", query, username)

    try:
        rows = cur.execute(query, (username,)).fetchall()
        result = [dict(row) for row in rows]
        return {"result": result}
    except Exception as e:
        app.logger.error("Database error: %s", str(e))
        return {"error": "Database error"}, 500
    finally:
        conn.close()

@app.route("/search")
def search():
    q = request.args.get("q", "")
    safe_q = escape(q)
    html = f"<h1>Results for: {safe_q}</h1>"
    return make_response(html, 200)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    if not validate_input(host, r'^[a-zA-Z0-9\.\-]+$'):
        return "Invalid hostname", 400

    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return f"Pinged {host}. Output: {result.stdout}"
    except subprocess.TimeoutExpired:
        return "Ping timeout", 500
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/backup")
def backup():
    target = request.args.get("target", "/tmp/backup.sql")

    if not target.startswith('/tmp/'):
        return "Backup path must be in /tmp directory", 400

    try:
        with open(target, 'w') as f:
            result = subprocess.run(
                ['pg_dump', 'mydb'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return f"Backup failed: {result.stderr}", 500
            f.write(result.stdout)
        return f"Backup to {target} completed successfully"
    except Exception as e:
        return str(e), 500

@app.route("/read")
def read_file():
    path = request.args.get("path", "")

    if '..' in path or path.startswith('/'):
        return "Access denied", 403

    allowed_files = ['app.log', 'readme.txt']
    if path not in allowed_files:
        return f"File not allowed. Allowed: {', '.join(allowed_files)}", 400

    try:
        with open(path, "r") as f:
            data = f.read()
        return f"<pre>{escape(data)}</pre>"
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        return str(e), 500

@app.route("/load")
def load():
    data = request.args.get("data", "")

    if not data:
        return "No data provided", 400

    try:
        import base64
        decoded_data = base64.b64decode(data).decode('utf-8')
        obj = json.loads(decoded_data)
        return f"Loaded JSON object: {obj}"
    except json.JSONDecodeError:
        return "Invalid JSON data", 400
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")

    if not expr:
        return "No expression provided", 400

    if not validate_input(expr, r'^[0-9\+\-\*\/\(\)\.\s]+$'):
        return "Invalid characters in expression", 400

    try:
        result = eval(expr, {"__builtins__": None}, {})
        return str(result)
    except Exception as e:
        return f"Calculation error: {e}", 500

@app.route("/debug")
def debug():
    if not app.config["DEBUG"]:
        return {"error": "Debug endpoint disabled in production"}, 403

    headers = dict(request.headers)
    filtered_headers = {}
    for k, v in headers.items():
        if k.lower() not in ['authorization', 'cookie', 'x-api-key']:
            filtered_headers[k] = v

    return {
        "message": "Debug information (limited)",
        "headers": filtered_headers,
        "app_debug": app.config["DEBUG"]
    }

@app.route("/health")
def health():
    """Health check endpoint для мониторинга"""
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

if __name__ == "__main__":
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))

    if app.config["DEBUG"]:
        app.run(host=host, port=port, debug=True)
    else:
        print(f"Production mode. Please run with: gunicorn -w 4 -b {host}:{port} app:app")
        app.run(host=host, port=port, debug=False)
