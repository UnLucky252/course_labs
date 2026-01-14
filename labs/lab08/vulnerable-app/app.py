from flask import (
    Flask,
    request,
    make_response,
    render_template_string,
    redirect,
    url_for,
    session
)
import sqlite3
import os
from markupsafe import escape
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(hours=1)

DB_PATH = os.environ.get("APP_DB_PATH", "app.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
        """
    )
    cur.execute("DELETE FROM users")
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')"
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')"
    )
    conn.commit()
    conn.close()


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'

    csp_policy = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp_policy

    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'

    permissions_policy = (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), magnetometer=(), accelerometer=(), "
        "gyroscope=()"
    )
    response.headers['Permissions-Policy'] = permissions_policy

    if 'Server' in response.headers:
        response.headers['Server'] = 'Protected-Server'

    if response.status_code == 200:
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response


@app.route("/")
def index():
    html = """
    <h1>Vulnerable DAST Demo App Secured</h1>
    <p>Пример уязвимого приложения для лабораторной по DAST (с исправлениями).</p>
    <ul>
      <li><a href="/echo?msg=Hello">Reflected XSS / echo</a></li>
      <li><a href="/search?username=admin">SQL Injection / search</a></li>
      <li><a href="/login">Логин с исправлениями</a></li>
      <li><a href="/profile">Профиль (сессия)</a></li>
      <li><a href="/admin">«Админка» с проверкой сессии</a></li>
      <li><a href="/files/secret.txt">Файл secret.txt</a></li>
    </ul>
    """
    resp = make_response(html)
    resp.set_cookie(
        "session_info",
        "secure-session",
        httponly=True,
        samesite='Lax',
        max_age=3600
    )
    return resp


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    safe_msg = escape(msg)
    template = """
    <h2>Echo (с защитой XSS)</h2>
    <p>Сообщение: {{msg}}</p>
    <p>Попробуйте передать что-нибудь вроде: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    <a href="/">Назад</a>
    """
    return render_template_string(template, msg=safe_msg)


@app.route("/search")
def search():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    query = "SELECT id, username, role FROM users WHERE username = ?"
    rows = []
    error = None

    try:
        cur.execute(query, (username,))
        rows = cur.fetchall()
    except Exception as e:
        app.logger.error(f"SQL error: {e}")
        error = "Ошибка выполнения запроса"

    conn.close()

    safe_username = escape(username)

    template = """
    <h2>Поиск пользователя</h2>
    <p>Поиск по имени: <code>{{ username }}</code></p>
    {% if error %}
      <p style="color:red;">{{ error }}</p>
    {% endif %}
    {% if rows %}
      <ul>
      {% for id, username, role in rows %}
        <li>{{ id }} – {{ username }} ({{ role }})</li>
      {% endfor %}
      </ul>
    {% else %}
      <p>Ничего не найдено</p>
    {% endif %}
    <p><small>SQL-запрос больше не отображается в целях безопасности</small></p>
    <a href="/">Назад</a>
    """
    return render_template_string(template, username=safe_username, rows=rows, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        form = """
        <h2>Логин (безопасный)</h2>
        <form method="post">
          <label>Username: <input type="text" name="username"></label><br>
          <label>Password: <input type="password" name="password"></label><br>
          <button type="submit">Login</button>
        </form>
        <p>Попробуйте: admin / admin123 или user / user123</p>
        <a href="/">Назад</a>
        """
        return render_template_string(form)

    username = escape(request.form.get("username", ""))
    password = escape(request.form.get("password", ""))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    row = cur.execute(query, (username, password)).fetchone()
    conn.close()

    if row:
        _, uname, role = row
        session['user'] = uname
        session['role'] = role
        session.permanent = True

        resp = make_response(
            f"<h2>Добро пожаловать, {escape(uname)} ({escape(role)})!</h2>"
            f"<p><a href='/profile'>Профиль</a> | <a href='/'>На главную</a></p>"
        )
        return resp
    else:
        return render_template_string(
            "<h2>Неверные учетные данные</h2><a href='/login'>Попробовать снова</a>"
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route("/profile")
def profile():
    username = session.get('user', 'guest')
    role = session.get('role', 'guest')

    template = """
    <h2>Профиль пользователя</h2>
    <p>Имя: {{ username }}</p>
    <p>Роль: {{ role }}</p>
    <p>Используется защищенная сессия Flask.</p>
    <p><a href="/logout">Выйти</a> | <a href="/">На главную</a></p>
    """
    return render_template_string(template, username=escape(username), role=escape(role))


@app.route("/admin")
def admin():
    if session.get('role') != 'admin':
        return (
            "<h2>Доступ запрещён: требуются права администратора</h2>"
            "<p><a href='/login'>Войти</a> | <a href='/'>На главную</a></p>",
            403,
        )

    template = """
    <h2>Admin panel</h2>
    <p>Секретные настройки приложения (демо).</p>
    <ul>
      <li>DEBUG: false</li>
      <li>SECURITY: enhanced</li>
      <li>LOGGING: enabled</li>
    </ul>
    <p><a href="/">На главную</a></p>
    """
    return render_template_string(template)


@app.route("/files/")
@app.route("/files/<path:subpath>")
def files(subpath=""):
    base_dir = os.path.abspath(os.path.dirname(__file__))
    target_dir = os.path.join(base_dir, "files")

    if subpath:
        requested_path = os.path.join(target_dir, subpath)
        requested_path = os.path.normpath(requested_path)
        if not requested_path.startswith(os.path.normpath(target_dir)):
            return "<h2>Доступ запрещён</h2><a href='/'>Назад</a>", 403
    else:
        return """
        <h2>Доступные файлы</h2>
        <ul>
          <li><a href="/files/secret.txt">secret.txt</a></li>
        </ul>
        <p><em>Directory listing отключен в целях безопасности.</em></p>
        <a href="/">Назад</a>
        """, 200

    full_path = requested_path

    if not os.path.exists(full_path):
        return "<h2>Путь не найден</h2><a href='/'>Назад</a>", 404

    if os.path.isdir(full_path):
        return "<h2>Доступ к директориям запрещён</h2><a href='/'>Назад</a>", 403

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        safe_content = escape(content)
        return f"<h3>Содержимое файла {escape(os.path.basename(full_path))}:</h3><pre>{safe_content}</pre><a href='/'>Назад</a>"
    except Exception as e:
        app.logger.error(f"Error reading file: {e}")
        return "<h2>Ошибка чтения файла</h2><a href='/'>Назад</a>", 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
