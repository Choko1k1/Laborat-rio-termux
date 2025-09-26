#!/data/data/com.termux/files/usr/bin/env bash
set -euo pipefail

# Install & Provision: Azzy Lab Full
# Usage: chmod +x install_azzy_lab_full.sh && ./install_azzy_lab_full.sh
# Platform: Termux (Android). Assumes pkg available.

PROJECT_DIR="$HOME/azzy-shop-full"
VENV_DIR="$PROJECT_DIR/.venv"
PY_BIN="$(command -v python || command -v python3 || echo python)"

echo "[INFO] Criando projeto em: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# System packages (best-effort, non-fatal)
echo "[INFO] Instalando pacotes básicos (pkg). Pode falhar se não tiver permissões."
pkg update -y >/dev/null 2>&1 || true
pkg install -y python git wget unzip termux-api >/dev/null 2>&1 || true

# Diretórios
mkdir -p templates static css js data

# requirements
cat > requirements.txt <<'REQ'
Flask>=2.2
gunicorn>=20.1
werkzeug>=2.2
SQLAlchemy>=1.4
Flask-Login>=0.6
REQ

# products.json
cat > data/products.json <<'JSON'
[
  {"sku":"AZ001","name":"Cyberdeck Mini","price":1299.00,"desc":"Placa compacta para pentesting offline.","img":"icon-deck"},
  {"sku":"AZ002","name":"Ghost Key","price":49.99,"desc":"Dongle USB para testes de autenticação (fictício).","img":"icon-key"},
  {"sku":"AZ003","name":"Signal Cloak","price":299.50,"desc":"Capa de ruído para sinal - simulado.","img":"icon-cloak"}
]
JSON

# app.py
cat > app.py <<'PY'
from flask import Flask, render_template, jsonify, request, abort, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
import os, json, datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "app.db"))
DB_URL = f"sqlite:///{DB_PATH}"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET", "change-me-azzy")

# SQLAlchemy
engine = create_engine(DB_URL, connect_args={"check_same_thread": False}, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)
    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

class LabLog(Base):
    __tablename__ = "lab_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(64))
    client_ip = Column(String(64))
    headers = Column(Text)
    body = Column(Text)
    status = Column(String(16))

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    u = db.query(User).filter(User.id == int(user_id)).first()
    db.close()
    return u

# Load products
with open(os.path.join(BASE_DIR, "data", "products.json"), "r", encoding="utf-8") as f:
    PRODUCTS = json.load(f)

# Shop
@app.route("/")
def index():
    return render_template("index.html", products=PRODUCTS)

@app.route("/index2")
def index2():
    return render_template("index2.html", products=PRODUCTS)

@app.route("/product/<sku>")
def product_page(sku):
    p = next((x for x in PRODUCTS if x["sku"] == sku), None)
    if not p:
        abort(404)
    return render_template("product.html", product=p)

@app.route("/api/products")
def api_products():
    return jsonify({"products": PRODUCTS})

# Auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.check_password(password):
        db.close()
        flash("Credenciais inválidas", "error")
        return redirect(url_for("login"))
    login_user(user)
    db.close()
    return redirect(url_for("post_login"))

@app.route("/post_login")
@login_required
def post_login():
    return render_template("post_login.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# admin-only decorator
def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            abort(403)
        return func(*args, **kwargs)
    return wrapper

@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    db = SessionLocal()
    logs = db.query(LabLog).order_by(LabLog.id.desc()).limit(200).all()
    db.close()
    return render_template("admin_logs.html", logs=logs)

# /api/lab -> console + DB
@app.route("/api/lab", methods=["POST"])
def api_lab():
    client_ip = request.remote_addr
    now = datetime.datetime.utcnow().isoformat() + "Z"
    headers = {k:v for k,v in request.headers.items()}
    raw = request.get_data(as_text=True)

    # Console log
    print("="*60)
    print(f"[{now}] /api/lab acesso")
    print(f"IP: {client_ip}")
    print("Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print("Body raw:")
    print(raw)
    print("="*60)

    # Persist
    try:
        json.loads(raw) if raw else {}
        status = "valid"
        code = 200
    except json.JSONDecodeError:
        status = "invalid"
        code = 400

    db = SessionLocal()
    log = LabLog(timestamp=now, client_ip=client_ip, headers=json.dumps(headers), body=raw, status=status)
    db.add(log); db.commit(); db.close()

    resp = {
        "timestamp": now,
        "client_ip": client_ip,
        "status": status,
        "headers": {
            "User-Agent": headers.get("User-Agent", "N/A"),
            "Content-Type": headers.get("Content-Type", "N/A")
        }
    }
    return jsonify(resp), code

@app.errorhandler(403)
def forbidden(e):
    return "403 Forbidden", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
PY

# templates/base.html
cat > templates/base.html <<'HTML'
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azzy Shop</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header class="topbar">
    <div class="brand">AZZY<span class="neon">SHOP</span></div>
    <nav>
      <a href="/">Loja</a>
      <a href="/index2">Coleções</a>
      {% if current_user.is_authenticated %}
        <a href="/post_login">Conta</a>
        <a href="/logout">Sair</a>
      {% else %}
        <a href="/login">Entrar</a>
      {% endif %}
    </nav>
  </header>
  <main>
    {% block content %}{% endblock %}
  </main>
<script src="/static/shop.js"></script>
</body>
</html>
HTML

# templates/index.html
cat > templates/index.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="hero">
  <h1>Loja de Testes — Ambiente Local</h1>
  <p>Produtos fictícios para estudo e pentest. Use apenas em ambiente autorizado.</p>
</section>
<section class="catalog">
  {% for p in products %}
  <article class="card">
    <div class="card-icon">
      {% if p.img == 'icon-deck' %}
        <svg viewBox="0 0 24 24" class="svgicon"><rect x="2" y="5" width="20" height="14" rx="2"/></svg>
      {% elif p.img == 'icon-key' %}
        <svg viewBox="0 0 24 24" class="svgicon"><path d="M7 14a5 5 0 1 0-4-2"/></svg>
      {% else %}
        <svg viewBox="0 0 24 24" class="svgicon"><path d="M12 2 L20 22 L4 22 Z"/></svg>
      {% endif %}
    </div>
    <div class="card-body">
      <h3>{{ p.name }}</h3>
      <p class="price">R$ {{ "%.2f"|format(p.price) }}</p>
      <p class="desc">{{ p.desc }}</p>
      <div class="actions">
        <a class="btn" href="/product/{{ p.sku }}">Ver</a>
      </div>
    </div>
  </article>
  {% endfor %}
</section>
{% endblock %}
HTML

# templates/index2.html
cat > templates/index2.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="hero">
  <h2>Coleções</h2>
  <p>Exemplo de outra página de loja (filtros não conectados — oportunidade para testes).</p>
</section>
<div class="catalog">
  {% for p in products %}
    <article class="card"><div class="card-body"><h3>{{p.name}}</h3><p>{{p.desc}}</p></div></article>
  {% endfor %}
</div>
{% endblock %}
HTML

# templates/product.html
cat > templates/product.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="product">
  <h2>{{ product.name }}</h2>
  <p class="price">R$ {{ "%.2f"|format(product.price) }}</p>
  <p>{{ product.desc }}</p>
  <form method="post" action="#" onsubmit="alert('Compra é fictícia — ambiente de testes'); return false;">
    <button class="btn">Comprar</button>
  </form>
  <p><a href="/">« Voltar</a></p>
</section>
{% endblock %}
HTML

# templates/login.html
cat > templates/login.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="product" style="max-width:480px">
  <h2>Login</h2>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <ul>
      {% for cat,msg in messages %}
        <li class="{{cat}}">{{msg}}</li>
      {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}
  <form method="post" action="/login">
    <label>Usuário<br><input name="username" required></label><br><br>
    <label>Senha<br><input name="password" type="password" required></label><br><br>
    <button class="btn" type="submit">Entrar</button>
  </form>
</section>
{% endblock %}
HTML

# templates/post_login.html
cat > templates/post_login.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="product">
  <h2>Conta</h2>
  <p>Bem-vindo, {{ user.username }}.</p>
  {% if user.is_admin %}
    <p><a href="/admin/logs" class="btn">Ver logs do /api/lab</a></p>
  {% endif %}
  <p><a href="/">Voltar à loja</a> — <a href="/logout">Sair</a></p>
</section>
{% endblock %}
HTML

# templates/admin_logs.html
cat > templates/admin_logs.html <<'HTML'
{% extends "base.html" %}
{% block content %}
<section class="product">
  <h2>Logs /api/lab (Últimos 200)</h2>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr><th>ID</th><th>TS</th><th>IP</th><th>Status</th><th>Body</th></tr></thead>
    <tbody>
      {% for l in logs %}
      <tr style="border-top:1px solid rgba(255,255,255,0.03)"><td>{{ l.id }}</td><td>{{ l.timestamp }}</td><td>{{ l.client_ip }}</td><td>{{ l.status }}</td><td><pre style="white-space:pre-wrap;max-height:120px;overflow:auto">{{ l.body }}</pre></td></tr>
      {% endfor %}
    </tbody>
  </table>
  <p><a href="/post_login">Voltar</a></p>
</section>
{% endblock %}
HTML

# static/style.css
cat > static/style.css <<'CSS'
:root{--bg:#05060a;--panel:#081018;--neon:#e6f7ff}
*{box-sizing:border-box}
body{margin:0;font-family:Inter,Roboto,Arial;background:linear-gradient(180deg,var(--bg),#020204);color:#dfefff}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:rgba(255,255,255,0.02);border-bottom:1px solid rgba(255,255,255,0.03)}
.brand{font-weight:700;letter-spacing:2px}
.brand .neon{color:var(--neon);text-shadow:0 0 8px rgba(230,247,255,0.9)}
.topbar nav a{color:rgba(230,247,255,0.9);margin-left:14px;text-decoration:none}
main{padding:20px}
.hero{padding:20px;border-radius:8px;background:rgba(255,255,255,0.02);margin-bottom:16px}
.catalog{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{display:flex;gap:12px;padding:12px;background:var(--panel);border-radius:8px;border:1px solid rgba(255,255,255,0.03)}
.card-icon{width:72px;height:72px;display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,0.02);border-radius:8px}
.svgicon{width:48px;height:48px;fill:none;stroke:var(--neon);stroke-width:1.2}
.card-body h3{margin:0 0 6px 0}
.price{color:var(--neon);font-weight:700}
.btn{background:transparent;color:var(--neon);border:1px solid rgba(230,247,255,0.12);padding:8px 10px;border-radius:6px;cursor:pointer}
.product{padding:12px;background:var(--panel);border-radius:8px}
CSS

# static/shop.js
cat > static/shop.js <<'JS'
// Minimal client JS
console.log('Azzy Shop client loaded');
JS

# create_db_and_admin.py
cat > create_db_and_admin.py <<'PY'
from sqlalchemy import create_engine
from app import Base, engine
import os
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'app.db')
def ensure_db():
    d = os.path.dirname(DB_PATH)
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    Base.metadata.create_all(bind=engine)
if __name__ == '__main__':
    ensure_db()
    print('DB criado / atualizado em', DB_PATH)
PY

# gen_admin.py (rotate admin creds each start)
cat > gen_admin.py <<'PY'
import os, random, string
from sqlalchemy.orm import sessionmaker
from app import User, engine
from werkzeug.security import generate_password_hash
def randstr(n=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))
Session = sessionmaker(bind=engine)
if __name__ == '__main__':
    username = 'admin_' + randstr(6)
    password = randstr(14)
    session = Session()
    # delete old auto admins
    for u in session.query(User).filter(User.username.like('admin_%')).all():
        session.delete(u)
    usr = User(username=username, password_hash=generate_password_hash(password), is_admin=True)
    session.add(usr)
    session.commit()
    session.close()
    with open('data/credentials.txt','w') as f:
        f.write(f"{username}:{password}\n")
    print('CREDENTIALS_ROTATED', username, password)
PY

# README.md (sem referência a IA)
cat > README.md <<'MD'
# Azzy Lab — Mini Shop (Local Lab)

Projeto local para fins educativos e testes de pentest. O sistema entrega:

- Frontend simples (Flask + templates) com tema "hacker" (neon branco).
- Autenticação com SQLite.
- Endpoint `/api/lab` que registra payloads recebidos (console + DB).
- Geração automática de credenciais admin a cada inicialização (arquivo `data/credentials.txt`).
- Páginas: `/`, `/index2`, `/product/<sku>`, `/login`, `/post_login`, `/admin/logs`.

## Como usar
1. Instale dependências: `pkg install python git` (Termux).
2. Execute o script de instalação: `chmod +x install_azzy_lab_full.sh && ./install_azzy_lab_full.sh`.
3. Inicie: `./start.sh`.
4. As credenciais geradas estarão em `data/credentials.txt` e serão exibidas no console.

## Observações técnicas
- Banco: SQLite (`data/app.db`).
- Segurança: ambiente propositalmente vulnerável em pontos discretos para treinamento (inputs refletidos, filtros leves). Use apenas em ambiente autorizado.
- Ao expor via túnel (ngrok), tenha plena consciência dos riscos.
MD

# start.sh
cat > start.sh <<'SH'
#!/data/data/com.termux/files/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
  python -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# cria DB
python create_db_and_admin.py
# gera credenciais admin aleatórias
python gen_admin.py
creds=$(cat data/credentials.txt | tr -d '\n')
# start gunicorn
nohup .venv/bin/gunicorn -w 2 -b 0.0.0.0:5000 app:app >/dev/null 2>&1 &
sleep 1
echo "[INFO] App iniciado em http://127.0.0.1:5000"
echo "[INFO] Credenciais admin (rotated): $creds"
# tenta abrir Chrome / browser no Android
if command -v termux-open-url >/dev/null 2>&1; then
  termux-open-url "http://127.0.0.1:5000"
elif command -v am >/dev/null 2>&1; then
  am start -a android.intent.action.VIEW -d "http://127.0.0.1:5000" com.android.chrome || true
else
  echo "Abra manualmente no navegador: http://127.0.0.1:5000"
fi
SH

# stop.sh
cat > stop.sh <<'SH'
#!/data/data/com.termux/files/usr/bin/env bash
pkill -f 'gunicorn -w' || true
echo "[INFO] Parada enviada"
SH

chmod +x start.sh stop.sh
chmod +x create_db_and_admin.py gen_admin.py

echo "[DONE] Instalação concluída em: $PROJECT_DIR"
echo "  Inicie com: cd $PROJECT_DIR && ./start.sh"
echo "  Pare com: cd $PROJECT_DIR && ./stop.sh"
echo "  Credenciais serão gravadas em: data/credentials.txt"
