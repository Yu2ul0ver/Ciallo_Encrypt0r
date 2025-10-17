import os
import io
import csv
import json
import pathlib
import random
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from encrypt import ciallo_encrypt

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, Response, stream_with_context
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "Lov3C1allo2025qwq!@#$"

DATA_DIR = pathlib.Path("data")
DATA_DIR.mkdir(exist_ok=True)

LOG_FILE = pathlib.Path(os.environ.get("LOG_FILE", DATA_DIR / "logs.jsonl"))

PROJECT_LOGS_FILE = DATA_DIR / "project_logs.jsonl"

CREDS_FILE = DATA_DIR / "admin_cred.json"
flag = os.environ.get("FLAG",'flag{test_flag}')
os.environ['FLAG'] = ''

DEFAULT_ADMIN_USER = None # email
DEFAULT_ADMIN_PASS = None # md5(the name of Repository)


def _ensure_creds_file():
    if not CREDS_FILE.exists():
        creds = {
            "username": DEFAULT_ADMIN_USER,
            "password": DEFAULT_ADMIN_PASS  
        }
        CREDS_FILE.write_text(json.dumps(creds, ensure_ascii=False, indent=2), encoding="utf-8")

def load_creds():
    _ensure_creds_file()
    with CREDS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_creds(creds: dict):
    CREDS_FILE.write_text(json.dumps(creds, ensure_ascii=False, indent=2), encoding="utf-8")


def preset():
    start_ts = 1760112039 
    end_ts = 1760716839 
    random_ts = random.randint(start_ts, end_ts)

    ts_str = str(int(random_ts))
    timestamp = random_ts
    dt = datetime.fromtimestamp(timestamp) 
    time_str = dt.strftime("%Y-%m-%d %H:%M:%S") 
    ct = ciallo_encrypt(flag, ts_str)  
    entry = {"ciphertext": ct, "ts": time_str}

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def write_log(ciphertext: str):
    now_cn = datetime.now(ZoneInfo("Asia/Shanghai"))
    ts_str = now_cn.strftime("%Y-%m-%d %H:%M:%S")  
    entry = {"ciphertext": ciphertext, "ts": ts_str}
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def read_logs():
    if not LOG_FILE.exists():
        return []
    out = []
    with LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return out


def ensure_project_logs_file():
    if not PROJECT_LOGS_FILE.exists():
        sample = {
            "ts": datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y:%m:%d %H:%M:%S"),
            "title": "项目创建",
            "content": "初始化 Ciallo Crypto，加密器首页与管理端搭建完成。"
        }
        PROJECT_LOGS_FILE.write_text(json.dumps(sample, ensure_ascii=False) + "\n", encoding="utf-8")

def read_project_logs():
    if not PROJECT_LOGS_FILE.exists():
        ensure_project_logs_file()
    items = []
    with PROJECT_LOGS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    items.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return items


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.get("/")
def index():
    return render_template("index.html", result=None, title="Ciallo Crypto · 加密器")

@app.post("/encrypt")
def encrypt():
    content = request.form.get("content", "")
    if not content:
        flash("请输入需要加密的内容", "warn")
        return redirect(url_for("index"))
    now_cn = datetime.now(ZoneInfo("Asia/Shanghai"))
    ts = now_cn.timestamp()
    ts_str = str(int(ts))

    ciphertext = ciallo_encrypt(content,ts_str)
    write_log(ciphertext)
    return render_template("index.html", result=ciphertext, title="Ciallo Crypto · 加密器")

@app.get("/decrypt")
def decryptor():
    return render_template("decrypt.html", title="Ciallo Crypto · 解密器（开发中）")

@app.get("/logs")
def logs_page():
    items = read_project_logs()
    return render_template("logs.html", items=items, title="Ciallo Crypto · 日志板块")


@app.get("/admin/login")
def admin_login():
    return render_template("login.html", title="Ciallo Crypto · 管理端登录")

@app.post("/admin/login")
def admin_login_post():
    form_user = request.form.get("username", "")
    form_pass = request.form.get("password", "")

    creds = load_creds()
    if form_user == creds.get("username") and form_pass == creds.get("password"):
        session["is_admin"] = True
        flash("欢迎回来，管理员！", "ok")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("admin_dashboard"))
    flash("账号或密码错误", "error")
    return redirect(url_for("admin_login"))

@app.get("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("已退出", "ok")
    return redirect(url_for("admin_login"))


@app.get("/admin")
@admin_required
def admin_dashboard():
    q = request.args.get("q", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(5, min(50, int(request.args.get("per_page", 10))))

    items = read_logs()
    total = len(items)

    if q:
        items = [x for x in items if q.lower() in x.get("ciphertext", "").lower()]

    filtered_total = len(items)

    start = (page - 1) * per_page
    end = start + per_page
    page_items = items[start:end]

    stats = {
        "total": total,
        "filtered": filtered_total,
        "page": page,
        "pages": max(1, (filtered_total + per_page - 1) // per_page),
        "per_page": per_page
    }

    return render_template("admin.html", items=page_items, stats=stats, q=q, title="Ciallo Crypto · 管理面板")

@app.post("/admin/clear")
@admin_required
def admin_clear():
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    flash("已清空历史加密记录", "ok")
    return redirect(url_for("admin_dashboard"))

@app.get("/admin/export.csv")
@admin_required
def admin_export_csv():
    items = read_logs()

    def generate():
        yield "\ufeff"  
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["ciphertext", "ts"])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for it in items:
            writer.writerow([it.get("ciphertext", ""), it.get("ts", "")])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    filename = f"cipher-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        stream_with_context(generate()),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


if __name__ == "__main__":
    preset()
    app.run(host='0.0.0.0', port=5000,use_reloader=False)
