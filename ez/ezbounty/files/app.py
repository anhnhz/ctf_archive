from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import asyncio
import threading
from pyppeteer import launch
import json

app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=False
)


DATABASE = "database.db"

with open("config.json") as f:
    config = json.load(f)

BASE_URL = config["BASE_URL"]
ADMIN_USER = config["ADMIN_USER"]
ADMIN_PASS = config["ADMIN_PASS"]
FLAG = config["FLAG"]

app.secret_key = config["SECRET_KEY"]

# ---------------- DB ----------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        (ADMIN_USER, generate_password_hash(ADMIN_PASS))
    )

    conn.commit()
    conn.close()


# ---------------- BOT ----------------
async def visit_url(url):
    browser = await launch(
        headless=True,  
        autoClose=False,
        executablePath="/usr/bin/google-chrome-stable",
        args=[   
            "--no-sandbox",
            "--ignore-certificate-errors",
            "--disable-setuid-sandbox"
        ],
        ignoreHTTPSErrors=True,
        handleSIGINT=False,
        handleSIGTERM=False,
        handleSIGHUP=False,
    )

    try:
        page = await browser.newPage()
        
        await page.setUserAgent("ctf-bot")

        await page.goto(f"{BASE_URL}/login")
        await page.type('input[name="username"]', ADMIN_USER)
        await page.type('input[name="password"]', ADMIN_PASS)
        await page.click('button[type="submit"]')

        await asyncio.sleep(2)

        await page.setCookie({
            "name": "flag",
            "value": FLAG,  
            "httpOnly": False,
            "sameSite": "None",
            "secure": True
        })
        
        

        await page.goto(url)
        
        await asyncio.sleep(3)

    finally:
        await browser.close()


def run_bot(url):
    asyncio.run(visit_url(url))



@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
        except:
            return "User già esistente"

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")

        return "Credenziali non valide"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html", username=session["username"])


@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        url = request.form.get("url")


        threading.Thread(target=run_bot, args=(url,)).start()

        return "Admin bot is visiting your URL..."

    return render_template("report.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
    

    

# ---------------- MAIN ----------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, ssl_context=('cert.pem', 'key.pem'))
