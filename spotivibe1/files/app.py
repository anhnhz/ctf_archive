from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import json
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import asyncio
import threading
from pyppeteer import launch
from urllib.parse import urlparse, unquote

with open("config.json") as f:
    config = json.load(f)

FLAG = config["FLAG"]
ADMIN_USER = config["ADMIN_USER"]
ADMIN_PASS = config["ADMIN_PASS"]
BASE_URL = config["BASE_URL"]

app = Flask(__name__)
app.secret_key = config["SECRET_KEY"]

DATABASE = "database.db"


async def visit_song(song_id):

    browser = await launch(
    headless=True,
    autoClose=False,
    args=[
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-setuid-sandbox"
    ],
    handleSIGINT=False,
    handleSIGTERM=False,
    handleSIGHUP=False
)

    page = await browser.newPage()

    await page.goto(f"{BASE_URL}/login")

    await page.type('input[name="username"]', ADMIN_USER)
    await page.type('input[name="password"]', ADMIN_PASS)

    await page.click('button[type="submit"]')

    await asyncio.sleep(2)


    await page.setCookie({
        "name": "flag",
        "value": FLAG,
        "path": "/",
        "httpOnly": False
    })


    await page.goto(f"{BASE_URL}/song/{song_id}")

    await asyncio.sleep(3)

    await browser.close()
    
def run_bot(song_id):
    asyncio.run(visit_song(song_id))

def is_valid_spotify_url(url):
    try:
        decoded = unquote(url)
        parsed = urlparse(decoded)

        if parsed.hostname != "open.spotify.com":
            return False

        if not parsed.path.startswith("/embed/"):
            return False

        if '"' in decoded:
            return False

        return True

    except:
        return False

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS songs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            spotify_url TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        (ADMIN_USER, generate_password_hash(ADMIN_PASS))
    )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = get_db()

        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            conn.commit()
        except:
            return "User already exists"

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

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

            return redirect(url_for("dashboard"))

        return "Invalid credentials"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "")

    conn = get_db()

    if search:
        songs = conn.execute(
            "SELECT * FROM songs WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], f"%{search}%")
        ).fetchall()
    else:
        songs = conn.execute(
            "SELECT * FROM songs WHERE user_id = ?",
            (session["user_id"],)
        ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        songs=songs,
        search=search
    )


@app.route("/add_song", methods=["GET", "POST"])
def add_song():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        title = request.form["title"]
        spotify_url = request.form["spotify_url"]

        if not is_valid_spotify_url(spotify_url):
            return "Invalid host"

        conn = get_db()

        conn.execute(
            "INSERT INTO songs (user_id, title, spotify_url) VALUES (?, ?, ?)",
            (session["user_id"], title, spotify_url)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    return render_template("add_song.html")
    
    
@app.route("/song/<int:song_id>")
def song(song_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    if session.get("username") == ADMIN_USER:
        song = conn.execute(
            "SELECT * FROM songs WHERE id = ?",
            (song_id,)
        ).fetchone()

    else:
        song = conn.execute(
            "SELECT * FROM songs WHERE id = ? AND user_id = ?",
            (song_id, session["user_id"])
        ).fetchone()

    conn.close()

    if not song:
        return "Song not found", 404

    return render_template("song.html", song=song)
    
@app.route("/report", methods=["GET", "POST"])
def report():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        song_id = request.form.get("song_id")

        
        try:
            song_id = int(song_id)
        except:
            return "Invalid ID"

        conn = get_db()

        
        song = conn.execute(
            "SELECT id FROM songs WHERE id = ? AND user_id = ?",
            (song_id, session["user_id"])
        ).fetchone()

        conn.close()

        if not song:
            return "Song not found"

        threading.Thread(target=run_bot, args=(song_id,)).start()

        return "Admin bot will review the page."

    return render_template("report.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()   
    app.run(host="0.0.0.0", port=5000)
