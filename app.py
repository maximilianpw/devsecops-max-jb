import os
from contextlib import closing

import psycopg2
from flask import Flask, jsonify

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "testdb")
DB_USER = os.getenv("DB_USER", "testuser")


def read_db_password():
    """Prefer a mounted secret file (DB_PASSWORD_FILE) over DB_PASSWORD."""
    secret_file = os.getenv("DB_PASSWORD_FILE")
    if secret_file:
        # A missing or unreadable file fails at startup, not as an opaque 500.
        with open(secret_file, encoding="utf-8") as fh:
            return fh.read().rstrip("\r\n")
    return os.getenv("DB_PASSWORD")


DB_PASSWORD = read_db_password()
DB_CONNECT_TIMEOUT = 5


@app.route("/health")
def health_check():
    return jsonify({"status": "ok"})


@app.route("/hello")
def hello():
    return jsonify({"message": "Hello world"})


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        connect_timeout=DB_CONNECT_TIMEOUT,
    )


@app.route("/dbtest")
def db_test():
    try:
        # psycopg2's own context managers only end the transaction; closing()
        # guarantees the cursor and connection are released on every path.
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
    except psycopg2.Error:
        # Connection details stay in the server log, never in the response.
        app.logger.exception("Database connectivity check failed")
        return jsonify({"db_connection": "failed"}), 500

    if result == (1,):
        return jsonify({"db_connection": "successful"})
    return jsonify({"db_connection": "failed"}), 500
