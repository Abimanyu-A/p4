"""Sample vulnerable Flask API used as a scan target for the SAST engine demo.

Every finding below is labeled in sample_repos/ANSWER_KEY.json.
DO NOT deploy this app anywhere real — it is deliberately insecure.
"""
import os
import pickle
import sqlite3

from flask import Flask, request
import requests

app = Flask(__name__)
DB_PATH = "orders.db"


# --- FLASK-SQLI-1 (true positive: injection) ---------------------------------
@app.route("/orders/search")
def search_orders():
    customer = request.args.get("customer")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # user input concatenated directly into SQL
    query = "SELECT id, item, total FROM orders WHERE customer = '" + customer + "'"
    cur.execute(query)
    return {"rows": cur.fetchall()}


# --- FLASK-CMDI-1 (true positive: injection) ----------------------------------
@app.route("/reports/generate")
def generate_report():
    report_name = request.args.get("name")
    # shells out with untrusted input baked into the command string
    os.system("wkhtmltopdf /tmp/reports/" + report_name + ".html /tmp/out.pdf")
    return {"status": "queued"}


# --- FLASK-DESER-1 (true positive: insecure deserialization) -----------------
@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = request.get_data()
    # untrusted bytes fed straight into pickle
    session = pickle.loads(blob)
    return {"restored": session.get("user")}


# --- FLASK-SSRF-1 (true positive: SSRF, duplicated in vuln_flask_worker) -----
@app.route("/webhooks/preview")
def preview_webhook():
    target_url = request.args.get("url")
    # attacker-controlled URL fetched server-side, no allowlist
    resp = requests.get(target_url, timeout=5)
    return {"status_code": resp.status_code, "body": resp.text[:200]}


# --- FLASK-DESER-FP-1 (false-positive trap: eval on a constant) --------------
@app.route("/config/version")
def version():
    # eval() is flagged by the naive pattern rule, but the argument is a
    # hardcoded literal, not attacker input, so there is nothing to exploit.
    computed = eval("1 + 2 + 3")
    return {"version": f"1.{computed}.0"}


# --- FLASK-SQLI-FP-1 (false-positive trap: string built from constants) -----
@app.route("/health")
def health():
    table = "orders"
    # looks like string-built SQL to a keyword scanner, but every piece is a
    # hardcoded literal — no user input reaches this query.
    query = "SELECT COUNT(*) FROM " + table
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(query)
    return {"count": cur.fetchone()[0]}


if __name__ == "__main__":
    app.run(debug=False)
