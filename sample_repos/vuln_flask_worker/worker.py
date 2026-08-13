"""Sample vulnerable Flask worker service — second repo in the demo fleet.

Deliberately contains a *duplicate* of the SSRF pattern found in
vuln_flask_api/app.py so the Validate stage's cross-repo dedup can be
demonstrated, plus its own unique findings and false-positive traps.
"""
import subprocess
import yaml
from flask import Flask, request
import requests

app = Flask(__name__)


# --- WORKER-SSRF-1 (true positive: SSRF — same class as FLASK-SSRF-1) -------
@app.route("/integrations/fetch")
def fetch_integration_manifest():
    manifest_url = request.args.get("manifest_url")
    # same shape as vuln_flask_api's SSRF: attacker URL, server-side fetch
    resp = requests.get(manifest_url, timeout=5)
    return {"manifest": resp.text[:200]}


# --- WORKER-DESER-1 (true positive: insecure deserialization) ---------------
@app.route("/jobs/import", methods=["POST"])
def import_job_spec():
    raw_yaml = request.get_data(as_text=True)
    # yaml.load without a safe loader can instantiate arbitrary Python objects
    spec = yaml.load(raw_yaml, Loader=yaml.Loader)
    return {"job": spec.get("name")}


# --- WORKER-CMDI-FP-1 (false-positive trap: no shell, fixed argv) ----------
@app.route("/jobs/cleanup")
def cleanup_tmp():
    # subprocess with a fixed argument list and shell=False — nothing here
    # is attacker-influenced and no shell is invoked, so it's not exploitable
    # even though a keyword scanner sees "subprocess" + a path-like string.
    subprocess.run(["rm", "-rf", "/tmp/worker-cache/"], shell=False, check=False)
    return {"status": "cleaned"}


if __name__ == "__main__":
    app.run(port=5001, debug=False)
