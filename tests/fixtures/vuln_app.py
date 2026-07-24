"""Golden-file fixture: every line is a Bandit trip-wire."""
import pickle
import subprocess
import requests

DB_PASSWORD = "hunter2-supersecret"          # B105
API_SECRET = "sk-abcdef1234567890"           # B105

def load_pickle(blob):
    return pickle.loads(blob)                # B301

def call_url(url):
    return requests.get(url, verify=False)   # B501

def shell_out(cmd):
    subprocess.run(cmd, shell=True)          # B602

def query(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = %s" % uid)  # B608

def dynamic_calc(expr):
    return eval(expr)                        # B307

def start():
    app.run(host="0.0.0.0", debug=True)      # B201
