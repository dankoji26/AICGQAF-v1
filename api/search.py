"""
AICGQAF v1.0 - Test PR File 1: SQL Injection
============================================
This file is intentionally vulnerable for testing the pipeline.
Expected result: Layer 1 FAIL — CWE-89 auto-rejected.
"""
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/api/users/search", methods=["GET"])
def search_users():
    # VULNERABILITY: SQL Injection (CWE-89)
    # AI-generated code missing parameterised queries
    username = request.args.get("username", "")
    conn     = sqlite3.connect("users.db")
    cursor   = conn.cursor()
    query    = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results  = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})

if __name__ == "__main__":
    app.run(debug=True)
