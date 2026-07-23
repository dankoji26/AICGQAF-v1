"""
AICGQAF v1.0 - Test PR File 4: Clean Code
==========================================
This file is secure and well-written.
Expected result: Pipeline Path 1 or 3 — Auto-approved.
"""
from flask import Flask, request, jsonify
import sqlite3, re

app = Flask(__name__)

def validate_search_term(term: str) -> str | None:
    """Validate and sanitise search input."""
    term = term.strip()
    if not term or len(term) > 100:
        return None
    if not re.match(r"^[a-zA-Z0-9\s\-\.]+$", term):
        return None
    return term

@app.route("/api/products/search", methods=["GET"])
def search_products():
    raw  = request.args.get("name", "")
    term = validate_search_term(raw)

    if term is None:
        return jsonify({"error": "Invalid search term"}), 400

    conn   = sqlite3.connect("products.db")
    cursor = conn.cursor()
    # Parameterised query — safe from SQL injection
    cursor.execute(
        "SELECT id, name, price, category FROM products WHERE name LIKE ?",
        (f"%{term}%",)
    )
    rows    = cursor.fetchall()
    conn.close()

    # Return only safe public fields
    products = [
        {"id": r[0], "name": r[1], "price": r[2], "category": r[3]}
        for r in rows
    ]
    return jsonify({"products": products, "count": len(products)})
