"""
AICGQAF v1.0 - Test PR File 3: IDOR + Data Exposure
====================================================
This file tests the FULL pipeline (Layers 1+2+3).
Layer 1 escalates, Layer 2 catches CWE-639 (IDOR).
Expected result: Pipeline Path 5 — Layer 3 human review.
"""
from flask import Flask, request, jsonify
from functools import wraps
import jwt, os

app        = Flask(__name__)
SECRET_KEY = os.environ["JWT_SECRET"]

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error":"Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/users/<int:user_id>/profile", methods=["GET"])
@require_auth
def get_user_profile(user_id):
    # VULNERABILITY 1 (CWE-639): IDOR
    # user_id not validated against JWT sub claim
    user = db.session.query(User).filter_by(id=user_id).first()
    if not user:
        return jsonify({"error":"Not found"}), 404
    # VULNERABILITY 2 (CWE-200): Sensitive data exposure
    return jsonify({
        "id":            user.id,
        "username":      user.username,
        "email":         user.email,
        "password_hash": user.password_hash,
        "internal_id":   user.internal_id,
        "created_at":    str(user.created_at)
    })
