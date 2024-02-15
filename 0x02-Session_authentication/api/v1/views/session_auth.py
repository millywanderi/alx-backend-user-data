#!/usr/bin/env python3
"""Module to authenticate session views"""
from api.v1.views import app_views
from flask import request, jsonify, abort
from os import getenv
from models.user import User
from typing import Tuple


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def user_login() -> Tuple[str, int]:
    """Method that login user"""
    email = request.form.get('email')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get('password')
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400

    try:
        user = User.search({'email': email})
    except Exception as e:
        return jsonify({"error": "no user found for this email"}), 404

    if len(user) <= 0:
        return jsonify({"error": "no user found for this email"}), 404

    if user[0].is_valid_password(password):
        from api.v1.app import auth
        session_id = auth.create_session(getattr(user[0], "id"))
        result = jsonify(user[0].to_json())
        result.set_cookie(getenv('SESSION_NAME'), session_id)
        return result
    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def user_logout() -> str:
    """Method that deletes user session"""
    from api.v1.app import auth
    session_deleted = auth.destroy_session(request)
    if session_deleted:
        return jsonify({}), 200
    abort(404)
