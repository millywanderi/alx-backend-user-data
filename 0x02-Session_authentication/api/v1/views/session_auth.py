#!/usr/bin/env python3
"""Module to authenticate session views"""
from api.v1.views import app_views
from flask import request, jsonify, abort
from os import getenv
from models.user import User


@app_views.route('/auth_session/login', method=['POST'], strict_slashes=False)
def user_login() -> str:
    """Method that login user"""
    from api.v1.app import auth

    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or len(email) == 0:
        return jsonify({"error": "email missing"}), 400
    if password is None or len(password) == 0:
        return jsonify({"error": "password missing"}), 400

    user = User.search({'email': email})
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    if not user[0].is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user[0].id)

    result = jsonify(user[0].to_json())
    result.set_cookie(hetenv('SESSION_NAME'), session_id)
    return result
