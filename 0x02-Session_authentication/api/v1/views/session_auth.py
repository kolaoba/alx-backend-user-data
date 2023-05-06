#!/usr/bin/env python3
""" Module of Session Auth views that
handles all routes for the Session authentication.
"""
from flask import jsonify, abort, request, session
from api.v1.views import app_views
from models.user import User

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def authenticate() -> str:
    """ 
    authenticates email and password
    """
    user_email = request.form.get('email')
    user_password = request.form.get('password')
    if user_email is None:
        return jsonify({
            "error": "email missing"
        }), 400
    if user_password is None:
        return jsonify({
            "error": "password missing"
        }), 400
    users = User.search({'email': user_email})
    if not users:
        return jsonify({
            "error": "no user found for this email"
        }), 404
    user = users[0]
    if not user.is_valid_password(user_password):
        return jsonify({
            "error": "wrong password"
        }), 401
    # otherwise create a session ID
    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    session[user.id] = session_id
    return user.to_json()
