#!/usr/bin/env python3
"""Module: Session Authentic"""
from api.v1.auth.auth import Auth
from models.user import User
import uuid
from flask import request


class SessionAuth(Auth):
    """Class that authenticate a session"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """"Method that creates a user_id session"""
        if isinstance(user_id, str):
            session_id = str(uuid.uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Method that returns a User ID based on a Session ID"""
        if session_id is not None and type(session_id) == str:
            user_id = self.user_id_by_session_id.get(session_id)
            if user_id is not None:
                return user_id
            return None

    def current_user(self, request=None) -> User:
        """Method that returns a User instance based on a cookie value"""
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Method that destroys session's instances"""
        session_id = self.session_cookie(request)
        user = self.user_id_for_session_id(session_id)
        if ((request is None or session_id is None) or user is None):
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
