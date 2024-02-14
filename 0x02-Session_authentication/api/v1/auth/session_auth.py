#!/usr/bin/env python3
"""Module: Session Authentic"""
from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """Class that authenticate a session"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """"Method that creates a user_id session"""
        if user_id is None and type(user_id) != str:
            return None
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
