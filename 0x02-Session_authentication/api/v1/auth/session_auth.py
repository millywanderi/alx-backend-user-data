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
        if user_id is None and user_id != str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id
