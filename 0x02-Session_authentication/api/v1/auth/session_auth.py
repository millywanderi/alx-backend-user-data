#!/usr/bin/env python3
"""Module: Session Authentic"""
from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """Class that authenticate a session"""
