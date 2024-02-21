#!/usr/bin/env python3
"""
Module for authentication
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """method that hashes a password"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
