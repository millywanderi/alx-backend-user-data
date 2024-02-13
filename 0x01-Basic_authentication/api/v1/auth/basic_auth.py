#!/usr/bin/env python3
"""Module for basic authentication"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar, Tuple


class BasicAuth(Auth):
    """Class for basic authentication"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header for a
        Basic Authentication
        """
        auth_header = authorization_header
        if auth_header is not None and type(auth_header) == str:
            if auth_header.startswith("Basic"):
                return auth_header[6:]
        return None
