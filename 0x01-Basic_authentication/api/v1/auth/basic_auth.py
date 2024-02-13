#!/usr/bin/env python3
"""Module for basic authentication"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar, Tuple
import re
from models.base import DATA
from models.user import User
import uuid
import hashlib


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

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """returns the decoded value of a Base64 string"""
        base64_header = base64_authorization_header
        if base64_header is not None and type(base64_header) == str:
            try:
                base64_bytes = base64_header.encode('ascii')
                message_bytes = base64.b64decode(base64_bytes)
                return message_bytes.decode('ascii')
            except Exception:
                pass
        return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """returns the user email and password from the
        Base64 decoded value
        """
        decoded_base = decoded_base64_authorization_header
        if decoded_base is not None and type(decoded_base) == str:
            if ':' in decoded_base:
                email = re.match('(.+):', decoded_base)[1]
                password = re.match('.+:(.+)', decoded_base)[1]
                return (email, password)
        return(None, None)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password"""
        if user_email is not None or type(user_email) != str or \
                user_pwd is None or type(user_pwd) != str:
            return None

        try:
            for user in User.search({'email': user_email}):
                if user.is_valid_password(user_pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request"""
        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        email, pwrd = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(email, pwrd)
