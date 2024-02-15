#!/usr/bin/env python3
"""Class auth"""

import re
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Returns false if the path is in included paths"""
        if path is not None and excluded_paths is not None:
            for exclude_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclude_path[-1] == '*':
                    pattern = '{}.*'.format(exclude_path[0:-1])
                elif exclude_path[-1] == '/':
                    pattern = '{}/*'.format(exclude_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclude_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """validate all requests to secure the API"""
        if request is not None:
            dic_key = request.headers.get('Authorization')
            if dic_key is not None:
                return dic_key
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user method"""
        return None

    def session_cookie(self, request=None):
        """method that returns a cookie value from a request"""
        if request is not None:
            session_name = getenv('SESSION_NAME')
            cookie = request.cookies.get(session_name)
            return cookie
