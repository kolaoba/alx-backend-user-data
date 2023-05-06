#!/usr/bin/env python3
"""Define Auth Class"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Defines Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """defines require auth function"""

        if path is None or excluded_paths is None:
            return True
        if path in excluded_paths or path + '/' in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """defines authorization header"""
        
        # if request is None or 'Authotization' not in request.headers:
        #     return None
        return request.headers.get('Authorization') if request else None
        

    def current_user(self, request=None) -> TypeVar('User'):
        """returns current user"""
        return None
