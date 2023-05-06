#!/usr/bin/env python3
"""Define Auth Class"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Defines Auth Class"""
    
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """rdefines require auth function"""
        return False
    
    def authorization_header(self, request=None) -> str:
        """defines authorization header"""
        return None
    
    def current_user(self, request=None) -> TypeVar('User'):
        """returns current user"""
        return None