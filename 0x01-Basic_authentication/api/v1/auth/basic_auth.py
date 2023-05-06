#!/usr/bin/env python3
"""
BasicAuth that inherits from Auth
"""

from api.v1.auth.auth import Auth
import base64
import binascii
from models.user import User
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """class inherits from auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns Base64 part of the Authorization header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns decoded value of Base64 string"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded = base64.b64decode(base64_authorization_header)
            return decoded.decode('utf-8')
        except binascii.Error:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """returns user email and password from Base64 decoded value"""
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        usr_creds = decoded_base64_authorization_header.split(':')
        return usr_creds[0], usr_creds[1]

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on email and password"""
        if not isinstance(user_email, str):
            return None
        if not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        if len(users) == 0:
            return None

        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user
