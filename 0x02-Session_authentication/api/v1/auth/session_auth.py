#!/usr/bin/env python3
"""
SessionAuth that inherits from Auth
"""
from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """Class inherits from Auth"""
    user_id_by_session_id = dict()

    def create_session(self, user_id: str = None) -> str:
        """creates a session for a user_id
        generates and returns session_id
        """
        if user_id is None:
            return None
        if not isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id
