#!/usr/bin/env python3
"""
Hashing passwords with bcrypt
"""
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB, User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """hashes password, returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), salt=bcrypt.gensalt())


def _generate_uuid() -> str:
    """generates a uuid"""
    return str(uuid4())


class Auth:
    """Auth class, interact with authentication database"""

    def __init__(self) -> None:
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """registers a user"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """checks if password matches the hashed password"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                validate_pw = bcrypt.checkpw(password.encode("utf-8"),
                                             user.hashed_password)
                return validate_pw
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Create session """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        gen_session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=gen_session_id)
        return gen_session_id

    def get_user_from_session_id(self, session_id) -> User:
        """get user from session_id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """destroys current session"""
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """resets password token"""
        if email is None:
            return None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """update user password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError
        new_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=new_password,
                             reset_token=None)
        return None
