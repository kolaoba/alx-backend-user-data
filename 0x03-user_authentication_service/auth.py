#!/usr/bin/env python3
"""Defines Auth"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """hashes password, returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), salt=bcrypt.gensalt())
