#!/usr/bin/env python3
"""Defines Auth"""

from typing import ByteString
import bcrypt


def _hash_password(password: str) -> ByteString:
    """hashes password, returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), salt=bcrypt.gensalt())
