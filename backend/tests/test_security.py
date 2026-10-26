import os

import jwt
import pytest
from fastapi import HTTPException

from app.core import ph, token_for
from app.main import require


def test_password_hashing_uses_argon2_and_is_not_reversible():
    secret = "a-long-test-password"
    hashed = ph.hash(secret)
    assert hashed.startswith("$argon2id$")
    assert ph.verify(hashed, secret)
    assert hashed != secret


def test_role_guard_denies_viewer_and_allows_planner():
    guard = require("Administrator", "Planner")
    with pytest.raises(HTTPException) as denied:
        guard({"role": "Viewer", "email": "viewer@example.invalid"})
    assert denied.value.status_code == 403
    assert guard({"role": "Planner", "email": "planner@example.invalid"})["role"] == "Planner"


def test_signed_token_contains_identity_role_and_expiration():
    encoded = token_for("admin@example.invalid", "Administrator")
    decoded = jwt.decode(encoded, os.getenv("JWT_SECRET", "local-development-secret-change-me"), algorithms=["HS256"])
    assert decoded["sub"] == "admin@example.invalid"
    assert decoded["role"] == "Administrator"
    assert decoded["exp"]
