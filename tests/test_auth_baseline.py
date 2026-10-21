import jwt
from auth import generate_token, verify_token

def test_invalid_token():
    """verify that an invalid token is rejected by the app"""
    # create an invalid token
    token = "not_a_token"

    # verify the token and return result
    check_token = verify_token(token)
    assert check_token is None

def test_token_preserves_username():
    """verify that the JWT properly preserves a username"""
    # generate a token
    token = generate_token(2, "Bob2")

    # verify that the username matches the generated token
    payload = verify_token(token)
    assert payload["username"] == "Bob2"

def test_default_to_not_admin():
    """verify that a new token doesn't have admin priviledges"""
    # generate token
    token = generate_token(3, "Candace3")

    # verify that the token doesn't have admin priviledges
    payload = verify_token(token)
    assert payload["is_admin"] is False

def test_if_jwt_expires():
    """verify that the JWT contains an expiration claim """
    # generate a token
    token = generate_token(1, "Adam1")

    # verify if expiration claim is present (it isn't included in the original repo)
    payload = verify_token(token)
    assert "exp" in payload

