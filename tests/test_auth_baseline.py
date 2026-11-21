import jwt
import unittest
from auth import generate_token, verify_token

class Test_Auth(unittest.TestCase):

    def test_empty_token(self):
        """verify that an empty token is rejected by the app"""
        # generate an empty token
        token = ""

        # verify that token is rejected
        payload = verify_token(token)
        self.assertIsNone(payload)

    def test_invalid_token(self):
        """verify that an invalid token is rejected by the app"""
        # create an invalid token
        token = "not_a_token"

        # verify the token and return result
        check_token = verify_token(token)
        self.assertIsNone(check_token)

    def test_token_preserves_username(self):
        """verify that token properly preserves a username"""
        # generate a token
        token = generate_token(1, "Adam1")

        # verify that the username matches the generated token
        payload = verify_token(token)
        self.assertEqual(payload["username"], "Adam1")

    def test_token_preserves_userID(self):
        """verify that token properly preserves userID"""
        # generate a token
        token = generate_token(2, "Bob2")

        # verify user ID matches generated token
        payload = verify_token(token)
        self.assertEqual(payload["user_id"], 2)

    def test_default_to_not_admin(self):
        """verify that a new token doesn't have admin priviledges"""
        # generate token
        token = generate_token(3, "Candace3")

        # verify that the token doesn't have admin priviledges
        payload = verify_token(token)
        self.assertIs(payload["is_admin"], False)

    def test_admin_is_preserved(self):
        """verify that admin privileges are preserved in a token"""
        # generate a token
        token = generate_token(4, "Don4", is_admin=True)

        # verify that token has admin privileges
        payload = verify_token(token)
        self.assertIs(payload["is_admin"], True)

    def test_invalid_signature(self):
        """verify that a token with incorrect key is rejected"""
        # create a valid payload for a token
        payload = {"user_id": 5, "username": "Edward5", "is_admin": False}

        # try to create token with an invalid signature (will fail by default until fix implemented)
        token = jwt.encode(payload, "INVALID_KEY", algorithm="HS256")
        result = verify_token(token)

        self.assertIsNone(result, "This will fail by default until a fix is implemented")

    def test_if_jwt_expires(self):
        """verify that token contains expiration claim"""
        # generate a token
        token = generate_token(6, "Fiona6")

        # verify if expiration claim is present (will fail by default until fix implemented)
        payload = verify_token(token)

        self.assertIn("exp", payload, "This will fail by default until a fix is implemented")

    def test_token_has_issued_time(self):
        """verify that token contains a timestamp of when it was issued"""
        # generate a token
        token = generate_token(7, "Garfield7")

        # verify that token has an issued-at timestamp
        payload = verify_token(token)
        self.assertIn("iat", payload)

def test_forged_admin_token2(self):
        """Test if an attacker is able to change a user token and gain admin privileges"""

        # generate a valid token
        valid_token = generate_token(user_id=1, username="Amy1", is_admin=False)

        # decode and inspect the valid token, verify not admin
        valid_payload = jwt.decode(valid_token, options={"verify_signature": False})
        self.assertFalse(valid_payload["is_admin"])

        # change the token to gain admin privileges
        forged_payload = valid_payload.copy()
        forged_payload["is_admin"] = True
        forged_token = jwt.encode(forged_payload, "attacker-key", algorithm="HS256")

        # submit the forged token to authentication function
        result = verify_token(forged_token)

        # determine whether or not the authentication vulnerability has been fixed
        self.assertIsNotNone(result, "PASS: Forged token was rejected by app")
        self.assertTrue(result["is_admin"], "PASS: Forged admin privileges rejected by app")
        print("FAIL: Forged admin token was accepted")

def test_does_token_expire(self):
    """Verify if a token expires or not"""
    # generate a token
    token = generate_token(user_id=2, username="Ben2", is_admin=False)
    payload = jwt.decode(token, options={"verify_signature": False})

    # verify if expiration is present
    self.assertNotIn("exp", payload)
    result = verify_token(token)
    self.assertIsNotNone(result)

    print("FAIL: Token does not expire")


if __name__ == "__main__":
    unittest.main()