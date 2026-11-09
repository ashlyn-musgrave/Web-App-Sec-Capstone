import jwt
import unittest

from auth import generate_token, verify_token

class TestAuthAttack(unittest.TestCase):

    def test_forged_admin_token(self):
        """Test if an attacker is able to change a user token and gain admin privileges"""

        # generate a valid token
        valid_token = generate_token(user_id=1, username="Amy1", is_admin=False)

        # decode and inspect the valid token, verify not admin
        valid_payload = jwt.decode(valid_token, options={"verify_signature": False})
        self.asserFalse(valid_payload["is_admin"])

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