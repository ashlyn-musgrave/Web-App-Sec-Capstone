import jwt
import unittest
import requests

from auth import generate_token, verify_token

# *** import function that creates a new user here ***

BASE_URL = "http://localhost:5000"

class TestAuthAttack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # need to use function to create/tear down a new user once it's written
        cls.user = {"username": "Adam1", "password": "password1", "is_admin": False}

    def test_forged_admin_token(self):
        # Log in as test user and verify that credentials work
        login_response = requests.post(f"{BASE_URL}/login", 
                                       json={"username": self.user["username"],
                                             "password": self.user["password"]},
                                             timeout=10)
        self.assertEqual(login_response.status_code, 200)

        # get legitimate token, confirm it doesn't have admin privileges
        token = login_response.json()["token"]
        payload = jwt.decode(token, options={"verify_signature": False})

        self.assertFalse(payload["is_admin"])

        # confirm that user can't access admin page
        admin_response = requests.get(f"{BASE_URL}/sup3r_s3cr3t_admin", 
                                      headers={"Authorization": f"Bearer {token}"},
                                      timeout=10)
        self.assertEqual(admin_response.status_code, 403)

        # create a forged admin token
        payload["is_admin"] = True
        forged_admin_token = jwt.encode(payload, "invalid-key", algorithm="HS256")

        # attempt to access admin page with forged token
        attack_response = requests.get(f"{BASE_URL}/sup3r_s3cr3t_admin",
                                       headers={"Authorization": f"Bearer {forged_admin_token}"},
                                       timeout=10)
        self.assertEqual(attack_response.status_code, 200, "Forged admin token rejected")

if __name__ == "__main__":
    unittest.main()