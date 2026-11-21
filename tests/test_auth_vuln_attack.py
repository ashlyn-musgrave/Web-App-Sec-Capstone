import os
import jwt
import database
import unittest
import requests
import uuid

from auth import verify_token
from tests.helpers.test_accounts import create_test_account, delete_test_account, initialize_database

BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")

class TestAuthAttack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user = create_test_account()
        cls.user_2 = create_test_account()

    @classmethod
    def tearDownClass(cls):
        delete_test_account(cls.user)
        delete_test_account(cls.user_2)

    def test_forged_admin_token(self):
        """Attempts to log in with a forged admin token"""
        # Log in as test user and verify that credentials work
        login_response = requests.post(f"{BASE_URL}/login", 
                                       json={
                                           "username": self.user["username"],
                                           "password": self.user["password"]
                                           },
                                           timeout=10
                                        )
        
        self.assertEqual(login_response.status_code, 200)

        # get legitimate token, confirm it doesn't have admin privileges
        token = login_response.json()["token"]
        payload = jwt.decode(token, options={"verify_signature": False})

        self.assertFalse(payload["is_admin"])

        # confirm that user can't access admin page
        admin_response = requests.get(f"{BASE_URL}/sup3r_s3cr3t_admin", 
                                      headers={
                                          "Authorization": f"Bearer {token}"
                                          },
                                          timeout=10
                                        )
        
        self.assertEqual(admin_response.status_code, 403)

        # create a forged admin token
        payload["is_admin"] = True
        forged_admin_token = jwt.encode(payload, "invalid-key", algorithm="HS256")

        # attempt to access admin page with forged token
        attack_response = requests.get(f"{BASE_URL}/sup3r_s3cr3t_admin",
                                       headers={
                                           "Authorization": f"Bearer {forged_admin_token}"
                                           },
                                           timeout=10
                                    )
        
        self.assertEqual(attack_response.status_code, 401, "Forged admin token not rejected")

    def test_forged_user_id(self):
        """Attempts to log into another user's account"""

        # log in as first user
        login_response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": self.user["username"],
                "password": self.user["password"]
            },
            timeout=10
        )

        self.assertEqual(login_response.status_code, 200)

        # extract the real token
        token = login_response.json()["token"]
        payload = jwt.decode(
            token,
            options={"verify_signature": False}
        )

        # verify token belongs to user
        self.assertEqual(payload["user_id"], self.user["id"])

        # change the user_id to impersonate another user
        payload["user_id"] = self.user_2["id"]
        forged_token = jwt.encode(payload, "invalid-key", algorithm="HS256")

        # attempt to access other user's info
        response = requests.get(
            f"{BASE_URL}/api/v3/user/{self.user_2['id']}",
            headers={
                "Authorization": f"Bearer {forged_token}"
            },
            timeout=10
        )

        # see if forged token is accepted
        self.assertEqual(response.status_code, 401, "Forged user token not rejected")
        
    def test_login_rate_limit(self):
        """Verify that excessive login attempts aren't allowed"""
        login_credentials = {
            "username": self.user["username"],
            "password": "not-the-password"
        }

        # attempts 5 logins
        for _ in range(5):
            response = requests.post(
                f"{BASE_URL}/login",
                json=login_credentials,
                timeout=10
            )

            self.assertEqual(response.status_code, 401)
        response = requests.post(
            f"{BASE_URL}/login",
            json=login_credentials,
            timeout=10
        )

        self.assertEqual(response.status_code, 429, "Too many login attempts allowed")

    def test_unsigned_token(self):
        """Verify that an unsigned token is rejected"""

        unsigned_token = jwt.encode({
            "user_id": 1,
            "username": "Adam1",
            "is_admin": False},
            key=None,
            algorithm="none"
        )

        # attempts to verify token without signature
        result = verify_token(unsigned_token)
        self.assertIsNone(result, "Unsigned token was not rejected")

    def test_weak_passwords(self):
        """Verify that a weak password is rejected when registering a new account"""

        # generate a random username and assign a weak password
        login_credentials = {"username": f"test_{uuid.uuid4().hex[:8]}",
                             "password": "abc"
                            }

        # schedule account cleanup
        self.addCleanup(
            self.cleanup_test_account,
            login_credentials["username"]
        )

        response = requests.post(f"{BASE_URL}/register",
                                 json=login_credentials,
                                 timeout=10
                                )

        self.assertEqual(response.status_code, 400, "Allowed to register with a weak password")

    def cleanup_test_account(self, username):
        """Not part of authentication testing. Deletes test account from database"""

        initialize_database()
        conn = database.get_connection()

        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, username, account_number
                    FROM users
                    WHERE username = %s
                    """,
                    (username,)
                )
                user = cursor.fetchone()

        finally:
            conn.rollback()
            database.return_connection(conn)

        if user:
            account = {
                "id": user[0],
                "username": user[1],
                "account_number": user[2]
            }

            delete_test_account(account)


if __name__ == "__main__":
    unittest.main()