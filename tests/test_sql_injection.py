import os
import unittest
import requests
from urllib.parse import quote

BASE_URL = "http://localhost:5000"


class TestSQLInjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Loads required test account information from environment variables.
        Skips if required information is not available.
        """

        cls.username = os.getenv("TEST_USERNAME")
        cls.password = os.getenv("TEST_PASSWORD")
        cls.account_number = os.getenv("TEST_ACCOUNT_NUMBER")

        if not all([cls.username, cls.password, cls.account_number]):
            raise unittest.SkipTest(
                "TEST_USERNAME, TEST_PASSWORD, and TEST_ACCOUNT_NUMBER must be set"
            )

    def test_normal_login(self):
        """Verifies legitimate credentials are successful"""
        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": self.username,
                "password": self.password
            },
            timeout=10
        )

        # Credentials should be Accepted
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

    def test_invalid_login(self):
        """Verifies invalid credentials are unsuccessful"""

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": self.username,
                "password": "whatever"
            },
            timeout=10
        )

        # Credentials should be rejected
        self.assertEqual(response.status_code, 401)

    def test_login_sql_injection(self):
        # Verifies authentication bypass is unsuccessful

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "' OR '1'='1' -- ",
                "password": "whatever"
            },
            timeout=10
        )

        # Credentials should be rejected
        self.assertEqual(response.status_code, 401)

    def test_login_single_quote(self):
        """Verifies special character handling"""

        response = requests.post(
            f"{BASE_URL}/login",
            json={
                "username": "'",
                "password": "'"
            },
            timeout=10
        )

        # Server error should not occur
        self.assertNotEqual(response.status_code, 500)

    def test_balance_sql_injection(self):
        """Verifies account number injection is unsuccessful"""

        payload = "' OR '1'='1' -- "
        encoded_payload = quote(payload, safe="")
        response = requests.get(
            f"{BASE_URL}/check_balance/{encoded_payload}",
            timeout=10
        )

        # Incorrect account identifier should not return
        # a customer's account info
        self.assertEqual(response.status_code, 404)

        result = response.json()

        self.assertEqual(result["status"], "error")
        self.assertNotIn("balance", result)
        self.assertNotIn("username", result)

    def test_transaction_sql_injection(self):
        """Verifies transaction history injection is unsuccessful"""

        # Obtain real transactions
        normal_response = requests.get(
            f"{BASE_URL}/transactions/{self.account_number}",
            timeout=10
        )

        # Ensure test account has transactions
        self.assertEqual(normal_response.status_code, 200)

        normal_transactions = normal_response.json()["transactions"]

        self.assertTrue(
            normal_transactions,
            "Test account needs at least one transaction."
        )

        # Attempt injection
        payload = "' OR '1'='1' -- "
        encoded_payload = quote(payload, safe="")

        injected_response = requests.get(
            f"{BASE_URL}/transactions/{encoded_payload}",
            timeout=10
        )

        self.assertEqual(injected_response.status_code, 200)

        injected_transactions = injected_response.json()["transactions"]

        # Obtain unique transaction ids
        normal_ids = {
            transaction["id"]
            for transaction in normal_transactions
        }

        injected_ids = {
            transaction["id"]
            for transaction in injected_transactions
        }

        # Injection should not expose real transactions
        self.assertTrue(
            injected_ids.issubset(normal_ids),
            "SQL Injection exposed transactions outside of the test account."
        )


if __name__ == '__main__':
    unittest.main()
