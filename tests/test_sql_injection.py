import os
import unittest
import requests
from urllib.parse import quote
from auth import generate_token
from tests.helpers.test_accounts import (
    create_test_accounts,
    delete_test_accounts
)
from tests.helpers.test_transactions import (
    create_test_transactions,
    delete_test_transactions
)

BASE_URL = "http://localhost:5000"


class TestSQLInjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Creates required test account information with helper functions.
        Skips if required information is not created successfully.
        """

        # Create test account
        cls.accounts = create_test_accounts(1)
        cls.transaction_ids = []

        cls.username = cls.accounts[0]["username"]
        cls.password = cls.accounts[0]["password"]
        cls.account_number = cls.accounts[0]["account_number"]

        cls.token = generate_token(
            cls.accounts[0]["id"],
            cls.username
        )

        cls.headers = {
            "Authorization": f"Bearer {cls.token}"
        }

        if not all([cls.username, cls.password, cls.account_number]):
            raise unittest.SkipTest(
                "TEST_USERNAME, TEST_PASSWORD, and TEST_ACCOUNT_NUMBER must be set"
            )

        # Creates a list variable for account_number
        cls.account_numbers = [cls.account_number]

        # Create test transactions for test account
        cls.transaction_ids = create_test_transactions(cls.account_numbers)

    @classmethod
    def tearDownClass(cls) -> None:
        """Delete test accounts and transactions after testing is complete"""

        if cls.transaction_ids:
            delete_test_transactions(cls.account_numbers)
        if hasattr(cls, "accounts"):
            delete_test_accounts(cls.accounts)

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
        """Verifies special character (single quotes) handling"""

        test_cases = [
            {
                "username": "'",
                "password": self.password
            },
            {
                "username": self.username,
                "password": "'"
            }
        ]

        for credentials in test_cases:
            with self.subTest(credentials=credentials):
                response = requests.post(
                    f"{BASE_URL}/login",
                    json=credentials,
                    timeout=10
                )

                # Malformed credentials should not cause a server error
                # or successfully authenticate.
                self.assertIn(
                    response.status_code,
                    [400, 401, 422],
                    f"Unexpected response to single-quote input: "
                    f"{response.status_code} - {response.text}"
                )

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

        # Injection should not return any transaction data
        self.assertEqual(
            injected_transactions, [],
            "SQL Injection returned transaction data."
        )

    def test_transaction_union_sql_injection(self):
        """Verifies UNION-based injection
        cannot retrieve transaction records"""

        # Attempt to retrieve all transactions
        payload = (
            "x' UNION SELECT id, from_account, to_account, "
            "amount, timestamp, transaction_type, description "
            "FROM transactions -- "
        )

        encoded_payload = quote(payload, safe="")

        response = requests.get(
            f"{BASE_URL}/transactions/{encoded_payload}",
            timeout=10
        )

        # Injection should not expose transaction data
        self.assertEqual(response.status_code, 200)

        result = response.json()

        self.assertEqual(
            result["transactions"],
            [],
            "UNION-based SQL injection exposed transaction records."
        )

    def test_biller_id_numeric_sql_injection(self):
        """Verifies numeric SQL injection cannot manipulate biller lookup"""

        # Capture original account balance
        balance_response = requests.get(
            f"{BASE_URL}/check_balance/{self.account_number}",
            timeout=10
        )

        self.assertEqual(balance_response.status_code, 200)
        original_balance = balance_response.json()["balance"]

        # Capture original transaction IDs
        transaction_response = requests.get(
            f"{BASE_URL}/transactions/{self.account_number}",
            timeout=10
        )

        self.assertEqual(transaction_response.status_code, 200)

        original_ids = {
            transaction["id"]
            for transaction in transaction_response.json()["transactions"]
        }

        # Attempt numeric SQL injection
        response = requests.post(
            f"{BASE_URL}/api/bill-payments/create",
            headers=self.headers,
            json={
                "biller_id": "1 OR 1=1",
                "amount": 1.00,
                "payment_method": "balance"
            },
            timeout=10
        )

        # Malicious biller identifier should be rejected
        self.assertIn(
            response.status_code,
            [400, 404, 422],
            "Numeric SQL injection was not properly rejected"
        )

        # Verifies account balance remains unchanged
        updated_balance = requests.get(
            f"{BASE_URL}/check_balance/{self.account_number}",
            timeout=10
        ).json()["balance"]

        self.assertEqual(
            updated_balance,
            original_balance,
            "SQL injection modified the test account balance."
        )

        # Verify no addtional transactions were created
        updated_transactions = requests.get(
            f"{BASE_URL}/transactions/{self.account_number}",
            timeout=10
        ).json()["transactions"]

        updated_ids = {
            transaction["id"]
            for transaction in updated_transactions
        }

        self.assertEqual(
            updated_ids,
            original_ids,
            "SQL injection created unauthorized transactions."
        )

    def test_transfer_sql_injection(self):
        """Verifies malicious input cannot manipulate bank transfers"""

        # Capture original account balance
        balance_response = requests.get(
            f"{BASE_URL}/check_balance/{self.account_number}",
            timeout=10
        )

        self.assertEqual(balance_response.status_code, 200)

        original_balance = balance_response.json()["balance"]

        # Capture original transaction IDs
        transaction_response = requests.get(
            f"{BASE_URL}/transactions/{self.account_number}",
            timeout=10
        )

        self.assertEqual(transaction_response.status_code, 200)

        original_ids = {
            transaction["id"]
            for transaction in transaction_response.json()["transactions"]
        }

        # Attempt SQL injection through destination account
        payload = "' OR '1'='1' -- "

        response = requests.post(
            f"{BASE_URL}/transfer",
            headers=self.headers,
            json={
                "to_account": payload,
                "amount": 1.00,
                "description": "SQL inejction test"
            },
            timeout=10
        )

        # Malicious destination should be rejected
        self.assertIn(
            response.status_code,
            [400, 404, 422],
            "SQL injection resulted in an unsuccessful/unexpected response."
        )

        # Verify sender balance remains unchanged
        updated_balance = requests.get(
            f"{BASE_URL}/check_balance/{self.account_number}",
            timeout=10
        ).json()["balance"]

        self.assertEqual(
            updated_balance,
            original_balance,
            "SQL injection modified the sender's account balance."
        )

        # Verify no additional transactions were created
        updated_transactions = requests.get(
            f"{BASE_URL}/transactions/{self.account_number}",
            timeout=10
        ).json()["transactions"]

        updated_ids = {
            transaction["id"]
            for transaction in updated_transactions
        }

        self.assertEqual(
            updated_ids,
            original_ids,
            "SQL injection created an unauthorized transaction."
        )


if __name__ == '__main__':
    unittest.main()
