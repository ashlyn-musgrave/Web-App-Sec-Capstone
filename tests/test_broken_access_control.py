
import unittest

# Imports for BAC-01
from app import app
from auth import generate_token

# Imports for BAC-02
import jwt
from auth import generate_token, verify_token

from tests.helpers.test_accounts import (
    create_test_accounts,
    delete_test_accounts
)


class TestBrokenAccessControl(unittest.TestCase):
    """Security tests for VulnBank access controls."""

    def setUp(self):
        """Create two temporary customer accounts."""
        self.accounts = create_test_accounts(2)
        self.customer_a = self.accounts[0]
        self.customer_b = self.accounts[1]

    def tearDown(self):
        """Remove temporary test accounts."""
        if hasattr(self, "accounts"):
            delete_test_accounts(self.accounts)

    
    def test_bac_01_idor(self):
        """Customer A must not access Customer B's records."""

        # Generate a legitimate JWT for Customer A
        token = generate_token(
            user_id=self.customer_a["id"],
            username=self.customer_a["username"],
            is_admin=False
        )

        # Create Flask test client
        client = app.test_client()
        headers = {
            "Authorization": f"Bearer {token}"
        }

        # Test 1: Customer A accesses their own records
        own_response = client.get(
            f"/api/v3/user/{self.customer_a['id']}",
            headers=headers
        )

        print(
            "Customer A response:",
            own_response.status_code
        )

        self.assertEqual(
            own_response.status_code,
            200,
            "Customer A should access their own records"
        )

        # Test 2: Customer A attempts to access Customer B
        other_response = client.get(
            f"/api/v3/user/{self.customer_b['id']}",
            headers=headers
        )

        print(
            "Customer B response:",
            other_response.status_code
        )
        print(
            "Customer B response body:",
            other_response.get_json()
        )

        # Secure applications should deny unauthorized access
        self.assertIn(
            other_response.status_code,
            (403, 404),
            "BAC-01 FAILED: Customer A accessed "
            "Customer B's information"
        )


    
    def test_bac_02_vertical_privilege_escalation(self):
        """Reject a forged JWT claiming administrator privileges."""

        # Generate a legitimate token for Customer A
        valid_token = generate_token(
            user_id=self.customer_a["id"],
            username=self.customer_a["username"],
            is_admin=False
        )

        # Decode the token to inspect its original claims
        original_payload = jwt.decode(
            valid_token,
            options={"verify_signature": False},
            algorithms=["HS256"]
        )

        # Confirm Customer A starts as a regular user
        self.assertFalse(original_payload["is_admin"])

        # Modify the payload to claim administrator privileges
        forged_payload = original_payload.copy()
        forged_payload["is_admin"] = True

        # Sign with a key that is NOT the application's secret
        forged_token = jwt.encode(
            forged_payload,
            "attacker-controlled-test-key",
            algorithm="HS256"
        )

        # Submit the forged token to VulnBank's verification function
        result = verify_token(forged_token)

        print("Original admin status:", original_payload["is_admin"])
        print("Forged admin status:", forged_payload["is_admin"])
        print("Verification result:", result)

        # Secure verification must reject the forged token
        self.assertIsNone(
            result,
            "BAC-02 FAILED: VulnBank accepted a forged "
            "JWT containing administrator privileges"
        )


    
    def test_bac_03_horizontal_privilege_escalation(self):
        """Customer A must not modify Customer B's virtual card."""

        from app import app
        from auth import generate_token
        from database import execute_query

        client = app.test_client()

        # Generate legitimate tokens for both customers
        token_a = generate_token(
            self.customer_a["id"],
            self.customer_a["username"],
            False
        )

        token_b = generate_token(
            self.customer_b["id"],
            self.customer_b["username"],
            False
        )

        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        card_id = None

        try:
            # Customer B creates their own virtual card
            create_response = client.post(
                "/api/virtual-cards/create",
                headers=headers_b,
                json={
                    "card_limit": 1000,
                    "card_type": "standard"
                }
            )

            self.assertEqual(
                create_response.status_code,
                200,
                f"Card creation failed: {create_response.get_json()}"
            )

            card_id = create_response.get_json()["card_details"]["id"]

            # Verify Customer B owns the card
            ownership = execute_query(
                "SELECT user_id FROM virtual_cards "
                f"WHERE id = {int(card_id)}"
            )

            self.assertEqual(
                ownership[0][0],
                self.customer_b["id"]
            )

            # Record the card's original freeze status
            before = execute_query(
                "SELECT is_frozen FROM virtual_cards "
                f"WHERE id = {int(card_id)}"
            )

            original_status = before[0][0]

            # Customer A attempts to modify Customer B's card
            response = client.post(
                f"/api/virtual-cards/{card_id}/toggle-freeze",
                headers=headers_a
            )

            # Check whether the card actually changed
            after = execute_query(
                "SELECT is_frozen FROM virtual_cards "
                f"WHERE id = {int(card_id)}"
            )

            final_status = after[0][0]

            print("\nBAC-03: Horizontal Privilege Escalation")
            print("Customer B's card ID:", card_id)
            print("Original freeze status:", original_status)
            print("HTTP response:", response.status_code)
            print("Final freeze status:", final_status)

            # Secure application must reject unauthorized changes
            self.assertIn(
                response.status_code,
                (403, 404),
                "BAC-03 FAILED: Unauthorized card modification "
                "request was accepted."
            )

            self.assertEqual(
                original_status,
                final_status,
                "BAC-03 FAILED: Customer A modified "
                "Customer B's virtual card."
            )

        finally:
            # Remove only the card created by this test
            if card_id is not None:
                execute_query(
                    "DELETE FROM virtual_cards "
                    f"WHERE id = {int(card_id)} "
                    f"AND user_id = {int(self.customer_b['id'])} "
                    "RETURNING id"
                )



    def test_bac_04_function_level_access_control(self):
        """Restricted functions must enforce authorization."""
        pass

    def test_bac_05_forced_browsing(self):
        """Restricted pages must reject unauthorized access."""
        pass

    def test_bac_06_parameter_tampering(self):
        """User-controlled parameters must not grant privileges."""
        pass


if __name__ == "__main__":
    unittest.main()
