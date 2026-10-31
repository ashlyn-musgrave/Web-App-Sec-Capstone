
import os
import pytest
import requests

BASE_URL = os.getenv("VULNBANK_URL", "http://localhost:5000")

# Use two test accounts that you control.
USER_A_ACCOUNT = os.getenv("USER_A_ACCOUNT")
USER_B_ACCOUNT = os.getenv("USER_B_ACCOUNT")
USER_B_ID = os.getenv("USER_B_ID")

# Session cookie obtained by logging in as User A.
SESSION_COOKIE = os.getenv("USER_A_SESSION")

DENIED = {401, 403, 404}


@pytest.fixture
def user_a():
    """Create a session authenticated as User A."""
    if not SESSION_COOKIE:
        pytest.skip("Set USER_A_SESSION first")

    session = requests.Session()
    session.cookies.set("session", SESSION_COOKIE)
    yield session
    session.close()


def get(session, endpoint):
    """Send a GET request to VulnBank."""
    return session.get(
        f"{BASE_URL}{endpoint}",
        timeout=10,
        allow_redirects=False
    )


# BAC-01: Insecure Direct Object Reference
def test_unauthorized_account_balance(user_a):
    """User A should not access User B's balance."""
    if not USER_B_ACCOUNT:
        pytest.skip("Set USER_B_ACCOUNT first")

    response = get(
        user_a,
        f"/check_balance/{USER_B_ACCOUNT}"
    )

    assert response.status_code in DENIED, (
        f"Possible BAC: account balance returned "
        f"HTTP {response.status_code}"
    )


# BAC-02: Unauthorized transaction history
def test_unauthorized_transactions(user_a):
    """User A should not access User B's transactions."""
    if not USER_B_ACCOUNT:
        pytest.skip("Set USER_B_ACCOUNT first")

    response = get(
        user_a,
        f"/transactions/{USER_B_ACCOUNT}"
    )

    assert response.status_code in DENIED, (
        f"Possible BAC: transaction history returned "
        f"HTTP {response.status_code}"
    )


# BAC-03: Horizontal privilege escalation
def test_unauthorized_user_information(user_a):
    """User A should not retrieve User B's private data."""
    if not USER_B_ID:
        pytest.skip("Set USER_B_ID first")

    response = get(
        user_a,
        f"/api/v3/user/{USER_B_ID}"
    )

    assert response.status_code in DENIED, (
        f"Possible BAC: user information returned "
        f"HTTP {response.status_code}"
    )


# BAC-04: Vertical privilege escalation
def test_regular_user_admin_access(user_a):
    """Regular users should not access the admin page."""
    response = get(
        user_a,
        "/sup3r_s3cr3t_admin"
    )

    assert response.status_code in DENIED, (
        f"Possible BAC: admin page returned "
        f"HTTP {response.status_code}"
    )


# BAC-05: Unauthenticated administrative action
def test_unauthenticated_account_deletion():
    """Anonymous visitors must not delete accounts."""
    # Use an intentionally invalid ID, not a real user.
    invalid_user_id = 999999999

    response = requests.post(
        f"{BASE_URL}/admin/delete_account/{invalid_user_id}",
        timeout=10,
        allow_redirects=False
    )

    assert response.status_code in DENIED, (
        f"Review authorization: deletion endpoint "
        f"returned HTTP {response.status_code}"
    )
