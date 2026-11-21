import secrets
import database

DEFAULT_PASSWORD = "Whatever123!"


def initialize_database():
    """Initialize database connection pool when needed"""
    if database.connection_pool is None:
        database.init_connection_pool()


def create_test_account(password=DEFAULT_PASSWORD):
    """Creates temporary bank user and account

    Returns Dict containing user ID, name, password, and account number"""

    initialize_database()

    # Generates unique test credentials
    unique_id = secrets.token_hex(6)

    username = f"test_{unique_id}"
    account_number = f"9{secrets.randbelow(10**9):09d}"

    conn = database.get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (
                username,
                password,
                account_number
                )
                VALUES(%s, %s, %s)
                RETURNING id, username, account_number
                """,
                (username, password, account_number)
            )

            user = cursor.fetchone()
            conn.commit()

            return {
                "id": user[0],
                "username": user[1],
                "password": password,
                "account_number": user[2]
            }

    except Exception:
        conn.rollback()
        raise

    finally:
        database.return_connection(conn)


def delete_test_account(account):
    """Delete a test account and associated attributes"""

    if not account:
        return

    # Prevent accidental deletion of non-test accounts
    if not account["username"].startswith("test_"):
        raise ValueError("Deletion of a non-test account is"
                     "prohibited in test environment.")

    initialize_database()

    conn = database.get_connection()

    try:
        with conn.cursor() as cursor:

            # Remove transactions linked to this account
            cursor.execute(
                """
                DELETE FROM transactions
                WHERE from_account = %s
                OR to_account = %s
                """,
                (
                    account["account_number"],
                    account["account_number"]
                )
            )

            # Delete user and related attributes
            cursor.execute(
                """
                DELETE FROM users
                WHERE id = %s AND username = %s
                """,
                (
                    account["id"],
                    account["username"]
                )
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        database.return_connection(conn)


def create_test_accounts(count=1):
    """Creates multiple test accounts

    Returns list of test accounts"""

    accounts = []

    try:
        for i in range(count):
            accounts.append(create_test_account())

        return accounts

    except Exception:
        # Clean up any accounts created before an error
        for account in accounts:
            delete_test_account(account)

        raise


def delete_test_accounts(accounts):
    """Delete list of test accounts"""

    for account in accounts:
        delete_test_account(account)
