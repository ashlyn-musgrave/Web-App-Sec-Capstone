import random
import database
from database import execute_query


def initialize_database():
    """Initialize database connection pool when needed"""
    if database.connection_pool is None:
        database.init_connection_pool()


def create_test_transactions(account_numbers, count=10):
    """Creates test transactions from a list of test accounts"""

    initialize_database()

    if not account_numbers:
        raise ValueError("At least one test account required")

    transaction_types = ["transfer", "deposit", "withdrawal"]

    for i in range(count):
        from_account = random.choice(account_numbers)
        to_account = random.choice(account_numbers)

        # Avoids transferring to same accounts
        while len(account_numbers) > 1 and to_account == from_account:
            to_account = random.choice(account_numbers)

        amount = round(random.uniform(1.00, 1000.00), 2)
        transaction_type = random.choice(transaction_types)
        description = f"Automated test transaction {i + 1}"

    execute_query(
        """
        INSERT INTO transactions
            (from_account, to_account, amount,
            transaction_type, description)
        Values (%s, %s, %s, %s, %s)
            """,
        (
            from_account,
            to_account,
            amount,
            transaction_type,
            description
        ),
        fetch=False
    )


def delete_test_transactions(account_numbers):
    """Delete transactions associated with test accounts"""

    initialize_database()

    if not account_numbers:
        return

    placeholders = ", ".join(["%s"] * len(account_numbers))

    query = f"""
        DELETE FROM transactions
        WHERE from_account IN ({placeholders})
        OR to_account IN ({placeholders})
    """
    execute_query(
        query,
        tuple(account_numbers) + tuple(account_numbers),
        fetch=False
    )
