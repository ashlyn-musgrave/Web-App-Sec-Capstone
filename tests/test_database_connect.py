import unittest
from database import init_connection_pool, get_connection


class database_connection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initializes database connection
        init_connection_pool()

    def test_database_connection(self):
        # Create variable for database connection status
        connection = get_connection()

        # Verifies that connection status is not None
        self.assertIsNotNone(connection)

        connection.close()


if __name__ == '__main__':
    unittest.main()
