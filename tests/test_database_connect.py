import unittest
from database import init_connection_pool, get_connection


class database_connection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_connection_pool()

    def test_database_connection(self):
        connection = get_connection()

        self.assertIsNotNone(connection)

        connection.close()


if __name__ == '__main__':
    unittest.main()
