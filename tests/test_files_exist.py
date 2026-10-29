import unittest
from pathlib import Path


class test_files_exist(unittest.TestCase):

    def test_required_files(self):
        # Create variable for root path
        project_root = Path(__file__).resolve().parent.parent

        # Create variables for each file that will be tested
        app = project_root / "app.py"
        database = project_root / "database.py"
        start = project_root / "start.sh"
        env = project_root / ".env.example"

        # Verifies files exist
        self.assertTrue(app.is_file())
        self.assertTrue(database.is_file())
        self.assertTrue(start.is_file())
        self.assertTrue(env.is_file())


if __name__ == "__main__":
    unittest.main()
