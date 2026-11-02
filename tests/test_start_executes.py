import unittest
import os
from pathlib import Path


class test_start(unittest.TestCase):

    def test_start_is_executable(self):
        # Create variable for root path
        project_root = Path(__file__).resolve().parent.parent
        # Create variable for start.sh file
        start = project_root / "start.sh"

        # Verify Start is executable
        self.assertTrue(os.access(start, os.X_OK))


if __name__ == "__main__":
    unittest.main()
