import unittest
from unittest.mock import patch

from app import calculate


class CalculateTests(unittest.TestCase):
    def test_literal_input(self):
        with patch("builtins.input", return_value="{'answer': 42}"):
            self.assertEqual(calculate(), {"answer": 42})
