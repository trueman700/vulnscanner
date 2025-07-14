import unittest
import json
import os
from scanner1 import run_scan  # Import your scan function

class TestPhase1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_target = "127.0.0.1"  # Change to Metasploitable IP if available
        cls.results = run_scan(cls.test_target)
    
    def test_scan_execution(self):
        self.assertIsNotNone(self.results, "Scan returned no results")
    
    def test_output_structure(self):
        with open('scan_results.json') as f:
            data = json.load(f)
        self.assertIn('ip', data[0], "Missing IP in results")
        self.assertIn('ports', data[0], "Missing ports data")

if __name__ == '__main__':
    unittest.main()