import unittest

class TestInit(unittest.TestCase):

    def test_import(self):
        try:
            import core
            import scanners
        except ImportError:
            self.fail("Failed to import core or scanners module")

    def test_initialization(self):
        try:
            from core import storage_service
            from scanners import zap_scanner, nexpose_scanner, openvas_scanner
        except ImportError:
            self.fail("Failed to initialize core or scanners module")

if __name__ == '__main__':
    unittest.main()
