import unittest
from unittest.mock import Mock, patch
from scanners.nexpose_scanner import NexposeScanner

class TestNexposeScanner(unittest.TestCase):
    def setUp(self):
        self.nexpose_mock = Mock()
        self.storage_service_mock = Mock()
        self.nexpose_scanner = NexposeScanner()
        self.nexpose_scanner.nexpose = self.nexpose_mock
        self.nexpose_scanner.storage_service = self.storage_service_mock

    def test_start(self):
        self.nexpose_scanner.start('test_scan', 'http://test_target')
        self.nexpose_mock.start_scan.assert_called_once()

    def test_scan(self):
        self.nexpose_scanner.scan('test_scan', 'http://test_target')
        self.nexpose_mock.start_scan.assert_called_once()

    def test_get_scan_status(self):
        self.nexpose_scanner.get_scan_status('test_scan')
        self.nexpose_mock.get_scan.assert_called_once()

    def test_get_scan_results(self):
        self.nexpose_scanner.get_scan_results('test_scan')
        self.nexpose_mock.download_report.assert_called_once()

    def test_is_valid_scan(self):
        self.nexpose_scanner.is_valid_scan('test_scan')
        self.nexpose_mock.get_scan.assert_called_once()

    def test_pause(self):
        self.nexpose_scanner.pause('test_scan')
        self.nexpose_mock.set_scan_status.assert_called_once_with('pause')

    def test_resume(self):
        self.nexpose_scanner.resume('test_scan')
        self.nexpose_mock.set_scan_status.assert_called_once_with('resume')

    def test_stop(self):
        self.nexpose_scanner.stop('test_scan')
        self.nexpose_mock.set_scan_status.assert_called_once_with('stop')

    def test_remove(self):
        self.nexpose_scanner.remove('test_scan')
        self.nexpose_mock.set_scan_status.assert_called_once_with('remove')

    def test_list_scans(self):
        self.nexpose_scanner.list_scans()
        self.nexpose_mock.get_scans.assert_called_once()

if __name__ == '__main__':
    unittest.main()
