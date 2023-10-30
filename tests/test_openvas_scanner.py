import unittest
from unittest.mock import Mock, patch
from scanners.openvas_scanner import OpenVASScanner

class TestOpenVASScanner(unittest.TestCase):
    def setUp(self):
        self.openvas_mock = Mock()
        self.storage_service_mock = Mock()
        self.openvas_scanner = OpenVASScanner()
        self.openvas_scanner.openvas = self.openvas_mock
        self.openvas_scanner.storage_service = self.storage_service_mock

    def test_start(self):
        self.openvas_scanner.start('test_scan', 'http://test_target')
        self.openvas_mock.start_scan.assert_called_once()

    def test_scan(self):
        self.openvas_scanner.scan('test_scan', 'http://test_target')
        self.openvas_mock.start_scan.assert_called_once()

    def test_create_report(self):
        self.openvas_scanner._create_report('test_scan')
        self.openvas_mock.get_report.assert_called_once()

    def test_get_scan_status(self):
        self.openvas_scanner.get_scan_status('test_scan')
        self.openvas_mock.get_scan.assert_called_once()

    def test_get_scan_results(self):
        self.openvas_scanner.get_scan_results('test_scan')
        self.openvas_mock.get_report.assert_called_once()

    def test_process_results(self):
        self.openvas_scanner._process_results('test_report', {})
        self.openvas_mock.parse.assert_called_once()

    def test_is_valid_scan(self):
        self.openvas_scanner.is_valid_scan('test_scan')
        self.storage_service_mock.get_by_name.assert_called_once()

    def test_pause(self):
        self.openvas_scanner.pause('test_scan')
        self.openvas_mock.set_scan_status.assert_called_once_with('pause')

    def test_resume(self):
        self.openvas_scanner.resume('test_scan')
        self.openvas_mock.set_scan_status.assert_called_once_with('resume')

    def test_stop(self):
        self.openvas_scanner.stop('test_scan')
        self.openvas_mock.set_scan_status.assert_called_once_with('stop')

    def test_remove(self):
        self.openvas_scanner.remove('test_scan')
        self.openvas_mock.set_scan_status.assert_called_once_with('remove')

    def test_list_scans(self):
        self.openvas_scanner.list_scans()
        self.openvas_mock.get_scans.assert_called_once()

if __name__ == '__main__':
    unittest.main()
