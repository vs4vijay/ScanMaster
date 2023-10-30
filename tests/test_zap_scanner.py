import unittest
from unittest.mock import Mock, patch
from scanners.zap_scanner import ZapScanner

class TestZapScanner(unittest.TestCase):
    def setUp(self):
        self.zap_mock = Mock()
        self.storage_service_mock = Mock()
        self.zap_scanner = ZapScanner()
        self.zap_scanner.zap = self.zap_mock
        self.zap_scanner.storage_service = self.storage_service_mock

    def test_start(self):
        with patch('scanners.zap_scanner.ZAPv2.urlopen') as urlopen_mock:
            self.zap_scanner.start('test_scan', 'http://test_target')
            urlopen_mock.assert_called_once_with('http://test_target')

    def test_pause(self):
        self.zap_scanner.pause('test_scan')
        self.zap_mock.spider.pause.assert_called_once()
        self.zap_mock.ascan.pause.assert_called_once()

    def test_resume(self):
        self.zap_scanner.resume('test_scan')
        self.zap_mock.spider.resume.assert_called_once()
        self.zap_mock.ascan.resume.assert_called_once()

    def test_stop(self):
        self.zap_scanner.stop('test_scan')
        self.zap_mock.spider.stop.assert_called_once()
        self.zap_mock.ascan.stop.assert_called_once()

    def test_remove(self):
        self.zap_scanner.remove('test_scan')
        self.zap_mock.spider.removeScan.assert_called_once()
        self.zap_mock.ascan.removeScan.assert_called_once()

    def test_scan(self):
        with patch('scanners.zap_scanner.ZAPv2.urlopen') as urlopen_mock:
            self.zap_scanner.scan('test_scan', 'http://test_target')
            urlopen_mock.assert_called_once_with('http://test_target')

    def test_get_scan_status(self):
        self.zap_scanner.get_scan_status('test_scan')
        self.zap_mock.spider.status.assert_called_once()
        self.zap_mock.ascan.status.assert_called_once()

    def test_get_scan_results(self):
        self.zap_scanner.get_scan_results('test_scan')
        self.zap_mock.core.alerts.assert_called_once()

    def test_list_scans(self):
        self.zap_scanner.list_scans()
        self.zap_mock.ascan.scans.assert_called_once()

    def test_is_valid_scan(self):
        self.zap_scanner.is_valid_scan('test_scan')
        self.zap_mock.ascan.status.assert_called_once()

if __name__ == '__main__':
    unittest.main()
