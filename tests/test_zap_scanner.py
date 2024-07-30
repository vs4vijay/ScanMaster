import unittest
from unittest.mock import patch, MagicMock
from scanners.zap_scanner import ZapScanner

class TestZapScanner(unittest.TestCase):

    @patch('scanners.zap_scanner.ZAPv2')
    @patch('scanners.zap_scanner.StorageService')
    def setUp(self, MockStorageService, MockZAPv2):
        self.mock_zap = MockZAPv2.return_value
        self.mock_storage_service = MockStorageService.return_value
        self.zap_scanner = ZapScanner()

    def test_start(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        self.zap_scanner.scan = MagicMock(return_value=True)
        result = self.zap_scanner.start(scan_name, target)
        self.assertTrue(result)
        self.zap_scanner.scan.assert_called_once_with(scan_name, target)

    def test_pause(self):
        scan_name = 'test_scan'
        scan_data = {'scan_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.zap_scanner.pause(scan_name)
        self.assertEqual(result, scan_data)
        self.mock_zap.spider.pause.assert_called_once_with(scan_data['scan_id'])
        self.mock_zap.ascan.pause.assert_called_once_with(scan_data['scan_id'])

    def test_resume(self):
        scan_name = 'test_scan'
        scan_data = {'scan_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.zap_scanner.resume(scan_name)
        self.assertEqual(result, scan_data)
        self.mock_zap.spider.resume.assert_called_once_with(scan_data['scan_id'])
        self.mock_zap.ascan.resume.assert_called_once_with(scan_data['scan_id'])

    def test_stop(self):
        scan_name = 'test_scan'
        scan_data = {'scan_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.zap_scanner.stop(scan_name)
        self.assertEqual(result, scan_data)
        self.mock_zap.spider.stop.assert_called_once_with(scan_data['scan_id'])
        self.mock_zap.ascan.stop.assert_called_once_with(scan_data['scan_id'])

    def test_remove(self):
        scan_name = 'test_scan'
        scan_data = {'scan_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.zap_scanner.remove(scan_name)
        self.assertEqual(result, scan_data['scan_id'])
        self.mock_zap.spider.removeScan.assert_called_once_with(scan_data['scan_id'])
        self.mock_zap.ascan.removeScan.assert_called_once_with(scan_data['scan_id'])

    def test_scan(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        scan_id = 1
        active_scan_id = 2
        self.mock_zap.spider.scan.return_value = scan_id
        self.mock_zap.ascan.scan.return_value = active_scan_id
        scan_data = {
            'scan_name': scan_name,
            'scan_id': '',
            'target': target,
            'status': ''
        }
        self.mock_storage_service.get_by_name.return_value = None
        result = self.zap_scanner.scan(scan_name, target)
        self.assertEqual(result['ZAP']['zap_id'], scan_id)
        self.assertEqual(result['ZAP']['active_scan_id'], active_scan_id)
        self.assertEqual(result['ZAP']['scan_status']['status'], 'INPROGRESS')
        self.mock_storage_service.add.assert_called_once_with(scan_data)
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, result)

    def test_get_scan_status(self):
        scan_name = 'test_scan'
        scan_data = {
            'ZAP': {
                'zap_id': 1,
                'scan_status': {}
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        self.mock_zap.spider.status.return_value = '100'
        self.mock_zap.pscan.records_to_scan = 0
        self.mock_zap.ascan.status.return_value = '100'
        scan_status_list = []
        result = self.zap_scanner.get_scan_status(scan_name, scan_status_list)
        self.assertEqual(result[0]['scanner'], 'ZAP (spider_scan)')
        self.assertEqual(result[0]['status'], 'COMPLETE (100%)')
        self.assertEqual(result[1]['scanner'], 'ZAP (passive_scan)')
        self.assertEqual(result[1]['status'], 'COMPLETE (0)')
        self.assertEqual(result[2]['scanner'], 'ZAP (active_scan)')
        self.assertEqual(result[2]['status'], 'COMPLETE (100%)')
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, scan_data)

    def test_get_scan_results(self):
        scan_name = 'test_scan'
        scan_data = {
            'ZAP': {
                'zap_id': 1
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        alerts = [{'name': 'alert1', 'risk': 'High', 'url': 'http://example.com'}]
        self.mock_zap.core.alerts.return_value = alerts
        scan_results = {}
        result = self.zap_scanner.get_scan_results(scan_name, scan_results)
        self.assertEqual(result['alert1']['name'], 'alert1')
        self.assertEqual(result['alert1']['risk'], 'High')
        self.assertEqual(result['alert1']['urls'], {'http://example.com'})
        self.assertEqual(result['alert1']['severity'], 8.5)

if __name__ == '__main__':
    unittest.main()
