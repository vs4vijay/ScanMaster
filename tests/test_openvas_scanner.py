import unittest
from unittest.mock import patch, MagicMock
from scanners.openvas_scanner import OpenVASScanner

class TestOpenVASScanner(unittest.TestCase):

    @patch('scanners.openvas_scanner.Gmp')
    @patch('scanners.openvas_scanner.StorageService')
    def setUp(self, MockStorageService, MockGmp):
        self.mock_gmp = MockGmp.return_value
        self.mock_storage_service = MockStorageService.return_value
        self.openvas_scanner = OpenVASScanner()

    def test_start(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        self.openvas_scanner.scan = MagicMock(return_value=True)
        result = self.openvas_scanner.start(scan_name, target)
        self.assertTrue(result)
        self.openvas_scanner.scan.assert_called_once_with(scan_name, target)

    def test_scan(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        target_id = '1234'
        self.mock_gmp.create_target.return_value.get.return_value = target_id
        scan_data = {
            'scan_name': scan_name,
            'scan_id': '',
            'target': target,
            'status': ''
        }
        self.mock_storage_service.get_by_name.return_value = None
        result = self.openvas_scanner.scan(scan_name, target)
        self.assertEqual(result['OPENVAS']['openvas_id'], target_id)
        self.assertEqual(result['OPENVAS']['scan_status']['status'], 'INPROGRESS')
        self.mock_storage_service.add.assert_called_once_with(scan_data)
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, result)

    def test_get_scan_status(self):
        scan_name = 'test_scan'
        scan_data = {
            'OPENVAS': {
                'openvas_id': '1234',
                'scan_status': {}
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        self.mock_gmp.get_report.return_value = True
        scan_status_list = []
        result = self.openvas_scanner.get_scan_status(scan_name, scan_status_list)
        self.assertEqual(result[0]['scanner'], 'OpenVAS')
        self.assertEqual(result[0]['status'], 'COMPLETE')
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, scan_data)

    def test_get_scan_results(self):
        scan_name = 'test_scan'
        scan_data = {
            'OPENVAS': {
                'openvas_id': '1234',
                'report_id': '5678',
                'scan_status': {'status': 'COMPLETE'}
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        report = '<get_reports_response><report><report><results><result><name>vuln1</name><nvt><cvss_base>5.0</cvss_base><cve>CVE-1234</cve></nvt><threat>High</threat><description>desc</description></result></results></report></report></get_reports_response>'
        self.mock_gmp.get_report.return_value = report
        scan_results = {}
        result = self.openvas_scanner.get_scan_results(scan_name, scan_results)
        self.assertEqual(result['vuln1']['name'], 'vuln1')
        self.assertEqual(result['vuln1']['severity'], 5.0)
        self.assertEqual(result['vuln1']['cve_id'], 'CVE-1234')
        self.assertEqual(result['vuln1']['description'], 'desc')
        self.assertEqual(result['vuln1']['risk'], 'High')

    def test_pause(self):
        scan_name = 'test_scan'
        scan_data = {'openvas_id': '1234'}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.openvas_scanner.pause(scan_name)
        self.assertIsNone(result)

    def test_resume(self):
        scan_name = 'test_scan'
        scan_data = {'openvas_id': '1234'}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.openvas_scanner.resume(scan_name)
        self.assertIsNone(result)

    def test_stop(self):
        scan_name = 'test_scan'
        scan_data = {'openvas_id': '1234'}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.openvas_scanner.stop(scan_name)
        self.assertIsNone(result)

    def test_remove(self):
        scan_name = 'test_scan'
        scan_data = {'openvas_id': '1234'}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.openvas_scanner.remove(scan_name)
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
