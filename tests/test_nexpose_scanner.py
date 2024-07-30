import unittest
from unittest.mock import patch, MagicMock
from scanners.nexpose_scanner import NexposeScanner

class TestNexposeScanner(unittest.TestCase):

    @patch('scanners.nexpose_scanner.rapid7vmconsole')
    @patch('scanners.nexpose_scanner.StorageService')
    def setUp(self, MockStorageService, MockRapid7vmconsole):
        self.mock_rapid7 = MockRapid7vmconsole.return_value
        self.mock_storage_service = MockStorageService.return_value
        self.nexpose_scanner = NexposeScanner()

    def test_start(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        self.nexpose_scanner.scan = MagicMock(return_value=True)
        result = self.nexpose_scanner.start(scan_name, target)
        self.assertTrue(result)
        self.nexpose_scanner.scan.assert_called_once_with(scan_name, target)

    def test_scan(self):
        scan_name = 'test_scan'
        target = 'http://example.com'
        scan_id = 1
        site_id = 2
        self.mock_rapid7vmconsole.SiteApi.return_value.create_site.return_value.id = site_id
        self.mock_rapid7vmconsole.ScanApi.return_value.start_scan.return_value.id = scan_id
        scan_data = {
            'scan_name': scan_name,
            'scan_id': '',
            'target': target,
            'status': ''
        }
        self.mock_storage_service.get_by_name.return_value = None
        result = self.nexpose_scanner.scan(scan_name, target)
        self.assertEqual(result['NEXPOSE']['nexpose_id'], scan_id)
        self.assertEqual(result['NEXPOSE']['site_id'], site_id)
        self.assertEqual(result['NEXPOSE']['scan_status']['status'], 'INPROGRESS')
        self.mock_storage_service.add.assert_called_once_with(scan_data)
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, result)

    def test_get_scan_status(self):
        scan_name = 'test_scan'
        scan_data = {
            'NEXPOSE': {
                'nexpose_id': 1,
                'scan_status': {}
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        self.mock_rapid7vmconsole.ScanApi.return_value.get_scan.return_value.status = 'finished'
        scan_status_list = []
        result = self.nexpose_scanner.get_scan_status(scan_name, scan_status_list)
        self.assertEqual(result[0]['scanner'], 'Nexpose')
        self.assertEqual(result[0]['status'], 'COMPLETE')
        self.mock_storage_service.update_by_name.assert_called_once_with(scan_name, scan_data)

    def test_get_scan_results(self):
        scan_name = 'test_scan'
        scan_data = {
            'NEXPOSE': {
                'nexpose_id': 1,
                'report_id': 2,
                'report_instance_id': 3,
                'scan_status': {'status': 'COMPLETE'}
            },
            'target': 'http://example.com'
        }
        self.mock_storage_service.get_by_name.return_value = scan_data
        report = '<vulnerabilities><vulnerability title="vuln1" cvssScore="5.0"><references><reference source="CVE">CVE-1234</reference></references><description><ContainerBlockElement><Paragraph>desc</Paragraph></ContainerBlockElement></description><solution><ContainerBlockElement><Paragraph>sol</Paragraph></ContainerBlockElement></solution></vulnerability></vulnerabilities>'
        self.mock_rapid7vmconsole.ReportApi.return_value.download_report.return_value = report
        scan_results = {}
        result = self.nexpose_scanner.get_scan_results(scan_name, scan_results)
        self.assertEqual(result['vuln1']['name'], 'vuln1')
        self.assertEqual(result['vuln1']['severity'], 5.0)
        self.assertEqual(result['vuln1']['cve_id'], 'CVE-1234')
        self.assertEqual(result['vuln1']['description'], 'desc')
        self.assertEqual(result['vuln1']['solution'], 'sol')

    def test_pause(self):
        scan_name = 'test_scan'
        scan_data = {'nexpose_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.nexpose_scanner.pause(scan_name)
        self.assertEqual(result, self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.return_value)
        self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.assert_called_once_with(scan_data['nexpose_id'], 'pause')

    def test_resume(self):
        scan_name = 'test_scan'
        scan_data = {'nexpose_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.nexpose_scanner.resume(scan_name)
        self.assertEqual(result, self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.return_value)
        self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.assert_called_once_with(scan_data['nexpose_id'], 'resume')

    def test_stop(self):
        scan_name = 'test_scan'
        scan_data = {'nexpose_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.nexpose_scanner.stop(scan_name)
        self.assertEqual(result, self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.return_value)
        self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.assert_called_once_with(scan_data['nexpose_id'], 'stop')

    def test_remove(self):
        scan_name = 'test_scan'
        scan_data = {'nexpose_id': 1}
        self.mock_storage_service.get_by_name.return_value = scan_data
        result = self.nexpose_scanner.remove(scan_name)
        self.assertEqual(result, self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.return_value)
        self.mock_rapid7vmconsole.ScanApi.return_value.set_scan_status.assert_called_once_with(scan_data['nexpose_id'], 'remove')

if __name__ == '__main__':
    unittest.main()
