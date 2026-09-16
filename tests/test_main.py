import unittest
from unittest.mock import patch, MagicMock
import main

class TestMain(unittest.TestCase):

    @patch('main.ZapScanner')
    @patch('main.NexposeScanner')
    @patch('main.OpenVASScanner')
    def setUp(self, MockZapScanner, MockNexposeScanner, MockOpenVASScanner):
        self.mock_zap_scanner = MockZapScanner.return_value
        self.mock_nexpose_scanner = MockNexposeScanner.return_value
        self.mock_openvas_scanner = MockOpenVASScanner.return_value

    def test_main_with_target(self):
        config = {
            'scan_name': 'test_scan',
            'target': 'http://example.com',
            'pause': False,
            'resume': False
        }
        result = main.main(config)
        self.assertTrue(result)
        self.mock_zap_scanner.start.assert_called_once_with(config['scan_name'], config['target'])
        self.mock_nexpose_scanner.start.assert_called_once_with(config['scan_name'], config['target'])
        self.mock_openvas_scanner.start.assert_called_once_with(config['scan_name'], config['target'])

    def test_main_with_pause(self):
        config = {
            'scan_name': 'test_scan',
            'target': None,
            'pause': True,
            'resume': False
        }
        result = main.main(config)
        self.assertTrue(result)
        self.mock_zap_scanner.pause.assert_called_once_with(config['scan_name'])
        self.mock_nexpose_scanner.pause.assert_called_once_with(config['scan_name'])
        self.mock_openvas_scanner.pause.assert_called_once_with(config['scan_name'])

    def test_main_with_resume(self):
        config = {
            'scan_name': 'test_scan',
            'target': None,
            'pause': False,
            'resume': True
        }
        result = main.main(config)
        self.assertTrue(result)
        self.mock_zap_scanner.resume.assert_called_once_with(config['scan_name'])
        self.mock_nexpose_scanner.resume.assert_called_once_with(config['scan_name'])
        self.mock_openvas_scanner.resume.assert_called_once_with(config['scan_name'])

    def test_main_with_no_target_pause_resume(self):
        config = {
            'scan_name': 'test_scan',
            'target': None,
            'pause': False,
            'resume': False
        }
        result = main.main(config)
        self.assertTrue(result)
        self.mock_zap_scanner.get_scan_status.assert_called_once_with(config['scan_name'], [])
        self.mock_zap_scanner.get_scan_results.assert_called_once_with(config['scan_name'], {})
        self.mock_nexpose_scanner.get_scan_status.assert_called_once_with(config['scan_name'], [])
        self.mock_nexpose_scanner.get_scan_results.assert_called_once_with(config['scan_name'], {})
        self.mock_openvas_scanner.get_scan_status.assert_called_once_with(config['scan_name'], [])
        self.mock_openvas_scanner.get_scan_results.assert_called_once_with(config['scan_name'], {})

if __name__ == '__main__':
    unittest.main()
