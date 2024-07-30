import unittest
from unittest.mock import patch, MagicMock
from core.storage_service import StorageService

class TestStorageService(unittest.TestCase):

    @patch('core.storage_service.TinyDB')
    def setUp(self, MockTinyDB):
        self.mock_db = MockTinyDB.return_value
        self.storage_service = StorageService()

    def test_add(self):
        data = {'scan_name': 'test_scan'}
        self.storage_service.add(data)
        self.mock_db.insert.assert_called_once_with(data)

    def test_get_by_name(self):
        scan_name = 'test_scan'
        self.storage_service.get_by_name(scan_name)
        self.mock_db.get.assert_called_once_with({'scan_name': scan_name})

    def test_get_by_id(self):
        scan_id = 1
        self.storage_service.get_by_id(scan_id)
        self.mock_db.get.assert_called_once_with({'scan_id': scan_id})

    def test_update_by_name(self):
        scan_name = 'test_scan'
        data = {'status': 'completed'}
        self.storage_service.update_by_name(scan_name, data)
        self.mock_db.update.assert_called_once_with(data, {'scan_name': scan_name})

    def test_update_by_id(self):
        scan_id = 1
        data = {'status': 'completed'}
        self.storage_service.update_by_id(scan_id, data)
        self.mock_db.update.assert_called_once_with(data, {'scan_id': scan_id})

if __name__ == '__main__':
    unittest.main()
