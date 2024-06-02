import unittest
from tinydb import TinyDB, Query
from core.storage_service import StorageService

class TestStorageService(unittest.TestCase):
    def setUp(self):
        self.db = TinyDB('test_db.json')
        self.storage_service = StorageService()

    def test_add(self):
        data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'INPROGRESS'}
        self.storage_service.add(data)
        record = self.db.get(Query().scan_name == 'test_scan')
        self.assertEqual(record, data)

    def test_get_by_name(self):
        data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'INPROGRESS'}
        self.db.insert(data)
        record = self.storage_service.get_by_name('test_scan')
        self.assertEqual(record, data)

    def test_get_by_id(self):
        data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'INPROGRESS'}
        self.db.insert(data)
        record = self.storage_service.get_by_id('123')
        self.assertEqual(record, data)

    def test_update_by_name(self):
        data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'INPROGRESS'}
        new_data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'COMPLETE'}
        self.db.insert(data)
        self.storage_service.update_by_name('test_scan', new_data)
        record = self.db.get(Query().scan_name == 'test_scan')
        self.assertEqual(record, new_data)

    def test_update_by_id(self):
        data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'INPROGRESS'}
        new_data = {'scan_name': 'test_scan', 'scan_id': '123', 'target': 'http://test_target', 'status': 'COMPLETE'}
        self.db.insert(data)
        self.storage_service.update_by_id('123', new_data)
        record = self.db.get(Query().scan_id == '123')
        self.assertEqual(record, new_data)

if __name__ == '__main__':
    unittest.main()
