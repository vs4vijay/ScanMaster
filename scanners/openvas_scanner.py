import os
import sys
import time
import json

import xmltodict
from xml.etree import ElementTree
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from dotenv import load_dotenv, find_dotenv

from .scanner import Scanner
from core.storage_service import StorageService

load_dotenv(find_dotenv())

config = {
    'OPENVAS_SOCKET': os.getenv('OPENVAS_SOCKET'),
    'OPENVAS_USERNAME': os.getenv('OPENVAS_USERNAME'),
    'OPENVAS_PASSWORD': os.getenv('OPENVAS_PASSWORD'),
    'REPORT_FORMAT_ID': 'a994b278-1f62-11e1-96ac-406186ea4fc5',
    'SCAN_CONFIG_ID': 'daba56c8-73ec-11df-a475-002264764cea',
    'SCANNER_ID': '08b69003-5fc2-4037-a479-93b440211c73'
}

class OpenVASScanner(Scanner):

    name = 'OpenVAS'
    
    def __init__(self):
        connection = UnixSocketConnection(path=config['OPENVAS_SOCKET'])
        transform = EtreeTransform()
        self.gmp = Gmp(connection, transform=transform)
        self.storage_service = StorageService()
        self.scan_status = None
        self.scan_results = None

        # Login
        try:
            self.gmp.authenticate(config['OPENVAS_USERNAME'], config['OPENVAS_PASSWORD'])
        except:
            print(f'[{self.name}] Not able to connect to the {self.name}: ', sys.exc_info())
            return

        # Getting Version
        # version = self.gmp.get_version()
        # pretty_print(version)
    

    def start(self, scan_name, target):
        print(f'[{self.name}] Starting Scan for Target: {target}')
        self.scan_status = 'INPROGRESS'

        try:
            self.scan_results = self.scan(scan_name, target)
            return self.scan_results
        except:
            print(f'[{self.name}] Not able to connect to the {self.name}: ', sys.exc_info()) 
            return False


    def scan(self, scan_name, target):
        print(f'[{self.name}] Scan Name: {scan_name}')

        address = self._get_address(target)

        # Creating Target
        target_response = self.gmp.create_target(name=scan_name, hosts=[address])
        # print('target_response')
        self.scan_status = 'INPROGRESS'
        pretty_print(target_response)
        target_id = target_response.get('id')

        if not target_id:
            print(f'[{self.name}] could not able to create target: ', target_response.get('status_text'))
            return False

        # target_id = '69ca3c65-af09-48b8-bb3a-59e2e6cccb96'

        print(f'[{self.name}] Target Created: {target_id}')

        scan_data = self.storage_service.get_by_name(scan_name)

        if not scan_data:
            scan_data = {
                'scan_name': scan_name, 
                'scan_id': '', 
                'target': target,
                'status': ''
            }
            self.storage_service.add(scan_data)

        scan_data['OPENVAS'] = {
            'openvas_id': target_id,
            'target_id': target_id,
            'scan_status': {
                'status': 'INPROGRESS'
            }
        }
        self.storage_service.update_by_name(scan_name, scan_data)

        time.sleep(4)
        self._create_report(scan_name)

        return scan_data


    def _create_report(self, scan_name):

        scan_data = self.storage_service.get_by_name(scan_name)
        openvas_id = scan_data['OPENVAS']['openvas_id']

        scan_config_id = config['SCAN_CONFIG_ID']
        scanner_id = config['SCANNER_ID']
        report_format_id = config['REPORT_FORMAT_ID']

        # Creating Task
        task_response = self.gmp.create_task(name=scan_name, config_id=scan_config_id, target_id=openvas_id, scanner_id=scanner_id)
        # print('task_response')
        # pretty_print(task_response)
        task_id = task_response.get('id')

        # Starting Task
        start_task_response = self.gmp.start_task(task_id)
        # print('start_task_response')
        # pretty_print(start_task_response)
        report_id = start_task_response[0].text

        scan_data['OPENVAS']['report_id'] = report_id
        scan_data['OPENVAS']['report_format_id'] = report_format_id
        scan_data['OPENVAS']['scan_config_id'] = scan_config_id
        scan_data['OPENVAS']['scanner_id'] = scanner_id
        scan_data['OPENVAS']['task_id'] = task_id

        print(f'[{self.name}] Created Report: {report_id} with Task: {task_id}')

        self.storage_service.update_by_name(scan_name, scan_data)
        self.scan_status = 'COMPLETE'

        return scan_data
    

    def get_scan_status(self, scan_name, scan_status_list=[]):

        if not self.is_valid_scan(scan_name):
            return False

        return self.scan_status
        openvas_id = scan_data.get('OPENVAS', {})['openvas_id']
        target = scan_data['target']

        print(f'[{self.name}] Getting Scan Status for Target: {target}')
        print(f'[{self.name}] Scan Name: {scan_name}')
        print(f'[{self.name}] Scan Id: {openvas_id}')
        
        try:
            scan_info = self.get_scan_results(scan_name)
            # print('scan_info')
            # pretty_print(scan_info)
        except:
            print(f'[{self.name}] Could not get the scan {openvas_id}: ', sys.exc_info())
            return False

        scan_status['status'] = 'COMPLETE' if scan_info else 'INPROGRESS'
        scan_data['OPENVAS']['scan_status'] = scan_status

        self.storage_service.update_by_name(scan_name, scan_data)

        if scan_status['status'] is 'COMPLETE':
            print(f'[{self.name}] Scan {scan_name} Completed')

        scan_status_list.append({
            'scanner': self.name,
            'status': scan_status['status']
        })

        return scan_status_list


    def get_scan_results(self, scan_name, scan_results={}):

        if not self.is_valid_scan(scan_name):
            return False

        return self.scan_results

        # if scan_data.get('OPENVAS', {}).get('scan_status').get('status', None) != 'COMPLETE':
        #     print(f'[{self.name}] Scan is in progress')
        #     return False

        openvas_id = scan_data.get('OPENVAS', {})['openvas_id']
        report_id = scan_data.get('OPENVAS', {})['report_id']
        report_format_id = scan_data.get('OPENVAS', {})['report_format_id']
        # report_id = '79bf4984-9a0e-435a-807b-9dd530fb532f'

        try:
            report_response = self.gmp.get_report(report_id=report_id, report_format_id=report_format_id)
            # print('report_response')
            # pretty_print(report_response)
        except:
            print(f'[{self.name}] Could not get the scan {openvas_id}: ', sys.exc_info())
            return False

        self._process_results(report_response, scan_results)

        return scan_results
    

    def _process_results(self, report_response, scan_results={}):
        report_response_str = ElementTree.tostring(report_response, encoding='unicode')
        report_response_dict = xmltodict.parse(report_response_str)
        
        report_results = report_response_dict.get('get_reports_response', {}).get('report', {}).get('report', {}).get('results', {}).get('result', [])
        
        # print(json.dumps(report_results, indent=2))
        # print('report_results', report_results)

        for vuln in report_results:
            name = vuln.get('name')
            print('name: ', name)
            if scan_results.get(name):
                print('--- Duplicate name: ', name)
                continue
            nvt = vuln.get('nvt', {})
            scan_result = {}
            scan_result['name'] = name
            scan_result['severity'] = float(nvt.get('cvss_base', 0))
            scan_result['risk'] = vuln.get('threat')
            scan_result['cve_id'] = nvt.get('cve', 'N/A') if nvt.get('cve') != 'NOCVE' else 'N/A'
            scan_result['description'] = vuln.get('description')
            scan_result['solution'] = 'N/A'
            scan_result['reported_by'] = 'OpenVAS'
            scan_results[name] = scan_result
        return scan_results


    def is_valid_scan(self, scan_name):

        if self.scan_status is None:
            print(f'[{self.name}] Invalid Scan Name: {scan_name}')
            return False

        if not scan_data.get('OPENVAS'):
            print(f'[{self.name}] No Scan Details found for {scan_name}')
            return False

        return True


    def pause(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        # scan = self.storage_service.get_by_name(scan_name)
        # nexpose_id = scan['nexpose_id']

        # response = self.nexpose.set_scan_status(nexpose_id, 'pause')
        # pprint(response)
        # return response


    def resume(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        # scan = self.storage_service.get_by_name(scan_name)
        # nexpose_id = scan['nexpose_id']

        # response = self.nexpose.set_scan_status(nexpose_id, 'resume')
        # pprint(response)
        # return response


    def stop(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        # scan = self.storage_service.get_by_name(scan_name)
        # nexpose_id = scan['nexpose_id']

        # response = self.nexpose.set_scan_status(nexpose_id, 'stop')
        # pprint(response)
        # return response


    def remove(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        # scan = self.storage_service.get_by_name(scan_name)
        # nexpose_id = scan['nexpose_id']

        # response = self.nexpose.set_scan_status(nexpose_id, 'remove')
        # pprint(response)
        # return response
    
        
    def list_scans(self):
        pass

