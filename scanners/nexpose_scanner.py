import time
import base64

import rapid7vmconsole
from pprint import pprint
from bs4 import BeautifulSoup

from .scanner import Scanner
from core.storage_service import StorageService

config = {
    'HOST': 'https://url:3780',
    'USERNAME': 'username',
    'PASSWORD': 'password'
}

class NexposeScanner(Scanner):

    name = 'Nexpose'
    
    def __init__(self):
        self.nexpose_config = rapid7vmconsole.Configuration(name='VulnScanner')
        self.nexpose_config.username = config['USERNAME']
        self.nexpose_config.password = config['PASSWORD']
        self.nexpose_config.host = config['HOST']
        self.nexpose_config.assert_hostname = False
        self.nexpose_config.verify_ssl = False
        self.nexpose_config.ssl_ca_cert = None
        self.nexpose_config.connection_pool_maxsize = None
        self.nexpose_config.proxy = None
        self.nexpose_config.cert_file = None
        self.nexpose_config.key_file = None
        self.nexpose_config.safe_chars_for_path_param = ''

        auth_token = f'{config["USERNAME"]}:{config["PASSWORD"]}'
        auth_token = base64.b64encode(auth_token.encode('ascii')).decode()

        api_client = rapid7vmconsole.ApiClient(configuration=self.nexpose_config)
        api_client.default_headers['Authorization'] = f'Basic {auth_token}'

        self.nexpose_admin = rapid7vmconsole.AdministrationApi(api_client)
        self.nexpose = rapid7vmconsole.ScanApi(api_client)
        self.nexpose_site = rapid7vmconsole.SiteApi(api_client)
        self.nexpose_assets = rapid7vmconsole.AssetApi(api_client)
        self.nexpose_report = rapid7vmconsole.ReportApi(api_client)
        self.storage_service = StorageService()
    

    def start(self, scan_name, target):
        print(f'[{self.name}] Starting Scan for Target: {target}')

        try:
            return self.scan(scan_name, target)
        except:
            print(f'[{self.name}] Not able to connect to the {self.name}') 
            return False

    def scan(self, scan_name, target):
        print(f'[{self.name}] Scan Name: {scan_name}')

        address = self._get_address(target)

        # Creating Site
        scan_targets = rapid7vmconsole.IncludedScanTargets(addresses=[address])
        asset = rapid7vmconsole.StaticSite(included_targets=scan_targets)
        
        scan_scope = rapid7vmconsole.ScanScope(assets=asset)
        site_create_resource = rapid7vmconsole.SiteCreateResource(name=scan_name, scan=scan_scope)
        
        site = self.nexpose_site.create_site(site=site_create_resource)
        print(f'[{self.name}] Site Created: {site.id}')
        
        # Creating Scan
        adhoc_scan = rapid7vmconsole.AdhocScan(hosts=[address])

        # Starting Scan
        scan = self.nexpose.start_scan(site.id, scan=adhoc_scan)
        print(f'[{self.name}] Scan Started: {scan.id}')

        scan_data = self.storage_service.get_by_name(scan_name)

        if not scan_data:
            scan_data = {
                'scan_name': scan_name, 
                'scan_id': '', 
                'target': target,
                'status': ''
            }
            self.storage_service.add(scan_data)

        scan_data['NEXPOSE'] = {
            'nexpose_id': scan.id,
            'site_id': site.id,
            'scan_status': {
                'status': 'INPROGRESS'
            }
        }
        self.storage_service.update_by_name(scan_name, scan_data)

        return scan_data


    def _create_report(self, scan_name):

        scan_data = self.storage_service.get_by_name(scan_name)
        nexpose_id = scan_data['NEXPOSE']['nexpose_id']

        # Creating Report
        report_config_scope = rapid7vmconsole.ReportConfigScopeResource(scan=nexpose_id)
        report_config = rapid7vmconsole.Report(name=f'{scan_name}-xml-Report', format='xml-export', scope=report_config_scope)
        report = self.nexpose_report.create_report(report=report_config)

        # Generate Report Instance
        report_instance = self.nexpose_report.generate_report(report.id)

        scan_data['NEXPOSE']['report_id'] = report.id
        scan_data['NEXPOSE']['report_instance_id'] = report_instance.id

        print(f'[{self.name}] Created Report: {report.id} with Instance: {report_instance.id}')

        self.storage_service.update_by_name(scan_name, scan_data)

        return scan_data
    

    def get_scan_status(self, scan_name, scan_status_list=[]):

        if not self.is_valid_scan(scan_name):
            return False

        scan_data = self.storage_service.get_by_name(scan_name)
        scan_status = scan_data.get('NEXPOSE', {}).get('scan_status', {})
        nexpose_id = scan_data.get('NEXPOSE', {})['nexpose_id']
        target = scan_data['target']

        print(f'[{self.name}] Getting Scan Status for Target: {target}')
        print(f'[{self.name}] Scan Name: {scan_name}')
        print(f'[{self.name}] Scan Id: {nexpose_id}')
        
        scan_info = self.nexpose.get_scan(nexpose_id)

        scan_status['vulnerabilities'] = scan_info.vulnerabilities.__dict__
        scan_status['status'] = 'COMPLETE' if scan_info.status == 'finished' else 'INPROGRESS' if scan_info.status == 'running' else scan_info.status

        scan_data['NEXPOSE']['scan_status'] = scan_status

        self.storage_service.update_by_name(scan_name, scan_data)

        if scan_status['status'] is 'COMPLETE' and scan_data['NEXPOSE'].get('report_id', None) is None:
            print(f'[{self.name}] Scan {scan_name} Completed, Generating Report')

            # Starting the Report Generate Process
            self._create_report(scan_name)
            time.sleep(2)

        scan_status_list.append({
            'scanner': self.name,
            'status': scan_status['status']
        })

        return scan_status_list


    def get_scan_results(self, scan_name, scan_results={}):

        if not self.is_valid_scan(scan_name):
            return False

        scan_data = self.storage_service.get_by_name(scan_name)

        if scan_data.get('NEXPOSE', {}).get('scan_status').get('status', None) != 'COMPLETE':
            print(f'[{self.name}] Scan is in progress')
            return False

        nexpose_id = scan_data.get('NEXPOSE', {})['nexpose_id']
        report_id = scan_data.get('NEXPOSE', {})['report_id']
        report_instance_id = scan_data.get('NEXPOSE', {})['report_instance_id']

        downloaded_report = self.nexpose_report.download_report(report_id, report_instance_id)
        parsed_report = BeautifulSoup(downloaded_report, features='xml')

        self._process_results(parsed_report, scan_results)

        return scan_results
    
    def _process_results(self, report, scan_results):

        for vuln in report.find_all('vulnerability'):
            name = vuln.get('title')
            
            if scan_results.get(name):
                print('-------- Dup title', name)
                continue

            scan_result = {}
            scan_result['name'] = name
            scan_result['severity'] = float(vuln.get('cvssScore'))
            scan_result['risk'] = self._get_nexpose_risk(scan_result['severity'])
            scan_result['cve_id'] = ''
            scan_result['description'] = ''
            scan_result['solution'] = ''
            scan_result['reported_by'] = self.name

            if vuln.references.find('reference', source='CVE'):
                scan_result['cve_id'] = vuln.references.find('reference', source='CVE').text
            
            if vuln.description.ContainerBlockElement.Paragraph:
                scan_result['description'] = vuln.description.ContainerBlockElement.Paragraph.text
            
            if vuln.solution.ContainerBlockElement.Paragraph:
                scan_result['solution'] = vuln.solution.ContainerBlockElement.Paragraph.text

            scan_results[name] = scan_result
        
        return scan_results


    def is_valid_scan(self, scan_name):

        scan_data = self.storage_service.get_by_name(scan_name)
        if not scan_data:
            print(f'[{self.name}] Invalid Scan Name: {scan_name}')
            return False

        if not scan_data.get('NEXPOSE'):
            print(f'[{self.name}] No Scan Details found for {scan_name}')
            return False

        return True

    def _get_nexpose_risk(self, severity): 
        if 0.1 <= severity <= 3.9:
            return 'Low'
        elif 4 <= severity <= 6.9:
            return 'Low'
        elif 7 <= severity <= 10:
            return 'Low'
        else:
            return 'N/A'


    def pause(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        scan = self.storage_service.get_by_name(scan_name)
        nexpose_id = scan['nexpose_id']

        response = self.nexpose.set_scan_status(nexpose_id, 'pause')
        pprint(response)
        return response


    def resume(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        scan = self.storage_service.get_by_name(scan_name)
        nexpose_id = scan['nexpose_id']

        response = self.nexpose.set_scan_status(nexpose_id, 'resume')
        pprint(response)
        return response


    def stop(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        scan = self.storage_service.get_by_name(scan_name)
        nexpose_id = scan['nexpose_id']

        response = self.nexpose.set_scan_status(nexpose_id, 'stop')
        pprint(response)
        return response


    def remove(self, scan_name):
        if not self.is_valid_scan(scan_name):
            return False

        scan = self.storage_service.get_by_name(scan_name)
        nexpose_id = scan['nexpose_id']

        response = self.nexpose.set_scan_status(nexpose_id, 'remove')
        pprint(response)
        return response
    
        
    def list_scans(self):
        active = False
        scans = self.nexpose.get_scans(active=active)
        print(f'[{self.name}] Scans: {len(scans)}', scans)

