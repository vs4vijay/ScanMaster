
import re

from terminaltables import SingleTable, DoubleTable

class Scanner:
    
    def __init__():
        pass
    
    def scan(self):
        pass

    def get_scan_status(self):
        pass

    def get_scan_results(self):
        pass

    def is_valid_scan(self):
        pass

    def list_scans(self):
        pass

    def pause(self):
        pass

    def resume(self):
        pass
    
    def stop(self):
        pass

    def _get_address(self, target):
        return re.sub('http[s]*://', '', target)
        
    def _process_for_duplicates(self, scan_results):
        return scan_results

    def print_scan_status(self, scan_status_list):
        status = []
        status.append([ '#', 'Scanner', 'Status'])
        count = 0
        
        for scan_status in scan_status_list:
            count += 1
            status.append([ count, scan_status['scanner'], scan_status['status'] ])

        status_table = DoubleTable(status)
        status_table.title = 'Scan Status'
        print(status_table.table)

    def print_report(self, scan_results):

        if not scan_results:
            return False

        results = list(scan_results.values())

        scan_report = []
        scan_report.append([ '#', 'Vuln. Name', 'Risk', 'Severity', 'CVE/CWE ID', 'URLs', 'Desc.', 'Sol.', 'Scanner' ])

        count = 0
        for vuln in sorted(results, key = lambda x: x['severity'], reverse=True):
            count += 1

            name = vuln['name']
            risk = vuln['risk']
            severity = vuln['severity']
            cve_id = vuln.get('cweid') or vuln.get('cveid', '')
            urls = list(vuln.get('urls', []))
            description = vuln['description']
            solution = vuln['solution']
            reported_by = vuln['reported_by']

            urls = f'({len(urls)} URLs) {urls[0]}' if urls else ''

            scan_report.append([ count, name, risk, severity, cve_id, urls, 'desc', 'sol', reported_by ])

        scan_report_table = SingleTable(scan_report)
        scan_report_table.title = 'Vuln. Alerts'
        print(scan_report_table.table)
