#!/usr/bin/env python3

import json
from xml.etree import ElementTree

import xmltodict

from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print



def _process_results(report_response, scan_results={}):
    report_response_str = ElementTree.tostring(report_response, encoding='unicode')
    report_response_dict = xmltodict.parse(report_response_str)
    

    # print(json.dumps(report_results, indent=2))

    
    report_results = report_response_dict.get('get_reports_response', {}).get('report', {}).get('report', {}).get('results', {}).get('result', [])
    
    print(json.dumps(report_results, indent=2))

    print('report_results', report_results)

    for vuln in report_results:
        name = vuln.get('name')
        print('name: ', name)
        if scan_results.get(name):
            print('-------- Dup title', name)
            continue
        nvt = vuln.get('nvt', {})
        scan_result = {}
        scan_result['name'] = name
        scan_result['severity'] = float(nvt.get('cvss_base', 0))
        scan_result['risk'] = vuln.get('threat')
        scan_result['cve_id'] = nvt.get('cve', 'N/A') if nvt.get('cve') != 'NOCVE' else 'N/A'
        scan_result['description'] = '' # vuln.get('description')
        scan_result['solution'] = 'N/A'
        scan_result['reported_by'] = 'OpenVAS'
        scan_results[name] = scan_result
    return scan_results



connection = UnixSocketConnection(path='/var/run/openvasmd.sock')
transform = EtreeTransform()
gmp = Gmp(connection, transform=transform)

# Retrieve GMP version supported by the remote daemon
version = gmp.get_version()

# Prints the XML in beautiful form
pretty_print(version)

# Login
gmp.authenticate('admin', 'admin')


name = 'name-5'
ip_address = 'scanme.nmap.org'
# ip_address = 'webscantest.com'
# ip_address = 'slack.com'


# response = gmp.create_target(name=name, hosts=[ip_address])
# pretty_print(response)
# target_id = response.get('id')
# print('target_id: ', target_id)
# target_id = 'b7b3b26d-5e19-482c-a1b5-d5c46b89edaa'
target_id = '69ca3c65-af09-48b8-bb3a-59e2e6cccb96'

scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'
scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'

# response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id)
# task_id = response.get('id')


# response = gmp.start_task(task_id)
# report_id = response[0].text

# print('report_id', report_id)

report_id = '79bf4984-9a0e-435a-807b-9dd530fb532f'

report_format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'


report_response = gmp.get_report(report_id=report_id, report_format_id=report_format_id)
# pretty_print(report_response)

scan_results={}
_process_results(report_response, scan_results)

print('scan_results: ')
print(scan_results)

