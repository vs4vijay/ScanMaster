#!/usr/bin/env python3

import base64

import rapid7vmconsole
from bs4 import BeautifulSoup
from terminaltables import AsciiTable, SingleTable, DoubleTable


config = {
    'HOST': 'https://life.do:3780',
    'USERNAME': '',
    'PASSWORD': ''
}

nexpose_config = rapid7vmconsole.Configuration(name='Scanner')
nexpose_config.username = config['USERNAME']
nexpose_config.password = config['PASSWORD']
nexpose_config.host = config['HOST']
nexpose_config.assert_hostname = False
nexpose_config.verify_ssl = False
nexpose_config.ssl_ca_cert = None
nexpose_config.connection_pool_maxsize = None
nexpose_config.proxy = None
nexpose_config.cert_file = None
nexpose_config.key_file = None
nexpose_config.safe_chars_for_path_param = ''

auth = f'{config["USERNAME"]}:{config["PASSWORD"]}'
auth = base64.b64encode(auth.encode('ascii')).decode()
api_client = rapid7vmconsole.ApiClient(configuration=nexpose_config)
api_client.default_headers['Authorization'] = f'Basic {auth}'
nexpose_report = rapid7vmconsole.ReportApi(api_client)
nexpose_site = rapid7vmconsole.SiteApi(api_client)

scan_name='sixyfive7'
nexpose_id=1

report_config_scope = rapid7vmconsole.ReportConfigScopeResource(scan=nexpose_id)

### HTML
# report_config = rapid7vmconsole.Report(name=f'{scan_name}-html-Report', format='html', template='audit-report', scope=report_config_scope)
# report = nexpose_report.create_report(report=report_config)
# report_instance = nexpose_report.generate_report(report.id)
# hh = nexpose_report.download_report(report.id, report_instance.id)

### XML
# report_config = rapid7vmconsole.Report(name=f'{scan_name}-xml-Report', format='xml-export', scope=report_config_scope)
# print('report_config', report_config)

# report = nexpose_report.create_report(report=report_config)
# print('report', report)

# report_instance = nexpose_report.generate_report(report.id)
# print('report_instance', report_instance)

# print('report.id, report_instance.id', report.id, report_instance.id)
xx = nexpose_report.download_report(23, 26)

# xx = nexpose_report.download_report(12, 1)

# soup = BeautifulSoup(xx, 'xml.parser')
soup = BeautifulSoup(xx, features='xml')

print(soup)


scan_data_map = {}
scan_data = []
scan_data.append([ '#', 'Name', 'Risk', 'Severity', 'CVE/CWE ID','URLs', 'Solution' ])
count = 0

for vuln in soup.find_all('vulnerability'):
    title = vuln.get('title')

    if scan_data_map.get(title):
        pass

    count += 1

    cvss_score = vuln.get('cvssScore')
    pci_severity = vuln.get('pciSeverity')
    severity = vuln.get('severity')

    if vuln.references.find('reference', source='CVE'):
        cve = vuln.references.find('reference', source='CVE').text
    else:
        cve = ''
    
    if vuln.description.ContainerBlockElement.Paragraph:
        description = vuln.description.ContainerBlockElement.Paragraph.text
    else:
        description = ''
    
    if vuln.solution.ContainerBlockElement.Paragraph:
        solution = vuln.solution.ContainerBlockElement.Paragraph.text
    else:
        solution = ''

    scan_data.append([count, title, cve, cvss_score, 'description', pci_severity, severity, 'solution'])



# print('scan_data', scan_data)

report_table = SingleTable(scan_data)
report_table.title = 'Alerts'
print(report_table.table)



### SQL
# report_config = rapid7vmconsole.Report(name=f'{scan_name}-sql-Report', format='sql-query', query='select * from dim_asset', version='2.3.0', scope=report_config_scope)
# report = nexpose_report.create_report(report=report_config)
# report_instance = nexpose_report.generate_report(report.id)
# ss = nexpose_report.download_report(report.id, report_instance.id)

# ### CSV
# report_config_scope = rapid7vmconsole.ReportConfigScopeResource(sites=[2])

# report_config = rapid7vmconsole.Report(name=f'{scan_name}-csv-Report', format='csv-export', template='audit-report', scope=report_config_scope)
# report = nexpose_report.create_report(report=report_config)
# report_instance = nexpose_report.generate_report(report.id)
# cc = nexpose_report.download_report(report.id, report_instance.id)


# asset_api = rapid7vmconsole.AssetApi(api_client)
# assets = asset_api.get_assets()

# for a in assets.resources:
#     print("Asset ID: %s; Hostname: %s; IP Address: %s" % (a.id, a.host_name, a.ip))



aa = [{'format': 'pdf',
            'templates': ['audit-report',
                            'executive-overview',
                            'prioritized-remediations',
                            'prioritized-remediations-with-details',
                            'r7-discovered-assets',
                            'r7-vulnerability-exceptions',
                            'top-riskiest-assets',
                            'top-vulnerable-assets',
                            'vulnerability-trends']},
            {'format': 'html',
            'templates': ['audit-report',
                            'executive-overview',
                            'prioritized-remediations',
                            'prioritized-remediations-with-details',
                            'r7-discovered-assets',
                            'r7-vulnerability-exceptions',
                            'top-riskiest-assets',
                            'top-vulnerable-assets',
                            'vulnerability-trends']},
            {'format': 'nexpose-simple-xml', 'templates': None},
            {'format': 'xml-export', 'templates': None},
            {'format': 'xml-export-v2', 'templates': None}]


# print('HTML report:')
        # pprint(self.zap.core.htmlreport())

        # print('JSON report:')
        # pprint(self.zap.core.jsonreport())

        # with open('report.xml', 'w') as f:
        #     f.write(self.zap.core.xmlreport())
        
        # with open('report.html', 'w') as f:
        #     f.write(self.zap.core.htmlreport())



        # print(self.zap.spider.scanProgress(scan_id))
        # print(self.zap.ascan.scanProgress(scan_id))