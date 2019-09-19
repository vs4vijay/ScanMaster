# VulnScanner

Security Tool which scans a target using OpenVAS, Zap, and Nexpose. And consolidates the scan result.


![](/screenshots/screenshot1.png)

---

## Prerequisites

- Python 3
- Zap
- Nexpose
- OpenVAS

---

## Installation

`pip3 install -r requirements.txt`

OR

Run in Virtual Env:

```
python3 -m venv .venv

source .venv/bin/activate

pip3 install -r requirements.txt
```
---


## Configuration

The configuration of scanners will be in Environment File `.env`. There is sample `.env.example` file in the codebase, update the values with the proper API Keys and Credentials details before using. Rename it to `.env`.

---


## Start a scan against a Target

`./main.py --scan-name <scan-name> --target <url>`


## Get scan result

`./main.py --scan-name <scan-name>`


## Pause/Resume a scan result

- `./main.py --scan-name <scan-name> --pause`
- `./main.py --scan-name <scan-name> --resume`


## Targets to Test
- http://scanme.nmap.org
- http://webscantest.com

---


## ToDo
- [ ] Add Nessus
- [ ] Error Stack
- [ ] auto reload
- [ ] Remove logs
- [ ] Save to CSV
- [ ] Make it interactive
- [ ] OOPs
- [ ] Color logging
---

### Scanner Interface:

- start
- scan
- get_scan_status
- get_scan_results
- is_valid_scan
- list_scans
- pause
- resume
- stop


### Development Notes

```python3

        pprint(core.htmlreport())


        # address = rapid7vmconsole.Address(ip=target)
        # asset = rapid7vmconsole.Asset(addresses=[address])


        scan_targets = rapid7vmconsole.IncludedScanTargets(addresses=[target])

        asset = rapid7vmconsole.StaticSite(included_targets=scan_targets)

        scan_scope = rapid7vmconsole.ScanScope(assets=asset)

        site_create_resource = rapid7vmconsole.SiteCreateResource(name=scan_name, scan=scan_scope)

        site = self.nexpose_site.create_site(site=site_create_resource)

        print('Site Created', site)

        adhoc_scan = rapid7vmconsole.AdhocScan(hosts=[target])
        print('adhoc_scan', adhoc_scan)

        site_id = site.id

        scan = self.nexpose.start_scan(site_id, scan=adhoc_scan)
        print('start scan response id', scan.id)
        # scan['vulnerabilities']
        pprint(scan)

if shutdownOnceFinished:
    # Shutdown ZAP once finished
    pprint('Shutdown ZAP -> ' + core.shutdown())

report_config_scope = rapid7vmconsole.ReportConfigScopeResource(scan=nexpose_id)

report_config_categories = rapid7vmconsole.ReportConfigCategoryFilters(included=[])

report_config_filters = rapid7vmconsole.ReportConfigFiltersResource(categories=report_config_categories)

report_config = rapid7vmconsole.Report(name=f'{scan_name}-Report', template='audit-report', format='csv-export', scope=report_config_scope)

        report_config = rapid7vmconsole.Report(name=f'{scan_name}-Report', format='sql-query', query='select * from dim_asset', version='2.3.0')

report_config = rapid7vmconsole.Report(name=f'{scan_name}-SampleXML-Report', format='nexpose-simple-xml', scope=report_config_scope)
report = nexpose_report.create_report(report=report_config)
report_instance = nexpose_report.generate_report(report.id)
nexpose_report.download_report(report.id, report_instance.id)



report_config = rapid7vmconsole.Report(name=f'{scan_name}-sml2-Report', format='xml-export-v2', scope=report_config_scope)
report = nexpose_report.create_report(report=report_config)
report_instance = nexpose_report.generate_report(report.id)
dd = nexpose_report.download_report(report.id, report_instance.id)


report_config = rapid7vmconsole.Report(name=f'{scan_name}-html-Report', format='html', template='audit-report', scope=report_config_scope)
report = nexpose_report.create_report(report=report_config)
report_instance = nexpose_report.generate_report(report.id)
dd = nexpose_report.download_report(report.id, report_instance.id)


report_config.id = 42
report_config.timezone = 'Asia/Calcutta'

report_config.language = 'en-US'
report_config.owner = 1
report_config.organization = 'Organization'

# report_config.component = 'Component'
# report_config.email = rapid7vmconsole.ReportEmail(additional_recipients=['asd@asd.asd'])


# print('self.zap.spider.results', self.zap.spider.results(scan_id))




# Retrieve all tasks
tasks = gmp.get_tasks()

# Get names of tasks
task_names = tasks.xpath('task/name/text()')
pretty_print(task_names)
```