#!/usr/bin/env python3

import sys
import time
import logging
import argparse

from dotenv import load_dotenv, find_dotenv

from scanners.zap_scanner import ZapScanner
from scanners.nexpose_scanner import NexposeScanner


load_dotenv(find_dotenv())

logging.basicConfig(filename='vuln-scanner.log', level=logging.INFO)


def main(config):

    scanners = [ZapScanner(), NexposeScanner()]

    scan_results = {}
    scan_status_list = []

    if config['target']:
        for scanner in scanners:
            scanner.start(config['scan_name'], config['target'])
            time.sleep(1)

    elif config['pause']:
        for scanner in scanners:
            scanner.pause(config['scan_name'])
            time.sleep(1)
        
    elif config['resume']:
        for scanner in scanners:
            scanner.resume(config['scan_name'])
            time.sleep(1)
    else:
        for scanner in scanners:
            scanner.get_scan_status(config.get('scan_name'), scan_status_list)
            scanner.get_scan_results(config.get('scan_name'), scan_results)
            time.sleep(2)

    scanner.print_scan_status(scan_status_list)
    scanner.print_report(scan_results)
    
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scan-name', required=True, help='Specify a scan name')
    parser.add_argument('-i', '--scan-id', help='Specify the scan id', type=int)
    parser.add_argument('-t', '--target', help='Specify the Target URL or IP')
    parser.add_argument('-p', '--pause', action='store_true', help='Pause a specified scan')
    parser.add_argument('-r', '--resume', action='store_true', help='Resume a specified scan')
    parser.add_argument('-v', '--version', action='version', version='VulnScanner 1.0')
    args = parser.parse_args()

    config = {
        'scan_name': args.scan_name,
        'target': args.target,
        'pause': args.pause,
        'resume': args.resume
    }
    
    main(config)

    exit(0)