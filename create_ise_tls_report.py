#!/usr/bin/env python3
#! -*- coding: utf-8 -*-

__author__ = 'Johannes Luther'
__email__ = ' johannes.luther@isarnet.de'
__date__= '28.10.2024'

"""
Create ISE TLS report for 802.1X

This module creates a report, which includes the used TLS ciphers and versions
for 802.1X TLS based EAP methods, based on an input JSON file.
"""

# Imports #####################################################################
## Standard library imports
import argparse
import csv
import json
import logging
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path


# CONSTANTS ###################################################################
PROGRAM_NAME = "ISE 802.1X supplicant TLS reporter"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SCRIPT_NAME = os.path.basename(__file__)
HOME_DIR = Path.home()

# Log levels: Requires logging module
LOG_LEVEL_ERROR = logging.ERROR
LOG_LEVEL_WARN = logging.WARN
LOG_LEVEL_INFO = logging.INFO
LOG_LEVEL_DEBUG = logging.DEBUG
LOG_LEVEL = LOG_LEVEL_INFO

# Program defaults
REPORT_OUTPUT_FORMATS = ["csv"]
LOG_ENTRY_KEY_ROOT ="_kv"
LOG_ENTRY_KEY_USERNAME = "UserName"
LOG_ENTRY_KEY_TLS_VER = "TLSVersion"
LOG_ENTRY_KEY_TLS_CIPHER = "TLSCipher"
LOG_ENTRY_KEY_NAS_PORT_TYPE = "NAS-Port-Type"
LOG_ENTRY_KEY_EAP_OUTER_METHOD = "EapTunnel"
LOG_ENTRY_KEY_AUTH_METHOD = "EapAuthentication"
LOG_ENTRY_KEY_CALLING_ID = "Calling-Station-ID"
LOG_ENTRY_KEY_CALLED_ID = "Called-Station-ID"
LOG_ENTRY_KEY_AD_USER = "AD-User-SamAccount-Name"

# Command line arguments ######################################################
cmdArgs = argparse.ArgumentParser()

cmdArgs.add_argument(
    "-i", "--input_file", required=True,
    help="Input file for log analysis")

cmdArgs.add_argument(
    "-o", "--output_file", required=False,
    help="Output file for report files")

cmdArgs.add_argument(
    "-f", "--output_file_format", required=False,
    help="Output format for report files",
    choices=REPORT_OUTPUT_FORMATS, default="csv"
    )

cmdArgs.add_argument(
    "-s", "--show_tls_versions", required=False,
    help="Print client records with the given TLS version (e.g. TLSv1.1)")

cmdArgs.add_argument(
    "-v", "--verbose", required=False, action="count", default=0,
    help="Verbosity level (-v/-vv/-vvv/-vvv)" )

args = cmdArgs.parse_args()
###############################################################################

# Logger global configuration #################################################
# Log level
if args.verbose >= 3:
    logLevel = LOG_LEVEL_DEBUG
elif args.verbose == 2:
    logLevel = LOG_LEVEL_INFO
elif args.verbose == 1:
    logLevel = LOG_LEVEL_WARN
else:
    logLevel = LOG_LEVEL

logging.basicConfig(level=logLevel,format='%(asctime)s - %(name)s - %(threadName)s -  %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
###############################################################################
@dataclass
class TLSRecord:
    username: str
    endpoint_mac: str
    source: str
    tls_version: str
    tls_cipher: str
    nas_port_type: str
    auth_method: str
    eap_outer_method: str = ""
    ad_username: str = ""

    def to_csv(self, delimiter: str = ","):
        return f'{self.username}{delimiter}'\
            f'{self.endpoint_mac}{delimiter}'\
            f'{self.source}{delimiter}'\
            f'{self.tls_version}{delimiter}'\
            f'{self.tls_cipher}{delimiter}'\
            f'{self.nas_port_type}{delimiter}'\
            f'{self.auth_method}{delimiter}'\
            f'{self.eap_outer_method}{delimiter}'\
            f'{self.ad_username}'

    def as_dict(self):
        return asdict(self)


@dataclass
class TLSReport:
    records: list[TLSRecord] = field(default_factory=list)
    skip_duplicate_clients: bool = True
    known_clients = set()

    def add_record(self, record: TLSRecord):
            if record.endpoint_mac in self.known_clients and self.skip_duplicate_clients:
                logger.debug(f'Skipping client MAC {record.endpoint_mac}: TLS information already collected')
            else:
                self.records.append(record)
                self.known_clients.add(record.endpoint_mac)
    
    def print_clients_by_tls_version(self, tls_version_string: str):
        output_record_list = []
        for record in self.records:
            if record.tls_version.lower() == tls_version_string.lower():
                output_record_list.append(record.as_dict())

        print(json.dumps(output_record_list))
        
    def to_csv(self, csv_report_filename: str, csv_delimiter: str = ','):
        logger.info(f'Output report to CSV file: {csv_report_filename}')
        try:
            with open(csv_report_filename, 'w', newline='') as csv_report_file:
                csv_report_writer = csv.DictWriter(csv_report_file, 
                    fieldnames = self.records[0].as_dict().keys(),
                    delimiter = csv_delimiter)
                csv_report_writer.writeheader()
                for record in self.records:
                    csv_report_writer.writerow(record.as_dict())
        except IndexError:
            logger.error('Could not export to CSV, because report contains no entries')

def json_log_to_tls_report(log_file_json: str) -> TLSReport:
    """ISE syslog to TLS report CSV generator

    This method

    Args:
        log_file_json (str): _description_
        output_filename (str): _description_
    """

    tls_report = TLSReport()

    with open(log_file_json, 'r') as log_file_json_handler:
        log_entries_json = log_file_json_handler.readlines()
        for line_index, log_entry in enumerate(log_entries_json):
            logger.debug(f"Process entry [{line_index}]: {log_entry}")
            try:
               entry_data:dict = json.loads(log_entry)[LOG_ENTRY_KEY_ROOT]
            except json.decoder.JSONDecodeError:
                logger.error(f"Could not decode entry line {line_index}")
                raise
            except KeyError:
                logger.error(f"Could not find expected root key ({LOG_ENTRY_KEY_ROOT}) "\
                    f"in log entry line {line_index}. Skip entry")
                continue
            # Skip line, if no 802.1X authentication
            if "EapAuthentication" not in entry_data.keys():
                logger.debug(f"Skipping line {line_index}: No EAP authentication")
                continue
            
            tls_record = TLSRecord(
                username = entry_data.get(LOG_ENTRY_KEY_USERNAME),
                endpoint_mac = entry_data.get(LOG_ENTRY_KEY_CALLING_ID),
                source = entry_data.get(LOG_ENTRY_KEY_CALLED_ID),
                nas_port_type = entry_data.get(LOG_ENTRY_KEY_NAS_PORT_TYPE),
                tls_version = entry_data.get(LOG_ENTRY_KEY_TLS_VER),
                tls_cipher = entry_data.get(LOG_ENTRY_KEY_TLS_CIPHER),
                auth_method = entry_data.get(LOG_ENTRY_KEY_AUTH_METHOD, ""),
                eap_outer_method = entry_data.get(LOG_ENTRY_KEY_EAP_OUTER_METHOD),
                ad_username = entry_data.get(LOG_ENTRY_KEY_AD_USER, ""),
            )
            tls_report.add_record(record = tls_record)
    return tls_report


if __name__ == "__main__":
   
    tls_report = json_log_to_tls_report(log_file_json=args.input_file)

    # Output report to CSV file
    if args.output_file and args.output_file_format.lower() == "csv":
        tls_report.to_csv(csv_report_filename=args.output_file)

    # Output to screen
    if args.show_tls_versions:
        tls_report.print_clients_by_tls_version(args.show_tls_versions)
