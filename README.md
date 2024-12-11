# Cisco ISE 802.1X TLS reporter

## Overview / Motivation

In Cisco ISE as of version 3.4, there is no builtin report to provide a summary about used 802.1X TLS versions and ciphers.  
The only way is using the RADIUS authentication report and check the used `TLSCipher` and `TLSVersion` in the report details per client.  
In large scale environments, this is not a viable (or efficient) approach.

As of ISE 3.4 there is no way to extract this information by ERS/OpenAPI, MNT-API, DataConnect, pxGrid or ISE Log Analytics. The only way to get this information besides the Authentication detail report are:
- RADIUS packet capture
- ISE remote logging targets (Syslog) within the "Passed Authentications" log category (message code 5200).

Using this Python tool, a CSV (or CLI shell) report is created.

## Requirements

### Overview

- Python 3.11 (no external Python packages)
- Syslog-ng
- A __well__ formatted input file, based on the ISE syslogs
- Recommended: `jq` 

### Input syslog file

> Also check out this Cisco community document [here](https://community.cisco.com/t5/network-access-control/howto-tls-cipher-and-version-analysis-for-802-1x-clients-using/m-p/5224189#M593188)

To create the report and input file is needed, which contains the needed RADIUS passed authentication data. To optimize the processing (and avoid plaintext parsing, based on Regular Expressions), a special `syslog-ng` configuration is needed, to store:
- only the relevant data for the report (save disk space)
- the data in a simple machine readable / structured format (`json`), to improve processing speed and lower code complexity

An example for a syslog-ng configuration can be found [here](syslog-ng/ise_passed_auth.conf).

The destination data (input data for this script) should be structured like:

```json
{
  "_kv": {
    "UserName": "<ISE-USER-NAME>",
    "TLSVersion": "<TLS-VERSION>",
    "TLSCipher": "<TLS-CIPHER>",
    "NAS-Port-Type": "<RADIUS-NAS-PORT-TYPE>",
    "EapTunnel": "<EAP-TUNNEL-METHOD-OPTIONAL>",
    "EapAuthentication": "<AUTH-METHOD>",
    "Calling-Station-ID": "<RADIUS-CALLING-STATION-ID>",
    "Called-Station-ID": "<RADIUS-CALLED-STATION-ID>",
    "AD-User-SamAccount-Name": "<AD-USER-NAME-OPTIONAL>"
  },
  ...
}
```
Typically, the following additional information can be extracted from these fields, when using Cisco NADs:
- `UserName`: Find out the end device
- `NAS-Port-Type`: Is it a wireless or wired endpoint
- `Calling-Station-ID`: Endpoint MAC
- `Called-Station-ID`: Endpoint location (switch MAC or SSID)

## Usage

When there is some data, the Python script may be used against the collected data.

Examples:
```bash
# Show all TLS 1.0 clients
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log.json -s tlsv1

# Show all TLS 1.1 clients
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log -s tlsv1.1

# Show all TLS 1.2 clients
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log -s tlsv1.2

# Pretty print the output (based on the TLS1.1 client example) using jq (which must be installed)
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log -s tlsv1.1 | jq

# Count the number of clients (based on the TLS1.1 client example) using jq (which must be installed)
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log -s tlsv1.1 | jq length

# Export complete report as CSV
python create_ise_tls_report.py -i /var/log/ise/passed_auth_log -o ise_tls_report.csv
```

Using `jq`, very powerful data filtering is possible, for CLI based outputs.
