#!/usr/bin/python3
"""Fortigate Log Parser

Parses a Fortigate log file and presents a communication matrix.
"""

__author__ = 'olivier'
__title__ = 'fg_log_parser'
__version__ = '0.3'

import sys
import re
import json
import logging as log
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Union

# Pre-compiled regex for splitting key-value pairs (avoids recompilation per line)


def load_hosts_csv(csv_file: str) -> Dict[str, str]:
    """
    Load hosts CSV file and return address-to-name lookup dictionary.

    CSV format (semicolon-delimited):
        name;addr;addr6
        host.addr1;10.0.1.100;fd00:1::100

    Returns dict mapping both IPv4 and IPv6 addresses to host names.
    """
    hosts = {}
    with open(csv_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        if len(lines) < 2:
            return hosts
        # skip header line
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(';')
            if len(parts) >= 2:
                name = parts[0]
                addr = parts[1] if len(parts) > 1 else ''
                addr6 = parts[2] if len(parts) > 2 else ''
                if addr:
                    hosts[addr] = name
                if addr6:
                    hosts[addr6] = name
    return hosts


KV_PATTERN = re.compile(r'(?:[^\s,""]|"(?:\\.|[^""])*")+')


def split_kv(line: str) -> Dict[str, str]:
    """
    Splits lines in key and value pairs and returns a dictionary.

    Example:
        >>> line = 'srcip=192.168.1.1 dstip=8.8.8.8 \
        ...         dport=53 proto=53 dstcountry="United States"'
        >>> split_kv(line)
        {'srcip': '192.168.1.1', 'dstip': '8.8.8.8', 'dport': '53', 'proto': '53', 'dstcountry': '"United States"'}

    """
    kvdelim = '='  # key and value deliminator
    logline = {}  # dictionary for logline
    # split line in key and value pairs using pre-compiled regex
    for field in KV_PATTERN.findall(line):
        if kvdelim in field:
            key, value = field.split(kvdelim, 1)  # maxsplit=1 handles "key=val=ue"
            logline[key] = value
    return logline


def check_log_format(line: str, srcipfield: str, dstipfield: str) -> bool:
    """
    Checks if srcipfield and dstipfield appear in the raw log line string.

    Args:
        line: Raw log line string
        srcipfield: Field name to search for (e.g., 'srcip')
        dstipfield: Field name to search for (e.g., 'dstip')

    Returns:
        True if both fields found in line, False otherwise

    Examples:
        >>> line ='srcip=192.168.1.1 dstip=8.8.8.8 dstport=53 proto=53'
        >>> check_log_format(line, "srcip", "dstip")
        True
        >>> line ='srcip=192.168.1.1 dstport=53 proto=53'
        >>> check_log_format(line, "srcip", "dstip")
        False
        >>> line = ''
        >>> check_log_format(line, "srcip", "dstip")
        False
    """
    log.debug("check_log_format: checking line: %s", line[:200])
    if srcipfield in line and dstipfield in line:
        log.debug("check_log_format: found srcipfield %s", srcipfield)
        log.debug("check_log_format: found dstipfield %s", dstipfield)
        return True
    else:
        return False


def translate_protonr(protocolnr: Optional[str]) -> Union[str, int, None]:
    """
    Translates ports as names.

    Examples:
        >>> translate_protonr(53)
        53
        >>> translate_protonr(1)
        'ICMP'
        >>> translate_protonr(6)
        'TCP'
        >>> translate_protonr(17)
        'UDP'
    """
    # check if function input was a integer
    # and translate if we know translation
    try:
        if int(protocolnr) == 1:
            return "ICMP"   # icmp has protocol nr 1
        elif int(protocolnr) == 6:
            return "TCP"    # tcp has protocol nr 6
        elif int(protocolnr) == 17:
            return "UDP"    # udp has protocol nr 17
        else:
            return int(protocolnr)
    # if function input was something else than int
    except (ValueError, AttributeError, TypeError):
        return protocolnr


def get_communication_matrix(logfile: str,
                             logformat: Dict[str, str],
                             countbytes: bool = False,
                             noipcheck: bool = False,
                             showaction: bool = False) -> Dict[str, Any]:
    """
    Reads firewall logfile and returns communication matrix as a dictionary.

    Parameters:
        logfile         Logfile to parse
        logformat       dictionary containing log format
        countbytes      sum up bytes sent and received

    Sample return matrix (one logline parsed):
        {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

    Example:

    """

    log.debug("get_communication_matrix() started with parameters: ")
    log.debug("Option logfile: %s", logfile)
    log.debug("Option countbytes: %s", countbytes)
    log.debug("Option showaction: %s", showaction)

    # validate file exists before processing
    logfile_path = Path(logfile)
    if not logfile_path.exists():
        log.error("Logfile not found: %s", logfile)
        sys.exit(1)
    if not logfile_path.is_file():
        log.error("Path is not a file: %s", logfile)
        sys.exit(1)

    # assign log format options from logformat dict
    srcipfield = logformat['srcipfield']
    dstipfield = logformat['dstipfield']
    dstportfield = logformat['dstportfield']
    protofield = logformat['protofield']
    sentbytesfield = logformat['sentbytesfield']
    rcvdbytesfield = logformat['rcvdbytesfield']
    actionfield = logformat['actionfield']

    matrix = {}  # communication matrix

    with open(logfile, 'r', encoding='utf-8', errors='replace') as infile:
        # parse each line in file
        linecount = 1  # linecount for detailed error message

        for line in infile:
            # Communication matrix structure:
            # Level 1: srcip (source IP)
            # Level 2: dstip (destination IP)
            # Level 3: dstport (destination port)
            # Level 4: proto (protocol)
            # Level 5: count, sentbytes, rcvdbytes

            # check if necessary fields are in first line
            if linecount == 1 and not noipcheck:
                # print error message if srcip or dstip are missing
                if not check_log_format(line, srcipfield, dstipfield):
                    log.error("Required fields missing in line %s", linecount)
                    log.error("Expected fields: '%s' and '%s'", srcipfield, dstipfield)
                    log.error("Line content: %s", line[:200])
                    sys.exit(1)

            # split each line in key and value pairs.
            logline = split_kv(line)
            linecount += 1

            # get() does substitute missing values with None
            # missing log fields will show None in the matrix
            srcip = logline.get(srcipfield)
            dstip = logline.get(dstipfield)
            dstport = logline.get(dstportfield)
            proto = translate_protonr(logline.get(protofield))
            # user has set --action
            if showaction:
                action = logline.get(actionfield)
            # if user has set --countbytes
            if countbytes:
                sentbytes = logline.get(sentbytesfield)
                rcvdbytes = logline.get(rcvdbytesfield)
            # extend matrix for each source ip
            if srcip not in matrix:
                log.debug("Found new srcip %s", srcip)
                matrix[srcip] = {}
            # extend matrix for each dstip in srcip
            if dstip not in matrix[srcip]:
                log.debug("Found new dstip: %s for sourceip: %s", dstip, srcip)
                matrix[srcip][dstip] = {}
            # extend matrix for each port in comm. pair
            if dstport not in matrix[srcip][dstip]:
                matrix[srcip][dstip][dstport] = {}
            # if proto not in matrix extend matrix
            if proto not in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto] = {}
                matrix[srcip][dstip][dstport][proto]["count"] = 1
                if showaction:
                    matrix[srcip][dstip][dstport][proto]["action"] = action
                if countbytes:
                    try:
                        matrix[srcip][dstip][dstport][proto]["sentbytes"] = int(sentbytes) if sentbytes else 0
                        matrix[srcip][dstip][dstport][proto]["rcvdbytes"] = int(rcvdbytes) if rcvdbytes else 0
                    except (ValueError, TypeError) as e:
                        log.warning("Line %s: Invalid byte values (sent=%s, rcvd=%s): %s",
                                    linecount, sentbytes, rcvdbytes, e)
                        matrix[srcip][dstip][dstport][proto]["sentbytes"] = 0
                        matrix[srcip][dstip][dstport][proto]["rcvdbytes"] = 0
            # if proto is already in matrix
            # increase count of variable count and sum bytes
            elif proto in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto]["count"] += 1
                if countbytes:
                    try:
                        matrix[srcip][dstip][dstport][proto]["sentbytes"] += int(sentbytes) if sentbytes else 0
                    except (TypeError, ValueError) as e:
                        log.warning("Line %s: Invalid sentbytes value '%s': %s", linecount, sentbytes, e)
                    try:
                        matrix[srcip][dstip][dstport][proto]["rcvdbytes"] += int(rcvdbytes) if rcvdbytes else 0
                    except (TypeError, ValueError) as e:
                        log.warning("Line %s: Invalid rcvdbytes value '%s': %s", linecount, rcvdbytes, e)
        log.info("Parsed %s lines in logfile: %s ", linecount, logfile)
    return matrix


def print_communication_matrix(matrix: Dict[str, Any], indent: int = 0,
                               hosts: Optional[Dict[str, str]] = None,
                               _level: int = 0) -> None:
    """
    Prints the communication matrix in a nice format.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix(matrix)
    192.168.1.1
        8.8.8.8
            53
                UDP
                    count
                        1
    """
    if hosts is None:
        hosts = {}
    for key, value in matrix.items():
        # values are printed with 4 whitespace indent
        line = '    ' * indent + str(key)
        # Add hostname for srcip (level 0) and dstip (level 1)
        if _level in (0, 1) and key and hosts.get(key):
            line += f" ({hosts.get(key)})"
        print(line)
        if isinstance(value, dict):
            print_communication_matrix(value, indent+1, hosts, _level+1)
        else:
            print('    ' * (indent+1) + str(value))
    return None

def print_communication_matrix_as_csv(matrix: Dict[str, Any],
                                      countbytes: bool = False,
                                      showaction: bool = False,
                                      hosts: Optional[Dict[str, str]] = None) -> None:
    """
    Prints communication matrix in csv format.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix_as_csv(matrix)
    srcip;src.name;dstip;dst.name;dport;proto;count
    192.168.1.1;;8.8.8.8;;53;UDP;1

    Example 2 (option countbytes set):
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1, 'sentbytes': 10, 'rcvdbytes': 10}}}}}
    >>> print_communication_matrix_as_csv(matrix, countbytes=True)
    srcip;src.name;dstip;dst.name;dport;proto;count;sentbytes;rcvdbytes
    192.168.1.1;;8.8.8.8;;53;UDP;1;10;10

    """
    if hosts is None:
        hosts = {}
    # Dynamic header based on options
    header = ["srcip", "src.name", "dstip", "dst.name", "dport", "proto", "count"]
    if showaction:
        header.append("action")
    if countbytes:
        header.extend(["sentbytes", "rcvdbytes"])
    print(";".join(header))

    for srcip in matrix:
        for dstip in matrix[srcip]:
            for dport in matrix[srcip][dstip]:
                for proto in matrix[srcip][dstip][dport]:
                    src_name = hosts.get(srcip, "") if srcip else ""
                    dst_name = hosts.get(dstip, "") if dstip else ""
                    row = [str(srcip or ""), src_name, str(dstip or ""), dst_name,
                           str(dport or ""), str(proto or ""),
                           str(matrix[srcip][dstip][dport][proto].get("count", ""))]
                    if showaction:
                        row.append(str(matrix[srcip][dstip][dport][proto].get("action") or ""))
                    if countbytes:
                        row.append(str(matrix[srcip][dstip][dport][proto].get("sentbytes") or ""))
                        row.append(str(matrix[srcip][dstip][dport][proto].get("rcvdbytes") or ""))
                    print(";".join(row))

def print_communication_matrix_as_json(matrix: Dict[str, Any],
                                       countbytes: bool = False,
                                       showaction: bool = False,
                                       hosts: Optional[Dict[str, str]] = None) -> None:
    """
    Prints communication matrix in JSON format (flat array structure).

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix_as_json(matrix)
    [
      {
        "srcip": "192.168.1.1",
        "src.name": "",
        "dstip": "8.8.8.8",
        "dst.name": "",
        "dport": "53",
        "proto": "UDP",
        "count": 1
      }
    ]

    Example 2 (option countbytes set):
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1, 'sentbytes': 10, 'rcvdbytes': 10}}}}}
    >>> print_communication_matrix_as_json(matrix, countbytes=True)
    [
      {
        "srcip": "192.168.1.1",
        "src.name": "",
        "dstip": "8.8.8.8",
        "dst.name": "",
        "dport": "53",
        "proto": "UDP",
        "count": 1,
        "sentbytes": 10,
        "rcvdbytes": 10
      }
    ]
    """
    if hosts is None:
        hosts = {}
    records = []

    for srcip in matrix:
        for dstip in matrix[srcip]:
            for dport in matrix[srcip][dstip]:
                for proto in matrix[srcip][dstip][dport]:
                    src_name = hosts.get(srcip, "") if srcip else ""
                    dst_name = hosts.get(dstip, "") if dstip else ""
                    record = {
                        "srcip": srcip,
                        "src.name": src_name,
                        "dstip": dstip,
                        "dst.name": dst_name,
                        "dport": dport,
                        "proto": proto,
                        "count": matrix[srcip][dstip][dport][proto].get("count")
                    }

                    if showaction:
                        record["action"] = matrix[srcip][dstip][dport][proto].get("action")

                    if countbytes:
                        record["sentbytes"] = matrix[srcip][dstip][dport][proto].get("sentbytes")
                        record["rcvdbytes"] = matrix[srcip][dstip][dport][proto].get("rcvdbytes")

                    records.append(record)

    print(json.dumps(records, indent=2))

def main() -> int:
    """
    Main function.
    """
    # create argument parser
    parser = argparse.ArgumentParser(
        description='Parses a Fortigate log file and presents a communication matrix.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Parse Fortigate Log:
    fg_log_parser.py -f fg.log
  Parse Iptables Log:
    fg_log_parser.py -f filter --srcipfield=SRC --dstipfield=DST --dstportfield=DPT --protofield=PROTO
  Parse Fortianalyzer Log:
    fg_log_parser.py -f faz.log --srcipfield=src --dstipfield=dst

Host File Format (--csv-hosts-file):
  Semicolon-delimited CSV with header: name;addr;addr6
  Example:
    name;addr;addr6
    webserver;10.0.1.100;fd00:1::100
    database;10.0.2.50;fd00:2::50
''')

    # required arguments
    parser.add_argument('-f', '--file', dest='file', metavar='<logfile>', required=True,
                        help='Logfile to parse')

    # boolean flags
    parser.add_argument('-s', '--showaction', action='store_true',
                        help='Show action field')
    parser.add_argument('-b', '--countbytes', action='store_true',
                        help='Count bytes for each communication quartet')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Activate verbose messages')
    parser.add_argument('-n', '--noipcheck', action='store_true',
                        help='Do not check if src and dst ip are present')
    parser.add_argument('-c', '--csv', action='store_true',
                        help='Print matrix in csv format (default is nested format)')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Print matrix in json format (default is nested format)')
    parser.add_argument('--version', action='version', version='Fortigate Log Parser 0.3')

    # log format options
    parser.add_argument('--srcipfield', default='srcip',
                        help='Src ip address field (default: srcip)')
    parser.add_argument('--dstipfield', default='dstip',
                        help='Dst ip address field (default: dstip)')
    parser.add_argument('--dstportfield', default='dstport',
                        help='Dst port field (default: dstport)')
    parser.add_argument('--protofield', default='proto',
                        help='Protocol field (default: proto)')
    parser.add_argument('--actionfield', default='action',
                        help='Action field (default: action)')
    parser.add_argument('--sentbytesfield', default='sentbyte',
                        help='Field for sent bytes (default: sentbyte)')
    parser.add_argument('--rcvdbytesfield', default='rcvdbyte',
                        help='Field for rcvd bytes (default: rcvdbyte)')
    parser.add_argument('--csv-hosts-file', metavar='<file>',
                        help='CSV file for IP-to-name resolution (adds src.name, dst.name)')

    # parse arguments
    args = parser.parse_args()

    # assign arguments
    logfile = args.file
    countbytes = args.countbytes
    verbose = args.verbose
    noipcheck = args.noipcheck
    csv = args.csv
    jsonformat = args.json
    showaction = args.showaction
    csv_hosts_file = args.csv_hosts_file

    # define logfile format
    logformat = {'srcipfield': args.srcipfield,
                 'dstipfield': args.dstipfield,
                 'dstportfield': args.dstportfield,
                 'protofield': args.protofield,
                 'sentbytesfield': args.sentbytesfield,
                 'rcvdbytesfield': args.rcvdbytesfield,
                 'actionfield': args.actionfield
                 }

    # set loglevel
    if verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.debug("Verbose output activated.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")
    log.debug("Script was started with arguments: %s", args)

    # load hosts file if specified
    hosts = {}
    if csv_hosts_file:
        hosts_path = Path(csv_hosts_file)
        if not hosts_path.exists():
            log.error("Hosts file not found: %s", csv_hosts_file)
            sys.exit(1)
        hosts = load_hosts_csv(csv_hosts_file)
        log.debug("Loaded %d host entries from %s", len(hosts), csv_hosts_file)

    # parse log
    log.debug("Reading firewall log...")
    matrix = get_communication_matrix(logfile, logformat, countbytes, noipcheck, showaction)
    if jsonformat:
        print_communication_matrix_as_json(matrix, countbytes, showaction, hosts)
    elif csv:
        print_communication_matrix_as_csv(matrix, countbytes, showaction, hosts)
    else:
        print_communication_matrix(matrix, hosts=hosts)
    return 0

if __name__ == "__main__":
    sys.exit(main())
