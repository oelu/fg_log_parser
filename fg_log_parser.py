#!/usr/local/bin/python2.7
""" Fortigate Log Parser

Usage: fg_log_parser.py
  fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

Options:
    -h --help   Show this message.
    --version  shows version information
    -b --countbytes  count bytes for each communication
"""
__author__ = 'olivier'

from docopt import docopt
from pprint import pprint
import re
import sys


def split_kv(line):
    """
    splits lines in key and value pairs and returns a dict
    """
    KVDELIM = '='  # key and value deliminator
    logline = {}
    for field in re.findall(r'(?:[^\s,""]|"(?:\\.|[^""])*")+', line):
        key, value = field.split(KVDELIM)
        logline[key] = value
    return logline


def read_fg_firewall_log(logfile, countbytes=False):
    """
    reads fortigate logfile and returns a communication matrix as dict
    """

    matrix = {}

    with open(logfile, 'r') as infile:
        for line in infile:
            logline = split_kv(line)
            """
            for loop creates a dictionary with multiple levels
            l1: srcips (source ips)
             l2: dstips (destination ips)
              l3: dstport (destination port number)
               l4: proto (protocoll number)
                l5: occurence count
            """
            srcip = logline['srcip']
            dstip = logline['dstip']
            dstport = logline['dstport']
            proto = translate_protonr(logline['proto'])
            if countbytes:
                sentbytes = logline['sentbyte']  # not used now
                rcvdbytes = logline['rcvdbyte']  # not used now

            if srcip not in matrix:
                matrix[srcip] = {}
            if dstip not in matrix[srcip]:
                matrix[srcip][dstip] = {}
            if dstport not in matrix[srcip][dstip]:
                matrix[srcip][dstip][dstport] = {}
            if proto not in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto] = {}
                matrix[srcip][dstip][dstport][proto]["count"] = 1
                if countbytes:
                    matrix[srcip][dstip][dstport][proto]["sentbytes"] = int(sentbytes)
                    matrix[srcip][dstip][dstport][proto]["rcvdbytes"] = int(rcvdbytes)
            elif proto in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto]["count"] += 1
                if countbytes:
                    matrix[srcip][dstip][dstport][proto]["sentbytes"] += int(sentbytes)
                    matrix[srcip][dstip][dstport][proto]["rcvdbytes"] += int(rcvdbytes)
    return matrix

def translate_protonr(protocolnr):
    """
    Translates port nr as names.

    Example:
        >>> translate_protonr(53)
        53
        >>> translate_protonr(1)
        'ICMP'
        >>> translate_protonr(6)
        'TCP'
        >>> translate_protonr(17)
        'UDP'
    """
    if int(protocolnr) == 1:
        return "ICMP"   # icmp has protonr 1
    elif int(protocolnr) == 6:
        return "TCP"    # tcp has protonr 6
    elif int(protocolnr) == 17:
        return "UDP"    # udp has protonr 17
    else:
        return protocolnr


def print_communication_matrix(matrix, indent=0):
    """
    prints the communication matrix in a nice format
    """
    # pprint(matrix)
    for key, value in matrix.iteritems():
        print '\t' * indent + str(key)
        if isinstance(value, dict):
            print_communication_matrix(value, indent+1)
        else:
            print '\t' * (indent+1) + str(value)
    return None


def main():
    """
    main function
    """
    # gets arguments from docopt
    arguments = docopt(__doc__)
    arguments = docopt(__doc__, version='Fortigate Log Parser 0.1')
    # assigns docopt argument to logfile
    logfile = arguments['<logfile>']
    countbytes = arguments['--countbytes']

    if logfile is None:
        print __doc__
        sys.exit(2)

    # parse fortigate log
    matrix = read_fg_firewall_log(logfile, countbytes)
    print_communication_matrix(matrix)
    return 1

if __name__ == "__main__":
    sys.exit(main())
