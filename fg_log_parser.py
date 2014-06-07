#!/usr/local/bin/python2.7
""" Fortigate Log Parser

Usage: fg_log_parser.py
  fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

Options:
    -b --countbytes  count bytes for each communication
    -h --help   Show this message.
    --verbose  activate verbose messages
    --version  shows version information
"""
__author__ = 'olivier'

from docopt import docopt
import re
import sys
import logging as log


def split_kv(line):
    """
    splits lines in key and value pairs and returns a dict
    """
    kvdelim = '='  # key and value deliminator
    logline = {}
    # split line in key and value pairs
    # regex matches internal substrings such as key = "word1 word2"
    for field in re.findall(r'(?:[^\s,""]|"(?:\\.|[^""])*")+', line):
        key, value = field.split(kvdelim)
        logline[key] = value
    return logline


def read_fg_firewall_log(logfile, countbytes=False):
    """
    reads fortigate logfile and returns a communication matrix as dict
    """

    matrix = {}

    with open(logfile, 'r') as infile:
        # parse each line in file
        for line in infile:
            """
            for loop creates a nested dictionary with multiple levels
            level 1:        srcips (source ips)
            level 2:       dstips (destination ips)
            level 3:        dstport (destination port number)
            level 4:        proto (protocoll number)
            level 5:         occurence count
                            sendbytes
                            rcvdbytes
            """

            # split each line in key and value pairs
            logline = split_kv(line)

            # check if necessary logfiles are present and assign them
            # to variables
            try:
                srcip = logline['srcip']
                dstip = logline['dstip']
                dstport = logline['dstport']
                proto = translate_protonr(logline['proto'])
                # if user has specified --countbytes
                if countbytes:
                    sentbytes = logline['sentbyte']  # not used now
                    rcvdbytes = logline['rcvdbyte']  # not used now
            except KeyError as kerror:
                log.error("could not parse logfile %s ", logfile)
                log.error("could parse logfileds, python error message is: ")
                log.error(kerror)

            # extend matrix for each source ip
            if srcip not in matrix:
                matrix[srcip] = {}
            # extend matrix for each dstip in srcip
            if dstip not in matrix[srcip]:
                matrix[srcip][dstip] = {}
            # extend matrix for each port in comm. pair
            if dstport not in matrix[srcip][dstip]:
                matrix[srcip][dstip][dstport] = {}
            # if proto not in matrix extend matrix
            if proto not in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto] = {}
                matrix[srcip][dstip][dstport][proto]["count"] = 1
                if countbytes:
                    matrix[srcip][dstip][dstport][proto]["sentbytes"] \
                        = int(sentbytes)
                    matrix[srcip][dstip][dstport][proto]["rcvdbytes"] \
                        = int(rcvdbytes)
            # increase count of variable count and sum bytes
            elif proto in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto]["count"] += 1
                if countbytes:
                    matrix[srcip][dstip][dstport][proto]["sentbytes"] \
                        += int(sentbytes)
                    matrix[srcip][dstip][dstport][proto]["rcvdbytes"] \
                        += int(rcvdbytes)
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


# TODO: add print to csv function
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
    verbose = arguments['--verbose']

    # set loglevel
    if verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose output activated.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")
    log.info("script was startet with arguments: ")
    log.info(arguments)

    # check if logfile argument is present
    if logfile is None:
        print __doc__
        sys.exit(2)

    # parse fortigate log
    log.info("reading firewall log...")
    matrix = read_fg_firewall_log(logfile, countbytes)
    print_communication_matrix(matrix)
    return 1

if __name__ == "__main__":
    sys.exit(main())
