"""Fortigate Log Parser
Parses a Fortigate logfile and presents a communication matrix.

Usage: fg_log_parser.py
  fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

Options:
    -b --countbytes  count bytes for each communication
    -h --help   Show this message.
    --verbose -v  activate verbose messages
    --version   shows version information
    --ignoreerrors  ignore parse errors in logfile format and continue
                    to read the file

    Log Format Options (case sensitive):
    --srcipfield=<srcipfield>  src ip address field [default: srcip]
    --dstipfield=<dstipfield>  dst ip address field [default: dstip]
    --dstportfield=<dstportfield>  dst port field [default: dstport]
    --protofield=<protofield>  protocol field [default: proto]

    --sentbytesfield=<sentbytesfield>  field for sent bytes [default: sentbyte]
    --rcvdbytesfield=<rcvdbytesfield>  field for rcvd bytes [default: rcvdbyte]


"""

__author__ = 'olivier'

try:
    from docopt import docopt
    import re
    import sys
    import logging as log
except ImportError as ioex:
    log.error("Could not import a required module")
    log.error(ioex)
    sys.exit(1)


def split_kv(line):
    """
    Splits lines in key and value pairs and returns a dictionary.
    """
    kvdelim = '='  # key and value deliminator
    logline = {}  # dictionary for logline
    # split line in key and value pairs
    # regex matches internal sub strings such as key = "word1 word2"
    for field in re.findall(r'(?:[^\s,""]|"(?:\\.|[^""])*")+', line):
        key, value = field.split(kvdelim)
        logline[key] = value
    return logline


def read_fg_firewall_log(logfile,
                         logformat,
                         countbytes=False,
                         ignoreerrors=False):
    """
    Reads fortigate logfile and returns communication matrix as a dictionary.

    Parameters:
        logfile         Logfile to parse
        logformat       dictionary containing log format
        countbytes      sum up bytes sent and received
        ignoreerrors    ignore parse errors

    """
    log.info("Function: read_fg_firewall_log started with parameters: ")
    log.info("Logfile: %s", logfile)
    log.info("Option countbytes: %s", countbytes)
    log.info("Option ignoreerrors: %s", ignoreerrors)

    # assign log format options from logformat dict
    srcipfield = logformat['srcipfield']
    dstipfield = logformat['dstipfield']
    dstportfield = logformat['dstportfield']
    protofield = logformat['protofield']
    sentbytesfield = logformat['sentbytesfield']
    rcvdbytesfield = logformat['rcvdbytesfield']

    matrix = {}

    with open(logfile, 'r') as infile:
        # parse each line in file
        linecount = 0  # linecount for detailed error message
        for line in infile:
            """
            For loop creates a nested dictionary with multiple levels.

            Level description:
            Level 1:        srcips (source ips)
            Level 2:        dstips (destination ips)
            Level 3:        dstport (destination port number)
            Level 4:        proto (protocol number)
            Level 5:        occurrence count
                            sentbytes
                            rcvdbytes
            """

            # split each line in key and value pairs.
            logline = split_kv(line)
            linecount += 1

            # check if necessary log fields are present and assign them
            # to variables
            try:
                srcip = logline[srcipfield]
                dstip = logline[dstipfield]
                dstport = logline[dstportfield]
                proto = translate_protonr(logline[protofield])
                # if user has specified --countbytes
                if countbytes:
                    sentbytes = logline[sentbytesfield]
                    rcvdbytes = logline[rcvdbytesfield]
            except KeyError as kerror:
                log.error("Parse error on line %s, field %s",
                          linecount, kerror)
                # check if user has specified --ignoreerrors
                if not ignoreerrors:
                    log.error("Consult help message for log format options")
                    log.error("or you can try the --ignoreerrors option")
                    sys.exit(1)

            # extend matrix for each source ip
            if srcip not in matrix:
                log.info("Found new srcip %s", srcip)
                matrix[srcip] = {}
            # extend matrix for each dstip in srcip
            if dstip not in matrix[srcip]:
                log.info("Found new dstip: %s for sourceip: %s", dstip, srcip)
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
        log.info("Parsed %s lines in logfile: %s ", linecount, logfile)
    return matrix


def translate_protonr(protocolnr):
    """
    Translates ports as names.

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
        return "ICMP"   # icmp has protocol nr 1
    elif int(protocolnr) == 6:
        return "TCP"    # tcp has protocol nr 6
    elif int(protocolnr) == 17:
        return "UDP"    # udp has protocol nr 17
    else:
        return protocolnr


def print_communication_matrix(matrix, indent=0):
    """
    Prints the communication matrix in a nice format.
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
    Main function.
    """
    # get arguments from docopt
    arguments = docopt(__doc__)
    arguments = docopt(__doc__, version='Fortigate Log Parser 0.3')
    # assign docopt argument
    # check module documentattion for argument description
    logfile = arguments['<logfile>']
    countbytes = arguments['--countbytes']
    ignoreerrors = arguments['--ignoreerrors']
    verbose = arguments['--verbose']

    # define logfile format
    # note: default values are set in the docopt string, see __doc__
    logformat = {'srcipfield': arguments['--srcipfield'],
                 'dstipfield': arguments['--dstipfield'],
                 'dstportfield': arguments['--dstportfield'],
                 'protofield': arguments['--protofield'],
                 'sentbytesfield': arguments['--dstportfield'],
                 'rcvdbytesfield': arguments['--rcvdbytesfield']
                 }

    # set loglevel
    if verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose output activated.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")
    log.info("Script was started with arguments: ")
    log.info(arguments)

    # check if logfile argument is present
    if logfile is None:
        print __doc__
        sys.exit(1)

    # parse fortigate log
    log.info("Reading firewall log...")
    matrix = read_fg_firewall_log(logfile, logformat, countbytes, ignoreerrors)
    print_communication_matrix(matrix)
    return 0

if __name__ == "__main__":
    sys.exit(main())
