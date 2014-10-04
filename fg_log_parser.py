"""Fortigate Log Parser
Parses a Fortigate logfile and presents a communication matrix.

Usage: fg_log_parser.py
  fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

Options:
    -b --countbytes         Count bytes for each communication quartet
    -h --help               Show this message
    -v --verbose            Activate verbose messages
    --version               Shows version information
    -n --noipcheck          Do not check if src and dst ip are present
    -c --csv                Print matrix in csv format (default is nested format)

    Log Format Options (case sensitive):
    --srcipfield=<srcipfield>       Src ip address field [default: srcip]
    --dstipfield=<dstipfield>       Dst ip address field [default: dstip]
    --dstportfield=<dstportfield>   Dst port field [default: dstport]
    --protofield=<protofield>       Protocol field [default: proto]


    If countbytes options is set you may have to specify:
    --sentbytesfield=<sentbytesfield>  Field for sent bytes [default: sentbyte]
    --rcvdbytesfield=<rcvdbytesfield>  Field for rcvd bytes [default: rcvdbyte]

Examples:
    Parse Fortigate Log:
        fg_log_parser.py -f fg.log
    Parse Iptables Log:
        fg_log_parser.py -f filter --srcipfield=SRC --dstipfield=DST --dstportfield=DPT --protofield=PROTO
    Parse Fortianalyzer Log:
        fg_log_parser.py -f faz.log --srcipfield=src --dstipfield=dst

"""

__author__ = 'olivier'
__title__ = 'fg_log_parser'
__version__ = '0.3'

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

    Example:
        >>> line = 'srcip=192.168.1.1 dstip=8.8.8.8 \
        ...         dport=53 proto=53 dstcountry="United States"'
        >>> split_kv(line)
        {'srcip': '192.168.1.1', 'dport': '53', 'dstip': '8.8.8.8', 'dstcountry': '"United States"', 'proto': '53'}

    """
    kvdelim = '='  # key and value deliminator
    logline = {}  # dictionary for logline
    # split line in key and value pairs
    # regex matches internal sub strings such as key = "word1 word2"
    for field in re.findall(r'(?:[^\s,""]|"(?:\\.|[^""])*")+', line):
        if kvdelim in field:
            key, value = field.split(kvdelim)
            logline[key] = value
    return logline


def check_log_format(line, srcipfield, dstipfield):
    """
    checks if srcipfield and dstipfield are in logline

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
    log.info("check_log_format: checking line: ")
    log.info(line)
    if srcipfield in line and dstipfield in line:
        log.info("check_log_format: found srcipfield %s", srcipfield)
        log.info("check_log_format: found dstipfield %s", dstipfield)
        return True
    else:
        return False


def translate_protonr(protocolnr):
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


def get_communication_matrix(logfile,
                             logformat,
                             countbytes=False,
                             noipcheck=False):
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

    log.info("get_communication_matrix() started with parameters: ")
    log.info("Option logfile: %s", logfile)
    log.info("Option countbytes: %s", countbytes)

    # assign log format options from logformat dict
    srcipfield = logformat['srcipfield']
    dstipfield = logformat['dstipfield']
    dstportfield = logformat['dstportfield']
    protofield = logformat['protofield']
    sentbytesfield = logformat['sentbytesfield']
    rcvdbytesfield = logformat['rcvdbytesfield']

    matrix = {}  # communication matrix

    with open(logfile, 'r') as infile:
        # parse each line in file
        linecount = 1  # linecount for detailed error message

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

            # check if necessary fields are in first line
            if linecount is 1 and not noipcheck:
                # print error message if srcip or dstip are missing
                if not check_log_format(line, srcipfield, dstipfield):
                    log.error("srcipfield or dstipfield not in line: %s ", linecount)
                    log.error("Check Log Format options and consult help message!")
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
            # if user has specified countbytes
            if countbytes:
                sentbytes = logline.get(sentbytesfield)
                rcvdbytes = logline.get(rcvdbytesfield)

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
            # if proto is already in matrix
            # increase count of variable count and sum bytes
            elif proto in matrix[srcip][dstip][dstport]:
                matrix[srcip][dstip][dstport][proto]["count"] += 1
                if countbytes:
                    try:
                        matrix[srcip][dstip][dstport][proto]["sentbytes"] \
                            += int(sentbytes)
                    except TypeError:
                        pass
                    try:
                        matrix[srcip][dstip][dstport][proto]["rcvdbytes"] \
                            += int(rcvdbytes)
                    except TypeError:
                        pass
        log.info("Parsed %s lines in logfile: %s ", linecount, logfile)
    return matrix


def print_communication_matrix(matrix, indent=0):
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
    for key, value in matrix.iteritems():
        # values are printed with 4 whitespace indent
        print '    ' * indent + str(key)
        if isinstance(value, dict):
            print_communication_matrix(value, indent+1)
        else:
            print '    ' * (indent+1) + str(value)
    return None

def print_communication_matrix_as_csv(matrix, countbytes=False):
    """
    Prints communication matrix in csv format.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix_as_csv(matrix)
    srcip;dstip;dport;proto;count;sentbytes;rcvdbytes
    192.168.1.1;8.8.8.8;53;UDP;1

    Example 2 (option countbytes set):
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1, 'sentbytes': 10, 'rcvdbytes': 10}}}}}
    >>> print_communication_matrix_as_csv(matrix, countbytes=True)
    srcip;dstip;dport;proto;count;sentbytes;rcvdbytes
    192.168.1.1;8.8.8.8;53;UDP;1;10;10

    """
    # Header
    print "srcip;dstip;dport;proto;count;sentbytes;rcvdbytes"
    for srcip in matrix.keys():
        for dstip in matrix.get(srcip):
            for dport in matrix[srcip][dstip].keys():
                for proto in matrix[srcip][dstip].get(dport):
                    count = matrix[srcip][dstip][dport][proto].get("count")
                    if countbytes:
                        rcvdbytes = matrix[srcip][dstip][dport][proto].get("rcvdbytes")
                        sentbytes = matrix[srcip][dstip][dport][proto].get("sentbytes")
                        print "%s;%s;%s;%s;%s;%s;%s" % (srcip, dstip, dport, proto, count, rcvdbytes, sentbytes)
                    else:
                        print "%s;%s;%s;%s;%s" % (srcip, dstip, dport, proto, count)


def main():
    """
    Main function.
    """
    # get arguments from docopt
    arguments = docopt(__doc__)
    arguments = docopt(__doc__, version='Fortigate Log Parser 0.3')
    # assign docopt argument
    # check module documentation for argument description
    logfile = arguments['<logfile>']
    countbytes = arguments['--countbytes']
    verbose = arguments['--verbose']
    noipcheck = arguments['--noipcheck']
    csv = arguments['--csv']

    # define logfile format
    # note: default values are set in the docopt string, see __doc__
    logformat = {'srcipfield': arguments['--srcipfield'],
                 'dstipfield': arguments['--dstipfield'],
                 'dstportfield': arguments['--dstportfield'],
                 'protofield': arguments['--protofield'],
                 'sentbytesfield': arguments['--sentbytesfield'],
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

    # parse log
    log.info("Reading firewall log...")
    matrix = get_communication_matrix(logfile, logformat, countbytes, noipcheck)
    if csv:
        print_communication_matrix_as_csv(matrix)
    else:
        print_communication_matrix(matrix)
    return 0

if __name__ == "__main__":
    sys.exit(main())
