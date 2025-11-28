# Fortigate Log Parser

<!-- toc -->
* [Installation](#installation)
  * [Download the Repository](#download-the-repository)
  * [Requirements](#requirements)
  * [Make the Script Executable (Optional)](#make-the-script-executable-optional)
* [Usage](#usage)
* [Features](#features)
* [Example Session](#example-session)
* [Example Session with CSV output](#example-session-with-csv-output)
* [Example Session with JSON output](#example-session-with-json-output)
* [Tests](#tests)

<!-- toc stop -->

*Parses a Fortigate traffic log and presents a communication matrix.*

# Installation

## Download the Repository

Clone the repository from GitHub:

    git clone https://github.com/yourusername/fg_log_parser.git
    cd fg_log_parser

Alternatively, download the repository as a ZIP file and extract it.

## Requirements

This script uses only Python 3 built-in modules and has no external dependencies.

## Make the Script Executable (Optional)

On Linux/macOS, you can make the script executable:

    chmod +x fg_log_parser.py

Then run it directly:

    ./fg_log_parser.py -f your_logfile.log

# Usage
The help message contains information about general options and log format options.

    $ python3 fg_log_parser.py --help
    usage: fg_log_parser.py [-h] -f <logfile> [-s] [-b] [-v] [-n] [-c] [-j]
                            [--version] [--srcipfield SRCIPFIELD]
                            [--dstipfield DSTIPFIELD]
                            [--dstportfield DSTPORTFIELD]
                            [--protofield PROTOFIELD] [--actionfield ACTIONFIELD]
                            [--sentbytesfield SENTBYTESFIELD]
                            [--rcvdbytesfield RCVDBYTESFIELD]

    Parses a Fortigate log file and presents a communication matrix.

    options:
      -h, --help            show this help message and exit
      -f, --file <logfile>  Logfile to parse
      -s, --showaction      Show action field
      -b, --countbytes      Count bytes for each communication quartet
      -v, --verbose         Activate verbose messages
      -n, --noipcheck       Do not check if src and dst ip are present
      -c, --csv             Print matrix in csv format (default is nested format)
      -j, --json            Print matrix in json format (default is nested format)
      --version             show program's version number and exit
      --srcipfield SRCIPFIELD
                            Src ip address field (default: srcip)
      --dstipfield DSTIPFIELD
                            Dst ip address field (default: dstip)
      --dstportfield DSTPORTFIELD
                            Dst port field (default: dstport)
      --protofield PROTOFIELD
                            Protocol field (default: proto)
      --actionfield ACTIONFIELD
                            Action field (default: action)
      --sentbytesfield SENTBYTESFIELD
                            Field for sent bytes (default: sentbyte)
      --rcvdbytesfield RCVDBYTESFIELD
                            Field for rcvd bytes (default: rcvdbyte)

    Examples:
      Parse Fortigate Log:
        fg_log_parser.py -f fg.log
      Parse Iptables Log:
        fg_log_parser.py -f filter --srcipfield=SRC --dstipfield=DST --dstportfield=DPT --protofield=PROTO
      Parse Fortianalyzer Log:
        fg_log_parser.py -f faz.log --srcipfield=src --dstipfield=dst

The communication
matrix has the form: 

    Source IP
        Destination IP
            Destination Port
                Protocol
                    Count
                    Rcvdbytes
                    Sentbytes

# Features
* Missing values will be substituted with 'None'
* Log format can be specified with parameters for `srcip`, `dstip`, `dport`, `protocol`, `rcvdbytes`, `sentbytes` fields.
* Default logfile format is the fortigate traffic log. The log format can be adjusted to other log formats, for example iptables logs.
* Export to CSV and JSON formats is possible

# Example Session

    $ python3 fg_log_parser.py -b -f example.log 
    192.168.1.3
	    1.2.3.4
		    443
			    TCP
				    count
					    1
				    rcvdbytes
					    11798
				    sentbytes
					    1686
	    4.4.5.5
		    443
			    TCP
				    count
					    1
				    rcvdbytes
					    7642
				    sentbytes
					    1621
	    1.1.2.2
		    443
			    TCP
				    count
					    1
				    rcvdbytes
					    29710
				    sentbytes
					    3174
	    8.8.8.8
		    53
			    UDP
				    count
					    10
				    rcvdbytes
					    2001

# Example Session with CSV output

    python3 fg_log_parser.py -c -f testlogs/fg.log
    srcip;dstip;dport;proto;count;action;sentbytes;rcvdbytes
    192.168.1.1;8.8.8.8;53;UDP;3;None
    192.168.1.1;8.8.8.8;None;None;1;None

# Example Session with JSON output

    python3 fg_log_parser.py -j -f testlogs/fg.log
    [
      {
        "srcip": "192.168.1.1",
        "dstip": "8.8.8.8",
        "dport": "53",
        "proto": "UDP",
        "count": 3
      },
      {
        "srcip": "192.168.1.1",
        "dstip": "8.8.8.8",
        "dport": null,
        "proto": null,
        "count": 1
      }
    ]

With byte counting enabled:

    python3 fg_log_parser.py -j -b -f testlogs/fg.log
    [
      {
        "srcip": "192.168.1.1",
        "dstip": "8.8.8.8",
        "dport": "53",
        "proto": "UDP",
        "count": 3,
        "sentbytes": 3,
        "rcvdbytes": 3
      },
      {
        "srcip": "192.168.1.1",
        "dstip": "8.8.8.8",
        "dport": null,
        "proto": null,
        "count": 1,
        "sentbytes": 1,
        "rcvdbytes": 1
      }
    ]

# Tests

The python `unittest` module is used for tests. The tests are located in the
`tests/test_fg_log_parser.py` file. Some common logfiles with different
logformats are in `testlogs/` and are tested each time.

To run the tests:

    python3 -m unittest discover tests

Or run the test file directly:

    python3 tests/test_fg_log_parser.py
