# Fortigate Log Parser

<!-- toc -->
* [Features](#features)
* [Example Session](#example-session)
* [Usage](#usage)
  * [Usage: fg_log_parser.py](#usage-fglogparserpy)
* [Tests](#tests)

<!-- toc stop -->
Parses a Fortigate traffic log and presents a communication matrix. The communication
matrix has the form: 

    Source IP
        Destination IP
            Destination Port
                Protocol
                    Count
                    Rcvdbytes
                    Sentbytes

# Features
* Missing values will be substituted with ‘None’
* Log format can be specified with parameters for `srcip`, `dstip`, `dport`, `protocol`, `rcvdbytes`, `sentbytes` fields. 
* Default logfile format is the fortigate traffic log. The log format can be adjusted to other log formats, for example iptables logs. 
* Export to .csv format is possible

# Example Session

    $ python fg_log_parser.py -b -f example.log 
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

# Usage
The help message contains information about general options and log format options. 

## Usage: fg_log_parser.py

    $ python fg_log_parser.py --help
    Fortigate Log Parser
    Parses a Fortigate logfile and presents a communication matrix.
    
    Usage: fg_log_parser.py
        fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

    Options:
        -s --showaction         Show action field.
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

# Tests

The python `doctest` module is used for tests. The tests are located either 
in the function docstring directly or in the `logfiles.test` file. Some common
logfiles with different logformats are in `testlogs/` and are tested each time.
