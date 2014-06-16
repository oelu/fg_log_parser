# Fortigate Log Parser
Parses a Fortigate traffic log and presents a communication matrix. The communication
matrix has the form: 

    Source IP
        Destination IP
            Destination Port
                Protocol
                    Count
                    Rcvdbytes
                    Sentbytes

## Features
* Missing values will be substituted with ‘None’
* Log format can be specified with parameters for `srcip`, `dstip`, `dport`, `protocol`, `rcvdbytes`, `sentbytes` fields. 
* Default logfile format is the fortigate traffic log. The log format can be adjusted to other log formats, for example iptables logs. 

## Requirements
* Requires python docopt module.
* Requires logging module.

## Example Session

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

## Usage
The help message contains information about general options and log format options. 

### Usage: fg_log_parser.py

        fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

### Options:

        -b --countbytes         Count bytes for each communication quartet
        -h --help               Show this message
        -v --verbose            activate verbose messages
        --version               Shows version information
        -n --noipcheck          Do not check if src and dst ip are present
    
### Log Format Options (case sensitive):

        --srcipfield=<srcipfield>       Src ip address field [default: srcip]
        --dstipfield=<dstipfield>       Dst ip address field [default: dstip]
        --dstportfield=<dstportfield>   Dst port field [default: dstport]
        --protofield=<protofield>       Protocol field [default: proto]

    If countbytes options is set you may have to specify:
        --sentbytesfield=<sentbytesfield>  Field for sent bytes [default: sentbyte]
        --rcvdbytesfield=<rcvdbytesfield>  Field for rcvd bytes [default: rcvdbyte]

### Examples:

        Parse Fortigate Log:
            fg_log_parser.py -f fg.log
        Parse Iptables Log:
            fg_log_parser.py -f filter --srcipfield=SRC --dstipfield=DST --dstportfield=DPT --protofield=PROTO
        Parse Fortianalyzer Log:
            fg_log_parser.py -f faz.log --srcipfield=src --dstipfield=dst
