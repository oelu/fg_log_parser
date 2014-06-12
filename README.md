# Fortigate Log Parser
Parses a Fortigate traffic log and presents a communication matrix. 

## Requirements
* Requires python docopt module.
* Requires logging module.

## Usage

    $ python fg_log_parser.py -h
    Fortigate Log Parser
        Parses a Fortigate logfile and presents a communication matrix.
    
    Usage: 
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

## Example Session

    $ ./fg_log_parser.py -b -f example.log 
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

