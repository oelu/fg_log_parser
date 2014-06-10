# Fortigate Log Parser
Parses a Fortigate traffic log and presents a communication matrix. 

## Usage
    Fortigate Log Parser

    Usage: fg_log_parser.py
        fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

    Options:
        -b --countbytes  count bytes for each communication
        -h --help   Show this message.
        --verbose  activate verbose messages
        --version  shows version information
    
    Default Logfile Format:
        The following log fields need to be available in the logfile:
            srcip   source ip address
            dstip   destination ip address
            proto   protocol
            dstport destination port
            
        If the countbytes option is set, the following
        two fields need to be present:
            sendbytes   number of sent bytes
            rcvdbytes   number of received bytes

## Requirements
* Requires python docopt module.
* Requires logging module.

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
