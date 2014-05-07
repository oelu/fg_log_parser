# Fortigate Log Parser
Parsers a Fortigate log and presents a communication matrix. 

## Usage
    Fortigate Log Parser
    
    Usage:
        get_requests.py (-f <logfile> | --file <logfile>)
        get_requests.py (-h | --help)
        get_requests.py --version
   Options:
      -h --help   Show this message.

## Requirements
* Requires python docopt module.

## Example Session
    $ ./fg_log_parser.py -f example.log
     192.168.1.1
        1.2.3.4
                80
                        UDP
                                2
        8.8.8.8
                53
                        UDP
                                5
        8.8.4.4
                53
                        UDP
                                2
