#!/bin/bash
# simple test to for fortigate log parser
/usr/local/bin/python2.7 -m doctest fg_log_parser.py
/usr/local/bin/python2.7 -m doctest -f logfiles.test
