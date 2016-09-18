#!/bin/bash
# simple test to for fortigate log parser
/usr/bin/python -m doctest fg_log_parser.py
/usr/bin/python2.7 -m doctest -f logfiles.test
