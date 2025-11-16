#!/bin/bash
# simple test to for fortigate log parser
/usr/bin/python3 -m doctest fg_log_parser.py
/usr/bin/python3 -m doctest -f logfiles.test
