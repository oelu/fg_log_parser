#!/bin/bash
# Unit tests for fortigate log parser
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py' -v
