#!/usr/bin/python3
"""Unit tests for fg_log_parser module."""

import unittest
import sys
import os
import json
from io import StringIO

# Add parent directory to path to import fg_log_parser
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fg_log_parser import (
    split_kv,
    check_log_format,
    translate_protonr,
    get_communication_matrix,
    print_communication_matrix,
    print_communication_matrix_as_csv,
    print_communication_matrix_as_json,
    load_hosts_csv
)


class TestSplitKV(unittest.TestCase):
    """Test cases for split_kv function."""

    def test_split_kv_basic(self):
        """Test basic key-value splitting."""
        line = 'srcip=192.168.1.1 dstip=8.8.8.8 dport=53 proto=53 dstcountry="United States"'
        result = split_kv(line)
        expected = {
            'srcip': '192.168.1.1',
            'dport': '53',
            'dstip': '8.8.8.8',
            'dstcountry': '"United States"',
            'proto': '53'
        }
        self.assertEqual(result, expected)


class TestCheckLogFormat(unittest.TestCase):
    """Test cases for check_log_format function."""

    def test_check_log_format_valid(self):
        """Test with valid log format containing both fields."""
        line = 'srcip=192.168.1.1 dstip=8.8.8.8 dstport=53 proto=53'
        result = check_log_format(line, "srcip", "dstip")
        self.assertTrue(result)

    def test_check_log_format_missing_field(self):
        """Test with missing dstip field."""
        line = 'srcip=192.168.1.1 dstport=53 proto=53'
        result = check_log_format(line, "srcip", "dstip")
        self.assertFalse(result)

    def test_check_log_format_empty_line(self):
        """Test with empty line."""
        line = ''
        result = check_log_format(line, "srcip", "dstip")
        self.assertFalse(result)


class TestTranslateProtonr(unittest.TestCase):
    """Test cases for translate_protonr function."""

    def test_translate_protonr_unknown(self):
        """Test protocol number that has no translation."""
        result = translate_protonr(53)
        self.assertEqual(result, 53)

    def test_translate_protonr_icmp(self):
        """Test ICMP protocol (1)."""
        result = translate_protonr(1)
        self.assertEqual(result, 'ICMP')

    def test_translate_protonr_tcp(self):
        """Test TCP protocol (6)."""
        result = translate_protonr(6)
        self.assertEqual(result, 'TCP')

    def test_translate_protonr_udp(self):
        """Test UDP protocol (17)."""
        result = translate_protonr(17)
        self.assertEqual(result, 'UDP')


class TestGetCommunicationMatrix(unittest.TestCase):
    """Test cases for get_communication_matrix function."""

    def setUp(self):
        """Set up common test fixtures."""
        self.logformat = {
            'srcipfield': 'srcip',
            'dstipfield': 'dstip',
            'dstportfield': 'dstport',
            'protofield': 'proto',
            'sentbytesfield': 'sentbyte',
            'rcvdbytesfield': 'rcvdbyte',
            'actionfield': 'action'
        }

    def test_get_communication_matrix_fortigate(self):
        """Test parsing Fortigate log file."""
        result = get_communication_matrix('testlogs/fg.log', self.logformat)
        expected = {
            '192.168.1.1': {
                '8.8.8.8': {
                    None: {None: {'count': 1}},
                    '53': {'UDP': {'count': 3}}
                }
            }
        }
        self.assertEqual(result, expected)

    def test_get_communication_matrix_with_none_values(self):
        """Test parsing log file with None values (noipcheck)."""
        result = get_communication_matrix('testlogs/fgnone.log', self.logformat, noipcheck=True)
        expected = {
            '192.168.1.1': {
                None: {
                    '53': {'UDP': {'count': 1}}
                }
            }
        }
        self.assertEqual(result, expected)

    def test_get_communication_matrix_iptables(self):
        """Test parsing iptables log file."""
        logformat_iptables = {
            'srcipfield': 'SRC',
            'dstipfield': 'DST',
            'protofield': 'PROTO',
            'dstportfield': 'DPT',
            'sentbytesfield': 'None',
            'rcvdbytesfield': 'None',
            'actionfield': 'action'
        }
        result = get_communication_matrix('testlogs/iptables', logformat_iptables)
        expected = {
            '192.168.1.1': {
                '8.8.8.8': {
                    None: {'ICMP': {'count': 1}},
                    '22': {'TCP': {'count': 3}}
                },
                '8.8.4.4': {
                    '22': {'UDP': {'count': 1}}
                }
            }
        }
        self.assertEqual(result, expected)


class TestPrintCommunicationMatrix(unittest.TestCase):
    """Test cases for print_communication_matrix function."""

    def test_print_communication_matrix_simple(self):
        """Test printing simple communication matrix."""
        matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        expected_lines = [
            '192.168.1.1',
            '    8.8.8.8',
            '        53',
            '            UDP',
            '                count',
            '                    1'
        ]

        for line in expected_lines:
            self.assertIn(line, output)

    def test_print_communication_matrix_with_none(self):
        """Test printing communication matrix with None values."""
        matrix = {'192.168.1.1': {'8.8.8.8': {None: {None: {'count': 1}}, '53': {'UDP': {'count': 3}}}}}

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        expected_lines = [
            '192.168.1.1',
            '    8.8.8.8',
            '        None',
            '            None',
            '                count',
            '                    1',
            '        53',
            '            UDP',
            '                count',
            '                    3'
        ]

        for line in expected_lines:
            self.assertIn(line, output)

    def test_print_communication_matrix_missing_dstip(self):
        """Test printing communication matrix with missing destination IP."""
        matrix = {'192.168.1.1': {None: {'53': {'UDP': {'count': 1}}}}}

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        expected_lines = [
            '192.168.1.1',
            '    None',
            '        53',
            '            UDP',
            '                count',
            '                    1'
        ]

        for line in expected_lines:
            self.assertIn(line, output)


class TestPrintCommunicationMatrixAsCSV(unittest.TestCase):
    """Test cases for print_communication_matrix_as_csv function."""

    def test_print_csv_simple(self):
        """Test CSV output for simple matrix."""
        matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_csv(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        lines = output.strip().split('\n')

        self.assertEqual(lines[0], 'srcip;src.name;dstip;dst.name;dport;proto;count')
        self.assertEqual(lines[1], '192.168.1.1;;8.8.8.8;;53;UDP;1')

    def test_print_csv_with_bytes(self):
        """Test CSV output with byte counts."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {
                        'UDP': {
                            'count': 1,
                            'sentbytes': 10,
                            'rcvdbytes': 10
                        }
                    }
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_csv(matrix, countbytes=True)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        lines = output.strip().split('\n')

        self.assertEqual(lines[0], 'srcip;src.name;dstip;dst.name;dport;proto;count;sentbytes;rcvdbytes')
        self.assertEqual(lines[1], '192.168.1.1;;8.8.8.8;;53;UDP;1;10;10')


class TestPrintCommunicationMatrixAsJSON(unittest.TestCase):
    """Test cases for print_communication_matrix_as_json function."""

    def test_print_json_simple(self):
        """Test JSON output for simple matrix."""
        matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertEqual(data[0]['dport'], '53')
        self.assertEqual(data[0]['proto'], 'UDP')
        self.assertEqual(data[0]['count'], 1)
        self.assertNotIn('sentbytes', data[0])
        self.assertNotIn('rcvdbytes', data[0])
        self.assertNotIn('action', data[0])

    def test_print_json_with_bytes(self):
        """Test JSON output with byte counts."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {
                        'UDP': {
                            'count': 1,
                            'sentbytes': 10,
                            'rcvdbytes': 20
                        }
                    }
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix, countbytes=True)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertEqual(data[0]['dport'], '53')
        self.assertEqual(data[0]['proto'], 'UDP')
        self.assertEqual(data[0]['count'], 1)
        self.assertEqual(data[0]['sentbytes'], 10)
        self.assertEqual(data[0]['rcvdbytes'], 20)
        self.assertNotIn('action', data[0])

    def test_print_json_with_action(self):
        """Test JSON output with action field."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {
                        'UDP': {
                            'count': 1,
                            'action': 'accept'
                        }
                    }
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix, showaction=True)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertEqual(data[0]['dport'], '53')
        self.assertEqual(data[0]['proto'], 'UDP')
        self.assertEqual(data[0]['count'], 1)
        self.assertEqual(data[0]['action'], 'accept')
        self.assertNotIn('sentbytes', data[0])
        self.assertNotIn('rcvdbytes', data[0])

    def test_print_json_with_none_values(self):
        """Test JSON output with None values."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    None: {
                        None: {'count': 1}
                    }
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertIsNone(data[0]['dport'])
        self.assertIsNone(data[0]['proto'])
        self.assertEqual(data[0]['count'], 1)

    def test_print_json_multiple_records(self):
        """Test JSON output with multiple records."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {'UDP': {'count': 3}},
                    None: {None: {'count': 1}}
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 2)

        # First record
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertEqual(data[0]['dport'], '53')
        self.assertEqual(data[0]['proto'], 'UDP')
        self.assertEqual(data[0]['count'], 3)

        # Second record
        self.assertEqual(data[1]['srcip'], '192.168.1.1')
        self.assertEqual(data[1]['dstip'], '8.8.8.8')
        self.assertIsNone(data[1]['dport'])
        self.assertIsNone(data[1]['proto'])
        self.assertEqual(data[1]['count'], 1)

    def test_print_json_valid_format(self):
        """Test that output is valid JSON."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {'UDP': {'count': 1}}
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()

        # Should not raise an exception if valid JSON
        try:
            data = json.loads(output)
            self.assertIsInstance(data, list)
        except json.JSONDecodeError:
            self.fail("Output is not valid JSON")

    def test_print_json_all_options(self):
        """Test JSON output with all options enabled."""
        matrix = {
            '192.168.1.1': {
                '8.8.8.8': {
                    '53': {
                        'UDP': {
                            'count': 5,
                            'action': 'accept',
                            'sentbytes': 100,
                            'rcvdbytes': 200
                        }
                    }
                }
            }
        }

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(matrix, countbytes=True, showaction=True)

        # Restore stdout
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['srcip'], '192.168.1.1')
        self.assertEqual(data[0]['dstip'], '8.8.8.8')
        self.assertEqual(data[0]['dport'], '53')
        self.assertEqual(data[0]['proto'], 'UDP')
        self.assertEqual(data[0]['count'], 5)
        self.assertEqual(data[0]['action'], 'accept')
        self.assertEqual(data[0]['sentbytes'], 100)
        self.assertEqual(data[0]['rcvdbytes'], 200)


class TestLoadHostsCSV(unittest.TestCase):
    """Test cases for load_hosts_csv function."""

    def setUp(self):
        """Create temporary CSV hosts file."""
        self.test_csv = '/tmp/test_hosts.csv'
        with open(self.test_csv, 'w') as f:
            f.write('name;addr;addr6\n')
            f.write('dns.server;8.8.8.8;2001:4860:4860::8888\n')
            f.write('client.host;192.168.1.1;fd00::1\n')

    def tearDown(self):
        """Remove temporary file."""
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    def test_load_hosts_csv_ipv4(self):
        """Test loading IPv4 addresses from CSV."""
        hosts = load_hosts_csv(self.test_csv)
        self.assertEqual(hosts.get('8.8.8.8'), 'dns.server')
        self.assertEqual(hosts.get('192.168.1.1'), 'client.host')

    def test_load_hosts_csv_ipv6(self):
        """Test loading IPv6 addresses from CSV."""
        hosts = load_hosts_csv(self.test_csv)
        self.assertEqual(hosts.get('2001:4860:4860::8888'), 'dns.server')
        self.assertEqual(hosts.get('fd00::1'), 'client.host')

    def test_load_hosts_csv_unknown_ip(self):
        """Test that unknown IPs return None."""
        hosts = load_hosts_csv(self.test_csv)
        self.assertIsNone(hosts.get('10.0.0.1'))

    def test_load_hosts_csv_empty_file(self):
        """Test loading empty CSV file."""
        empty_csv = '/tmp/empty_hosts.csv'
        with open(empty_csv, 'w') as f:
            f.write('name;addr;addr6\n')
        hosts = load_hosts_csv(empty_csv)
        self.assertEqual(hosts, {})
        os.remove(empty_csv)


class TestPrintWithHosts(unittest.TestCase):
    """Test cases for print functions with hosts parameter."""

    def setUp(self):
        """Set up test fixtures."""
        self.hosts = {
            '192.168.1.1': 'client.host',
            '8.8.8.8': 'dns.server'
        }
        self.matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

    def test_csv_with_hosts(self):
        """Test CSV output with host name resolution."""
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_csv(self.matrix, hosts=self.hosts)

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        lines = output.strip().split('\n')

        self.assertEqual(lines[0], 'srcip;src.name;dstip;dst.name;dport;proto;count')
        self.assertEqual(lines[1], '192.168.1.1;client.host;8.8.8.8;dns.server;53;UDP;1')

    def test_csv_with_partial_hosts(self):
        """Test CSV output when only some IPs have names."""
        partial_hosts = {'192.168.1.1': 'client.host'}

        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_csv(self.matrix, hosts=partial_hosts)

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        lines = output.strip().split('\n')

        self.assertEqual(lines[1], '192.168.1.1;client.host;8.8.8.8;;53;UDP;1')

    def test_json_with_hosts(self):
        """Test JSON output with host name resolution."""
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(self.matrix, hosts=self.hosts)

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(data[0]['src.name'], 'client.host')
        self.assertEqual(data[0]['dst.name'], 'dns.server')

    def test_json_with_empty_hosts(self):
        """Test JSON output with empty hosts dict."""
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix_as_json(self.matrix, hosts={})

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        data = json.loads(output)

        self.assertEqual(data[0]['src.name'], '')
        self.assertEqual(data[0]['dst.name'], '')

    def test_nested_with_hosts(self):
        """Test nested output with host name resolution."""
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix(self.matrix, hosts=self.hosts)

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        self.assertIn('192.168.1.1 (client.host)', output)
        self.assertIn('8.8.8.8 (dns.server)', output)

    def test_nested_without_hosts(self):
        """Test nested output without host names (no parentheses)."""
        captured_output = StringIO()
        sys.stdout = captured_output

        print_communication_matrix(self.matrix, hosts={})

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        self.assertIn('192.168.1.1', output)
        self.assertNotIn('(', output)


if __name__ == '__main__':
    unittest.main()
