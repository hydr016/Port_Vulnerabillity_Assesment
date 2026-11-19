"""Automated tests. Run from the project folder:  python -m unittest discover -s tests -v"""
import os
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.nmap_scanner import NmapError, run_scan                     # noqa: E402
from scanner.parser import ParseError, parse_nmap_xml                    # noqa: E402
from scanner.validator import TargetError, validate_target               # noqa: E402
from scanner.vulnerability_engine import analyse_ports                   # noqa: E402

ALLOWED = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# A small Nmap XML sample used ONLY as a unit-test input (the real app never uses it).
SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
 <host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>
  <hostnames><hostname name="lab-vm"/></hostnames>
  <ports>
   <port protocol="tcp" portid="21"><state state="open"/>
     <service name="ftp" product="vsftpd" version="2.3.4"/>
     <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>
   <port protocol="tcp" portid="22"><state state="open"/>
     <service name="ssh" product="OpenSSH" version="7.2p2"/></port>
   <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
   <port protocol="tcp" portid="80"><state state="open"/>
     <service name="http" product="Apache httpd" version="2.4.57"/></port>
   <port protocol="tcp" portid="81"><state state="closed"/></port>
  </ports></host></nmaprun>"""


class ValidationTests(unittest.TestCase):          # Test 3: invalid target input
    def test_accepts_localhost_ip(self):
        self.assertEqual(validate_target("127.0.0.1", ALLOWED)["address"], "127.0.0.1")

    def test_accepts_localhost_name(self):
        self.assertEqual(validate_target("localhost", ALLOWED)["address"], "127.0.0.1")

    def test_rejects_empty(self):
        with self.assertRaises(TargetError):
            validate_target("   ", ALLOWED)

    def test_rejects_malformed(self):
        for bad in ["999.1.1.1/", "bad host!", "192.168.1.0/24", "a;b", "-oX", "1.1.1.1,2.2.2.2"]:
            with self.assertRaises(TargetError, msg=bad):
                validate_target(bad, ALLOWED)

    def test_rejects_public_ip(self):
        with self.assertRaises(TargetError):
            validate_target("8.8.8.8", ALLOWED)

    def test_rejects_unresolvable_hostname(self):
        with self.assertRaises(TargetError):
            validate_target("no-such-host.invalid", ALLOWED)


class ParserTests(unittest.TestCase):
    def test_parses_open_ports_only(self):
        host = parse_nmap_xml(SAMPLE_XML)
        self.assertTrue(host["host_up"])
        self.assertEqual([p.port for p in host["ports"]], [21, 22, 23, 80])
        self.assertEqual(host["hostname"], "lab-vm")

    def test_malformed_xml(self):
        with self.assertRaises(ParseError):
            parse_nmap_xml("<nmaprun><broken")

    def test_host_down(self):
        xml = '<nmaprun version="7"><host><status state="down"/></host></nmaprun>'
        self.assertFalse(parse_nmap_xml(xml)["host_up"])

    def test_no_open_ports(self):
        xml = '<nmaprun version="7"><host><status state="up"/><address addr="127.0.0.1"/><ports/></host></nmaprun>'
        host = parse_nmap_xml(xml)
        self.assertEqual(host["ports"], [])
        self.assertEqual(analyse_ports(host["ports"]), [])


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.findings = analyse_ports(parse_nmap_xml(SAMPLE_XML)["ports"])

    def titles(self):
        return [f.title for f in self.findings]

    def test_findings_have_evidence_and_recommendation(self):
        self.assertTrue(self.findings)
        for f in self.findings:
            self.assertTrue(f.evidence and f.recommendation and f.description)

    def test_expected_findings(self):
        self.assertIn("Unencrypted remote login service (Telnet)", self.titles())
        self.assertIn("Anonymous FTP login allowed", self.titles())
        self.assertIn("Potential outdated service", self.titles())       # OpenSSH 7.2

    def test_modern_apache_not_flagged_as_outdated(self):
        for f in self.findings:
            if f.affected_port == 80:
                self.assertNotEqual(f.title, "Potential outdated service")

    def test_ids_and_order(self):
        self.assertEqual(self.findings[0].id, "FINDING-001")
        self.assertIn(self.findings[0].severity, ("High", "Critical"))

    def test_nothing_critical_without_confirmation(self):
        self.assertFalse([f for f in self.findings if f.severity == "Critical"])

    def test_open_ssh_alone_is_not_a_finding(self):
        xml = SAMPLE_XML.replace('version="7.2p2"', 'version="9.2p1"')
        found = analyse_ports(parse_nmap_xml(xml)["ports"])
        self.assertFalse([f for f in found if f.affected_port == 22])


class NmapMissingTest(unittest.TestCase):          # Test 4: Nmap unavailable
    def test_friendly_error_when_nmap_missing(self):
        with mock.patch("scanner.nmap_scanner.shutil.which", return_value=None):
            with self.assertRaises(NmapError) as ctx:
                run_scan("127.0.0.1", 4, {})
        self.assertIn("not installed", str(ctx.exception))


@unittest.skipUnless(shutil.which("nmap"), "Nmap not installed")
class LiveLocalhostTest(unittest.TestCase):        # Test 1: scan your own machine
    def test_scan_localhost(self):
        import socket
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        config = {"scan": {"port_spec": str(port), "timeout_seconds": 120, "use_nse": False}}
        try:
            result = run_scan("127.0.0.1", 4, config)
        finally:
            server.close()
        host = parse_nmap_xml(result["xml"])
        self.assertTrue(host["host_up"])
        self.assertIn(port, [p.port for p in host["ports"]])


if __name__ == "__main__":
    unittest.main()
