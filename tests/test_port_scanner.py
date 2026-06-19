import unittest
from scannet.core.port_scanner import PortScanner

class TestPortScanner(unittest.TestCase):
    def test_port_scanner_init(self):
        scanner = PortScanner("127.0.0.1", timeout=1.0, threads=10)
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.timeout, 1.0)
        self.assertEqual(scanner.threads, 10)

    def test_scan_ports_invalid_host(self):
        # We can scan port lists and expect them to be closed for non-existent target or local empty port
        scanner = PortScanner("192.0.2.1", timeout=0.1, threads=2) # 192.0.2.1 is reserved TEST-NET-1
        res = scanner.scan_ports([80, 443])
        # Port should be marked closed or open|filtered.
        # Since it is a reserved, non-responding target, it should time out (closed for TCP connect)
        self.assertEqual(res, {})
        
if __name__ == "__main__":
    unittest.main()
