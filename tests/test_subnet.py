import unittest
from scannet.core.subnet import SubnetTools

class TestSubnetTools(unittest.TestCase):
    def test_subnet_info_valid(self):
        info = SubnetTools.get_subnet_info("192.168.1.0/24")
        self.assertEqual(info["network_address"], "192.168.1.0")
        self.assertEqual(info["broadcast_address"], "192.168.1.255")
        self.assertTrue(info["is_private"])
        
    def test_subnet_hosts(self):
        hosts = SubnetTools.get_hosts("192.168.1.0/30")
        # For a /30 subnet, hosts are 192.168.1.1 and 192.168.1.2
        self.assertEqual(len(hosts), 2)
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.2", hosts)

    def test_invalid_subnet(self):
        with self.assertRaises(ValueError):
            SubnetTools.get_subnet_info("invalid_subnet_representation")

if __name__ == "__main__":
    unittest.main()
