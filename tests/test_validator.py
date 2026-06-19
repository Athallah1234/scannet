import unittest
from scannet.core.validator import TargetValidator
from scannet.utils.exceptions import TargetValidationError, UnauthorizedScanError

class TestTargetValidator(unittest.TestCase):
    def test_unauthorized_scan(self):
        # Scan without authorized confirmation raises exception
        with self.assertRaises(UnauthorizedScanError):
            TargetValidator.validate_target("127.0.0.1", authorized=False)
            
    def test_private_target_validation(self):
        # Private IPs validate correctly
        res = TargetValidator.validate_target("127.0.0.1", authorized=True)
        self.assertEqual(res, "127.0.0.1")

    def test_public_target_denied_by_default(self):
        # Public IP scanning blocked by default
        with self.assertRaises(TargetValidationError):
            TargetValidator.validate_target("8.8.8.8", authorized=True, allow_public=False)

    def test_public_target_allowed_explicitly(self):
        res = TargetValidator.validate_target("8.8.8.8", authorized=True, allow_public=True)
        self.assertEqual(res, "8.8.8.8")
        
    def test_invalid_target(self):
        with self.assertRaises(TargetValidationError):
            TargetValidator.validate_target("invalid_ip_or_domain_pattern###", authorized=True)

if __name__ == "__main__":
    unittest.main()
