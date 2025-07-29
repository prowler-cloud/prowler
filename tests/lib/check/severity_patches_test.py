import unittest
from unittest.mock import patch

from prowler.config.config import validate_severity_patches
from prowler.lib.check.models import Severity


class TestSeverityPatches(unittest.TestCase):
    def test_validate_severity_patches_valid(self):
        """Test validate_severity_patches with valid input"""
        severity_patches = {
            "ec2_ami_public": "high",
            "cloudtrail_logs_s3_validation": "critical",
        }
        
        result = validate_severity_patches(severity_patches)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result["ec2_ami_public"], "high")
        self.assertEqual(result["cloudtrail_logs_s3_validation"], "critical")
    
    def test_validate_severity_patches_empty_dict(self):
        """Test validate_severity_patches with empty dict"""
        severity_patches = {}
        
        result = validate_severity_patches(severity_patches)
        
        self.assertEqual(result, {})
    
    def test_validate_severity_patches_none(self):
        """Test validate_severity_patches with None"""
        severity_patches = None
        
        result = validate_severity_patches(severity_patches)
        
        self.assertEqual(result, {})
    
    def test_validate_severity_patches_case_insensitive(self):
        """Test validate_severity_patches handles case insensitively"""
        severity_patches = {
            "ec2_ami_public": "HIGH",  # Uppercase
            "cloudtrail_logs_s3_validation": "CriTiCal",  # Mixed case
        }
        
        result = validate_severity_patches(severity_patches)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result["ec2_ami_public"], "high")
        self.assertEqual(result["cloudtrail_logs_s3_validation"], "critical")


if __name__ == "__main__":
    unittest.main()