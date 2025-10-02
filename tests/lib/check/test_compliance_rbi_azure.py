"""
Test RBI Azure Compliance Framework
Tests for validating the RBI Cyber Security Framework compliance mapping for Azure
"""
import json
from pathlib import Path
from unittest import TestCase


class TestRBIAzureCompliance(TestCase):
    """Test suite for RBI Azure compliance framework"""

    @classmethod
    def setUpClass(cls):
        """Load the RBI Azure compliance file"""
        # Find the compliance file
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent.parent
        compliance_file = (
            project_root
            / "prowler/compliance/azure/rbi_cyber_security_framework_azure.json"
        )

        cls.compliance_file_path = compliance_file

        # Load the JSON
        with open(compliance_file, "r") as f:
            cls.compliance_data = json.load(f)

    def test_compliance_file_exists(self):
        """Test that the RBI Azure compliance file exists"""
        self.assertTrue(
            self.compliance_file_path.exists(),
            f"Compliance file not found at {self.compliance_file_path}",
        )

    def test_framework_metadata(self):
        """Test that framework metadata is correctly set"""
        self.assertEqual(
            self.compliance_data["Framework"],
            "RBI-Cyber-Security-Framework",
            "Framework name should be 'RBI-Cyber-Security-Framework'",
        )
        self.assertEqual(
            self.compliance_data["Provider"],
            "Azure",
            "Provider should be 'Azure'",
        )
        self.assertIn(
            "Reserve Bank of India",
            self.compliance_data["Name"],
            "Name should contain 'Reserve Bank of India'",
        )
        self.assertIn(
            "cyber security framework",
            self.compliance_data["Description"].lower(),
            "Description should mention cyber security framework",
        )

    def test_all_requirements_present(self):
        """Test that all 9 RBI Annex I requirements are present"""
        requirements = self.compliance_data.get("Requirements", [])

        # Should have exactly 9 requirements
        self.assertEqual(
            len(requirements),
            9,
            "RBI framework should have exactly 9 requirements",
        )

        # Check for specific requirement IDs
        expected_ids = [
            "annex_i_1_1",
            "annex_i_1_3",
            "annex_i_5_1",
            "annex_i_6",
            "annex_i_7_1",
            "annex_i_7_2",
            "annex_i_7_3",
            "annex_i_7_4",
            "annex_i_12",
        ]

        requirement_ids = [req["Id"] for req in requirements]

        for expected_id in expected_ids:
            self.assertIn(
                expected_id,
                requirement_ids,
                f"Requirement {expected_id} should be present",
            )

    def test_all_requirements_have_checks(self):
        """Test that all requirements have at least one check"""
        requirements = self.compliance_data.get("Requirements", [])

        for requirement in requirements:
            req_id = requirement.get("Id", "Unknown")
            checks = requirement.get("Checks", [])

            self.assertGreater(
                len(checks),
                0,
                f"Requirement {req_id} should have at least one check",
            )

    def test_no_duplicate_checks_within_requirement(self):
        """Test that there are no duplicate checks within each requirement"""
        requirements = self.compliance_data.get("Requirements", [])

        for requirement in requirements:
            req_id = requirement.get("Id", "Unknown")
            checks = requirement.get("Checks", [])

            # Check for duplicates
            unique_checks = set(checks)
            self.assertEqual(
                len(checks),
                len(unique_checks),
                f"Requirement {req_id} has duplicate checks",
            )

    def test_check_names_are_valid_azure_format(self):
        """Test that all check names follow Azure provider naming convention"""
        requirements = self.compliance_data.get("Requirements", [])

        # Valid Azure service prefixes based on existing checks
        valid_prefixes = [
            "aisearch_",
            "aks_",
            "apim_",
            "app_",
            "appinsights_",
            "containerregistry_",
            "cosmosdb_",
            "databricks_",
            "defender_",
            "entra_",
            "iam_",
            "keyvault_",
            "logs_",
            "monitor_",
            "mysql_",
            "network_",
            "policy_",
            "postgresql_",
            "recovery_",
            "sqlserver_",
            "storage_",
            "vm_",
        ]

        for requirement in requirements:
            req_id = requirement.get("Id", "Unknown")
            checks = requirement.get("Checks", [])

            for check in checks:
                has_valid_prefix = any(
                    check.startswith(prefix) for prefix in valid_prefixes
                )
                self.assertTrue(
                    has_valid_prefix,
                    f"Check '{check}' in requirement {req_id} does not have "
                    f"a valid Azure service prefix",
                )

    def test_requirements_have_descriptions(self):
        """Test that all requirements have descriptions"""
        requirements = self.compliance_data.get("Requirements", [])

        for requirement in requirements:
            req_id = requirement.get("Id", "Unknown")

            self.assertIn(
                "Description",
                requirement,
                f"Requirement {req_id} should have a Description",
            )
            self.assertGreater(
                len(requirement.get("Description", "")),
                10,
                f"Requirement {req_id} description should be meaningful (>10 chars)",
            )

    def test_requirements_have_attributes(self):
        """Test that all requirements have attributes"""
        requirements = self.compliance_data.get("Requirements", [])

        for requirement in requirements:
            req_id = requirement.get("Id", "Unknown")

            self.assertIn(
                "Attributes",
                requirement,
                f"Requirement {req_id} should have Attributes",
            )

            attributes = requirement.get("Attributes", [])
            self.assertGreater(
                len(attributes),
                0,
                f"Requirement {req_id} should have at least one attribute",
            )

            # Check attribute structure
            for attr in attributes:
                self.assertIn(
                    "ItemId",
                    attr,
                    f"Attribute in {req_id} should have ItemId",
                )
                self.assertIn(
                    "Service",
                    attr,
                    f"Attribute in {req_id} should have Service",
                )

    def test_json_structure_is_valid(self):
        """Test that the JSON structure is valid and can be loaded"""
        # If we got here, the JSON loaded successfully in setUpClass
        self.assertIsNotNone(self.compliance_data)
        self.assertIsInstance(self.compliance_data, dict)

    def test_alignment_with_aws_rbi(self):
        """Test that Azure RBI has same requirement IDs as AWS RBI for consistency"""
        # Check if AWS RBI file exists for comparison
        test_dir = Path(__file__).parent
        project_root = test_dir.parent.parent.parent
        aws_rbi_file = (
            project_root
            / "prowler/compliance/aws/rbi_cyber_security_framework_aws.json"
        )

        if not aws_rbi_file.exists():
            self.skipTest("AWS RBI file not found for comparison")

        with open(aws_rbi_file, "r") as f:
            aws_rbi_data = json.load(f)

        aws_requirements = aws_rbi_data.get("Requirements", [])
        azure_requirements = self.compliance_data.get("Requirements", [])

        aws_req_ids = {req["Id"] for req in aws_requirements}
        azure_req_ids = {req["Id"] for req in azure_requirements}

        # Azure should have the same requirement IDs as AWS
        self.assertEqual(
            aws_req_ids,
            azure_req_ids,
            "Azure and AWS RBI should have the same requirement IDs",
        )

    def test_data_protection_requirement_has_comprehensive_checks(self):
        """Test that Annex I (1.3) - Data Protection has comprehensive coverage"""
        requirements = self.compliance_data.get("Requirements", [])

        # Find the data protection requirement
        data_protection_req = None
        for req in requirements:
            if req["Id"] == "annex_i_1_3":
                data_protection_req = req
                break

        self.assertIsNotNone(
            data_protection_req,
            "Data protection requirement (annex_i_1_3) should exist",
        )

        checks = data_protection_req.get("Checks", [])

        # Should have comprehensive checks covering:
        # - Storage encryption
        # - SQL encryption
        # - Key Vault
        # - Network security
        # - VM encryption

        # Check for key security areas
        check_str = " ".join(checks)

        self.assertIn(
            "storage_",
            check_str,
            "Data protection should include storage checks",
        )
        self.assertIn(
            "sqlserver_",
            check_str,
            "Data protection should include SQL server checks",
        )
        self.assertIn(
            "keyvault_",
            check_str,
            "Data protection should include Key Vault checks",
        )

        # Should have a reasonable number of checks for comprehensive coverage
        self.assertGreater(
            len(checks),
            15,
            "Data protection requirement should have comprehensive check "
            "coverage (>15 checks)",
        )

    def test_patch_management_requirement_has_defender_checks(self):
        """Test that Annex I (6) - Patch Management has defender checks"""
        requirements = self.compliance_data.get("Requirements", [])

        # Find the patch management requirement
        patch_mgmt_req = None
        for req in requirements:
            if req["Id"] == "annex_i_6":
                patch_mgmt_req = req
                break

        self.assertIsNotNone(
            patch_mgmt_req,
            "Patch management requirement (annex_i_6) should exist",
        )

        checks = patch_mgmt_req.get("Checks", [])

        # Should have defender checks for vulnerability management
        defender_checks = [c for c in checks if c.startswith("defender_")]

        self.assertGreater(
            len(defender_checks),
            5,
            "Patch management should have multiple defender checks",
        )

    def test_backup_requirement_has_appropriate_checks(self):
        """Test that Annex I (12) - Backup has appropriate checks"""
        requirements = self.compliance_data.get("Requirements", [])

        # Find the backup requirement
        backup_req = None
        for req in requirements:
            if req["Id"] == "annex_i_12":
                backup_req = req
                break

        self.assertIsNotNone(
            backup_req,
            "Backup requirement (annex_i_12) should exist",
        )

        checks = backup_req.get("Checks", [])

        # Should include VM backup and storage redundancy
        check_str = " ".join(checks)

        self.assertIn(
            "vm_backup",
            check_str,
            "Backup requirement should include VM backup checks",
        )
        self.assertIn(
            "storage_",
            check_str,
            "Backup requirement should include storage checks",
        )
