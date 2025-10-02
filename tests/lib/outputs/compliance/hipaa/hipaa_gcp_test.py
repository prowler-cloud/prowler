"""Test HIPAA GCP compliance framework."""


class TestHIPAAGCPCompliance:
    """Test HIPAA GCP compliance framework validation."""

    def test_hipaa_gcp_json_loads_successfully(self):
        """Test that HIPAA GCP JSON file loads without errors."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        assert hipaa_path.exists(), "HIPAA GCP JSON file does not exist"

        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        assert hipaa_data["Framework"] == "HIPAA"
        assert hipaa_data["Provider"] == "GCP"
        assert hipaa_data["Name"] == "HIPAA compliance framework"
        assert len(hipaa_data["Requirements"]) > 0

    def test_hipaa_gcp_has_all_requirements(self):
        """Test that HIPAA GCP has all expected requirement IDs."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Key HIPAA requirements that must exist
        expected_requirements = [
            "164_308_a_1_ii_a",  # Risk analysis
            "164_308_a_1_ii_b",  # Risk Management
            "164_308_a_1_ii_d",  # Information system activity review
            "164_312_a_1",  # Access control
            "164_312_b",  # Audit controls
            "164_312_e_2_i",  # Encryption
        ]

        requirement_ids = [req["Id"] for req in hipaa_data["Requirements"]]

        for expected_id in expected_requirements:
            assert (
                expected_id in requirement_ids
            ), f"Missing required HIPAA requirement: {expected_id}"

    def test_hipaa_gcp_checks_reference_valid_gcp_checks(self):
        """Test that all checks referenced in HIPAA GCP exist in GCP provider."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks from HIPAA
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Get available GCP checks
        gcp_services_path = Path("prowler/providers/gcp/services")
        available_checks = set()

        for service_dir in gcp_services_path.iterdir():
            if service_dir.is_dir() and not service_dir.name.startswith("_"):
                for check_dir in service_dir.iterdir():
                    if check_dir.is_dir() and not check_dir.name.startswith("_"):
                        available_checks.add(check_dir.name)

        # Verify all HIPAA checks exist
        missing_checks = all_checks - available_checks
        assert (
            len(missing_checks) == 0
        ), f"HIPAA references non-existent checks: {missing_checks}"

    def test_hipaa_gcp_requirements_have_attributes(self):
        """Test that all requirements have proper attributes structure."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        for req in hipaa_data["Requirements"]:
            assert "Id" in req, "Requirement missing Id"
            assert "Name" in req, "Requirement missing Name"
            assert "Description" in req, "Requirement missing Description"
            assert "Attributes" in req, "Requirement missing Attributes"
            assert "Checks" in req, "Requirement missing Checks"

            # Validate attributes
            assert len(req["Attributes"]) > 0, f"Requirement {req['Id']} has no attributes"
            for attr in req["Attributes"]:
                assert "ItemId" in attr, "Attribute missing ItemId"
                assert "Section" in attr, "Attribute missing Section"
                assert "Service" in attr, "Attribute missing Service"
                assert (
                    attr["Service"] == "gcp"
                ), f"Attribute Service should be 'gcp', got {attr['Service']}"

    def test_hipaa_gcp_has_encryption_requirements(self):
        """Test that HIPAA GCP includes encryption-related requirements."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Find encryption requirement
        encryption_req = None
        for req in hipaa_data["Requirements"]:
            if req["Id"] == "164_312_e_2_i":  # Encryption requirement
                encryption_req = req
                break

        assert encryption_req is not None, "Missing encryption requirement 164_312_e_2_i"

        # Should include KMS and encryption-related checks
        encryption_checks = set(encryption_req["Checks"])
        assert "kms_key_not_publicly_accessible" in encryption_checks
        assert "kms_key_rotation_enabled" in encryption_checks

    def test_hipaa_gcp_has_logging_requirements(self):
        """Test that HIPAA GCP includes logging/audit requirements."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Find audit controls requirement
        audit_req = None
        for req in hipaa_data["Requirements"]:
            if req["Id"] == "164_312_b":  # Audit controls
                audit_req = req
                break

        assert audit_req is not None, "Missing audit controls requirement 164_312_b"

        # Should include logging checks
        audit_checks = set(audit_req["Checks"])
        assert "iam_audit_logs_enabled" in audit_checks
        assert "logging_sink_created" in audit_checks

    def test_hipaa_gcp_has_access_control_requirements(self):
        """Test that HIPAA GCP includes access control requirements."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Find access control requirement
        access_req = None
        for req in hipaa_data["Requirements"]:
            if req["Id"] == "164_312_a_1":  # Access control
                access_req = req
                break

        assert access_req is not None, "Missing access control requirement 164_312_a_1"

        # Should include IAM and access-related checks
        access_checks = set(access_req["Checks"])
        assert "iam_sa_no_administrative_privileges" in access_checks
        assert "iam_no_service_roles_at_project_level" in access_checks

    def test_hipaa_gcp_public_access_restrictions(self):
        """Test that HIPAA GCP includes public access restriction checks."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Verify key public access checks are included
        public_access_checks = {
            "cloudstorage_bucket_public_access",
            "cloudsql_instance_public_access",
            "compute_instance_public_ip",
            "bigquery_dataset_public_access",
        }

        for check in public_access_checks:
            assert (
                check in all_checks
            ), f"Missing important public access check: {check}"

    def test_hipaa_gcp_backup_and_recovery(self):
        """Test that HIPAA GCP includes backup and recovery requirements."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Find backup requirement
        backup_req = None
        for req in hipaa_data["Requirements"]:
            if req["Id"] == "164_308_a_7_ii_a":  # Data backup plan
                backup_req = req
                break

        assert backup_req is not None, "Missing data backup requirement 164_308_a_7_ii_a"

        # Should include backup checks
        backup_checks = set(backup_req["Checks"])
        assert "cloudsql_instance_automated_backups" in backup_checks

    def test_hipaa_gcp_unique_checks_count(self):
        """Test that HIPAA GCP has a reasonable number of unique checks."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect unique checks
        unique_checks = set()
        for req in hipaa_data["Requirements"]:
            unique_checks.update(req["Checks"])

        # HIPAA should have a substantial number of checks (at least 40)
        assert (
            len(unique_checks) >= 40
        ), f"HIPAA GCP should have at least 40 unique checks, found {len(unique_checks)}"

    def test_hipaa_gcp_no_duplicate_requirement_ids(self):
        """Test that there are no duplicate requirement IDs."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        requirement_ids = [req["Id"] for req in hipaa_data["Requirements"]]
        unique_ids = set(requirement_ids)

        assert len(requirement_ids) == len(
            unique_ids
        ), f"Duplicate requirement IDs found: {len(requirement_ids)} total vs {len(unique_ids)} unique"

    def test_hipaa_gcp_requirement_names_match_ids(self):
        """Test that requirement Names contain the requirement IDs."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        for req in hipaa_data["Requirements"]:
            # Extract numeric ID portion (e.g., "164.308" from "164_308_a_1_ii_a")
            id_parts = req["Id"].split("_")
            numeric_id = ".".join(id_parts[:2])  # Get "164.308"
            req_name = req["Name"]
            # The name should contain the numeric portion of the requirement ID
            assert numeric_id in req_name, f"Requirement name '{req_name}' does not contain ID portion '{numeric_id}' from '{req['Id']}'"

    def test_hipaa_gcp_json_structure_validity(self):
        """Test that HIPAA GCP JSON has valid structure for compliance framework."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Top-level structure
        required_keys = ["Framework", "Name", "Version", "Provider", "Description", "Requirements"]
        for key in required_keys:
            assert key in hipaa_data, f"Missing required top-level key: {key}"

        # Each requirement structure
        for req in hipaa_data["Requirements"]:
            required_req_keys = ["Id", "Name", "Description", "Attributes", "Checks"]
            for key in required_req_keys:
                assert key in req, f"Requirement {req.get('Id', 'UNKNOWN')} missing key: {key}"

    def test_hipaa_gcp_sql_security_checks(self):
        """Test that HIPAA GCP includes CloudSQL security checks."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Verify CloudSQL checks
        sql_checks = {
            "cloudsql_instance_automated_backups",
            "cloudsql_instance_ssl_connections",
            "cloudsql_instance_public_access",
        }

        for check in sql_checks:
            assert check in all_checks, f"Missing CloudSQL security check: {check}"

    def test_hipaa_gcp_network_security_checks(self):
        """Test that HIPAA GCP includes network security checks."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Verify network security checks
        network_checks = {
            "compute_firewall_ssh_access_from_the_internet_allowed",
            "compute_firewall_rdp_access_from_the_internet_allowed",
            "compute_subnet_flow_logs_enabled",
        }

        for check in network_checks:
            assert check in all_checks, f"Missing network security check: {check}"

    def test_hipaa_gcp_iam_checks_coverage(self):
        """Test that HIPAA GCP has comprehensive IAM checks."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Count IAM-related checks
        iam_checks = [check for check in all_checks if check.startswith("iam_")]
        assert len(iam_checks) >= 10, f"Should have at least 10 IAM checks, found {len(iam_checks)}"

    def test_hipaa_gcp_logging_metric_filters(self):
        """Test that HIPAA GCP includes logging metric filter alerts."""
        import json
        from pathlib import Path

        hipaa_path = Path("prowler/compliance/gcp/hipaa_gcp.json")
        with open(hipaa_path, "r") as f:
            hipaa_data = json.load(f)

        # Collect all checks
        all_checks = set()
        for req in hipaa_data["Requirements"]:
            all_checks.update(req["Checks"])

        # Count logging metric filter checks
        metric_filter_checks = [
            check
            for check in all_checks
            if "logging_log_metric_filter_and_alert" in check
        ]
        assert (
            len(metric_filter_checks) >= 5
        ), f"Should have at least 5 metric filter checks, found {len(metric_filter_checks)}"
