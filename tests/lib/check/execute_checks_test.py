import unittest
from unittest.mock import MagicMock, patch

from prowler.lib.check.check import execute_checks
from prowler.lib.check.models import Severity


class TestExecuteChecks(unittest.TestCase):
    def setUp(self):
        # Create a mock check class
        self.mock_check = MagicMock()
        self.mock_check.CheckID = "test_check"
        self.mock_check.Severity = Severity.medium

        # Create mock provider
        self.mock_provider = MagicMock()
        self.mock_provider.type = "aws"
        self.mock_provider._audit_config = {
            "severity_patches": {"test_check": "critical"}
        }
        self.mock_provider.mutelist.mutelist_file_path = None

        # Mock output options
        self.mock_output_options = MagicMock()
        self.mock_output_options.only_logs = False
        self.mock_output_options.verbose = False

        # Mock custom checks metadata
        self.mock_custom_checks_metadata = None

        # Mock config file
        self.mock_config_file = "mock_config.yaml"

    @patch("prowler.lib.check.check.import_check")
    @patch("prowler.lib.check.check.execute")
    @patch("prowler.lib.check.check.report")
    @patch("prowler.lib.check.check.update_audit_metadata")
    @patch("prowler.lib.check.check.alive_bar")
    @patch("prowler.lib.check.check.print_boxes")
    @patch("prowler.lib.check.check.print")
    def test_execute_checks_applies_severity_patch(
        self,
        mock_print,
        mock_print_boxes,
        mock_alive_bar,
        mock_update_audit_metadata,
        mock_report,
        mock_execute,
        mock_import_check,
    ):
        """Test that execute_checks correctly applies severity patches"""
        # Setup mocks
        mock_check_instance = MagicMock()
        mock_check_instance.CheckID = "test_check"
        mock_check_instance.Severity = Severity.medium
        mock_check_instance.ServiceName = "test_service"

        mock_check_class = MagicMock(return_value=mock_check_instance)
        mock_import_check.return_value = MagicMock()
        mock_import_check.return_value.test_check = mock_check_class

        mock_alive_bar.return_value.__enter__.return_value = MagicMock()

        # Execute the function
        execute_checks(
            ["test_check"],
            self.mock_provider,
            self.mock_custom_checks_metadata,
            self.mock_config_file,
            self.mock_output_options,
        )

        # Verify the severity was patched
        self.assertEqual(mock_check_instance.Severity, Severity.critical)

    @patch("prowler.lib.check.check.import_check")
    @patch("prowler.lib.check.check.execute")
    @patch("prowler.lib.check.check.report")
    @patch("prowler.lib.check.check.update_audit_metadata")
    @patch("prowler.lib.check.check.alive_bar")
    @patch("prowler.lib.check.check.print_boxes")
    @patch("prowler.lib.check.check.print")
    def test_execute_checks_no_severity_patch(
        self,
        mock_print,
        mock_print_boxes,
        mock_alive_bar,
        mock_update_audit_metadata,
        mock_report,
        mock_execute,
        mock_import_check,
    ):
        """Test that execute_checks doesn't change severity when no patch is defined"""
        # Setup mocks
        mock_check_instance = MagicMock()
        mock_check_instance.CheckID = "other_check"  # Different from the patched one
        mock_check_instance.Severity = Severity.medium
        mock_check_instance.ServiceName = "test_service"

        mock_check_class = MagicMock(return_value=mock_check_instance)
        mock_import_check.return_value = MagicMock()
        mock_import_check.return_value.other_check = mock_check_class

        mock_alive_bar.return_value.__enter__.return_value = MagicMock()

        # Execute the function
        execute_checks(
            ["other_check"],
            self.mock_provider,
            self.mock_custom_checks_metadata,
            self.mock_config_file,
            self.mock_output_options,
        )

        # Verify the severity was not changed
        self.assertEqual(mock_check_instance.Severity, Severity.medium)


if __name__ == "__main__":
    unittest.main()
