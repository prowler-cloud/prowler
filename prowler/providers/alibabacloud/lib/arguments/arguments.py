"""
Alibaba Cloud Provider CLI Arguments

This module defines the command-line interface arguments for the Alibaba Cloud provider.
"""

import os
from argparse import ArgumentTypeError, Namespace

from prowler.providers.alibabacloud.config import ALIBABACLOUD_REGIONS


def init_parser(self):
    """
    Initialize Alibaba Cloud provider CLI argument parser

    This function creates the argument parser for Alibaba Cloud provider and defines
    all the command-line arguments that can be used when auditing Alibaba Cloud.

    Args:
        self: The ProwlerArgumentParser instance
    """
    # Create Alibaba Cloud subparser
    alibabacloud_parser = self.subparsers.add_parser(
        "alibabacloud",
        parents=[self.common_providers_parser],
        help="Alibaba Cloud Provider",
    )

    # Authentication group
    alibabacloud_auth = alibabacloud_parser.add_argument_group(
        "Alibaba Cloud Authentication"
    )

    alibabacloud_auth.add_argument(
        "--access-key-id",
        nargs="?",
        default=os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID"),
        help="Alibaba Cloud AccessKey ID (also reads from ALIBABA_CLOUD_ACCESS_KEY_ID environment variable)",
    )

    alibabacloud_auth.add_argument(
        "--access-key-secret",
        nargs="?",
        default=os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
        help="Alibaba Cloud AccessKey Secret (also reads from ALIBABA_CLOUD_ACCESS_KEY_SECRET environment variable)",
    )

    alibabacloud_auth.add_argument(
        "--security-token",
        nargs="?",
        default=os.environ.get("ALIBABA_CLOUD_SECURITY_TOKEN"),
        help="Alibaba Cloud STS Security Token for temporary credentials (also reads from ALIBABA_CLOUD_SECURITY_TOKEN environment variable)",
    )

    # RAM Role assumption group
    alibabacloud_role = alibabacloud_parser.add_argument_group(
        "Alibaba Cloud RAM Role Assumption"
    )

    alibabacloud_role.add_argument(
        "--ram-role-arn",
        nargs="?",
        default=None,
        help="RAM Role ARN to assume for the audit (format: acs:ram::account-id:role/role-name)",
    )

    alibabacloud_role.add_argument(
        "--ram-session-name",
        nargs="?",
        default="ProwlerAuditSession",
        help="Session name for RAM role assumption (default: ProwlerAuditSession)",
    )

    alibabacloud_role.add_argument(
        "--ram-session-duration",
        nargs="?",
        type=int,
        default=3600,
        help="Session duration in seconds for RAM role assumption (900-43200, default: 3600)",
    )

    alibabacloud_role.add_argument(
        "--ram-external-id",
        nargs="?",
        default=None,
        help="External ID for RAM role assumption (optional)",
    )

    # Regions group
    alibabacloud_regions = alibabacloud_parser.add_argument_group(
        "Alibaba Cloud Regions"
    )

    alibabacloud_regions.add_argument(
        "--region-id",
        "--region-ids",
        nargs="+",
        default=[],
        dest="region_ids",
        help=f"Alibaba Cloud Region IDs to audit (space-separated). Available regions: {', '.join(ALIBABACLOUD_REGIONS[:10])}... (default: all regions)",
    )

    alibabacloud_regions.add_argument(
        "--filter-region",
        "--filter-regions",
        nargs="+",
        default=[],
        dest="filter_regions",
        help="Alibaba Cloud Region IDs to exclude from the audit (space-separated)",
    )

    # Resource filtering group
    alibabacloud_resources = alibabacloud_parser.add_argument_group(
        "Alibaba Cloud Resource Filtering"
    )

    alibabacloud_resources.add_argument(
        "--resource-tags",
        nargs="+",
        default=[],
        help="Filter resources by tags (format: key=value)",
    )

    alibabacloud_resources.add_argument(
        "--resource-ids",
        nargs="+",
        default=[],
        help="Specific resource IDs to audit (space-separated)",
    )


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """
    Validate Alibaba Cloud provider arguments

    This function validates the command-line arguments provided for the Alibaba Cloud provider.
    It checks for required credentials, validates region specifications, and ensures
    configuration coherence.

    Args:
        arguments: Parsed command-line arguments

    Returns:
        tuple: (is_valid: bool, error_message: str)
               - is_valid: True if arguments are valid, False otherwise
               - error_message: Error description if invalid, empty string if valid
    """
    # Check for required credentials
    if not arguments.access_key_id or not arguments.access_key_secret:
        return (
            False,
            "Alibaba Cloud AccessKey credentials are required. "
            "Provide --access-key-id and --access-key-secret, "
            "or set ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET environment variables.",
        )

    # Validate RAM role session duration
    if arguments.ram_role_arn:
        if not (900 <= arguments.ram_session_duration <= 43200):
            return (
                False,
                f"RAM role session duration must be between 900 and 43200 seconds. "
                f"Provided: {arguments.ram_session_duration}",
            )

    # Validate region IDs
    if arguments.region_ids:
        invalid_regions = [
            region for region in arguments.region_ids
            if region not in ALIBABACLOUD_REGIONS
        ]
        if invalid_regions:
            return (
                False,
                f"Invalid Alibaba Cloud region(s): {', '.join(invalid_regions)}. "
                f"Valid regions are: {', '.join(ALIBABACLOUD_REGIONS)}",
            )

    # Validate filter regions
    if arguments.filter_regions:
        invalid_filter_regions = [
            region for region in arguments.filter_regions
            if region not in ALIBABACLOUD_REGIONS
        ]
        if invalid_filter_regions:
            return (
                False,
                f"Invalid Alibaba Cloud filter region(s): {', '.join(invalid_filter_regions)}. "
                f"Valid regions are: {', '.join(ALIBABACLOUD_REGIONS)}",
            )

    # Validate resource tags format
    if arguments.resource_tags:
        for tag in arguments.resource_tags:
            if "=" not in tag:
                return (
                    False,
                    f"Invalid resource tag format: '{tag}'. Expected format: key=value",
                )

    # All validations passed
    return (True, "")
