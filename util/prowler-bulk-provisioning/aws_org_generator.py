#!/usr/bin/env python3

"""
AWS Organizations Account Generator for Prowler Bulk Provisioning

Generates YAML configuration for all accounts in an AWS Organization,
ready to be used with prowler_bulk_provisioning.py.

Prerequisites:
- ProwlerRole (or custom role) must be deployed across all accounts
- AWS credentials with Organizations read access (typically management account)
- See: https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/organizations/#deploying-prowler-iam-roles-across-aws-organizations
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    sys.exit(
        "boto3 is required. Install with: pip install boto3\n"
        "Or install all dependencies: pip install -r requirements-aws-org.txt"
    )

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required. Install with: pip install pyyaml")


def get_org_accounts(
    profile: Optional[str] = None, region: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve all accounts from AWS Organizations.

    Args:
        profile: AWS CLI profile name
        region: AWS region (defaults to us-east-1 for Organizations)

    Returns:
        List of account dictionaries with id, name, email, and status
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region or "us-east-1")
        client = session.client("organizations")

        accounts = []
        paginator = client.get_paginator("list_accounts")

        for page in paginator.paginate():
            for account in page["Accounts"]:
                # Only include ACTIVE accounts
                if account["Status"] == "ACTIVE":
                    accounts.append(
                        {
                            "id": account["Id"],
                            "name": account["Name"],
                            "email": account["Email"],
                            "status": account["Status"],
                        }
                    )

        return accounts

    except NoCredentialsError:
        sys.exit(
            "No AWS credentials found. Configure credentials using:\n"
            "  - AWS CLI: aws configure\n"
            "  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n"
            "  - IAM role if running on EC2/ECS/Lambda"
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            sys.exit(
                "Access denied to AWS Organizations API.\n"
                "Ensure you are using credentials from the management account\n"
                "with permissions to call organizations:ListAccounts"
            )
        elif error_code == "AWSOrganizationsNotInUseException":
            sys.exit(
                "AWS Organizations is not enabled for this account.\n"
                "This script requires an AWS Organization to be set up."
            )
        else:
            sys.exit(f"AWS API error: {e}")
    except Exception as e:
        sys.exit(f"Unexpected error listing accounts: {e}")


def generate_yaml_config(
    accounts: List[Dict[str, Any]],
    role_name: str = "ProwlerRole",
    external_id: Optional[str] = None,
    session_name: Optional[str] = None,
    duration_seconds: Optional[int] = None,
    alias_format: str = "{name}",
    exclude_accounts: Optional[List[str]] = None,
    include_accounts: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Generate YAML configuration for Prowler bulk provisioning.

    Args:
        accounts: List of account dictionaries from get_org_accounts
        role_name: IAM role name (default: ProwlerRole)
        external_id: External ID for role assumption (optional but recommended)
        session_name: Session name for role assumption (optional)
        duration_seconds: Session duration in seconds (optional)
        alias_format: Format string for alias (supports {name}, {id}, {email})
        exclude_accounts: List of account IDs to exclude
        include_accounts: List of account IDs to include (if set, only these are included)

    Returns:
        List of provider configurations ready for YAML export
    """
    exclude_accounts = exclude_accounts or []
    include_accounts = include_accounts or []

    providers = []

    for account in accounts:
        account_id = account["id"]

        # Apply filters
        if include_accounts and account_id not in include_accounts:
            continue
        if account_id in exclude_accounts:
            continue

        # Format alias using template
        alias = alias_format.format(
            name=account["name"], id=account_id, email=account["email"]
        )

        # Build role ARN
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        # Build credentials section
        credentials: Dict[str, Any] = {"role_arn": role_arn}

        if external_id:
            credentials["external_id"] = external_id

        if session_name:
            credentials["session_name"] = session_name

        if duration_seconds:
            credentials["duration_seconds"] = duration_seconds

        # Build provider entry
        provider = {
            "provider": "aws",
            "uid": account_id,
            "alias": alias,
            "auth_method": "role",
            "credentials": credentials,
        }

        providers.append(provider)

    return providers


def main():
    """Main function to generate AWS Organizations YAML configuration."""
    parser = argparse.ArgumentParser(
        description="Generate Prowler bulk provisioning YAML from AWS Organizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage - generate YAML for all accounts
  python aws_org_generator.py -o aws-accounts.yaml

  # Use custom role name and external ID
  python aws_org_generator.py -o aws-accounts.yaml \\
    --role-name ProwlerExecutionRole \\
    --external-id my-external-id-12345

  # Use specific AWS profile
  python aws_org_generator.py -o aws-accounts.yaml \\
    --profile org-management

  # Exclude specific accounts (e.g., management account)
  python aws_org_generator.py -o aws-accounts.yaml \\
    --exclude 123456789012,210987654321

  # Include only specific accounts
  python aws_org_generator.py -o aws-accounts.yaml \\
    --include 111111111111,222222222222

  # Custom alias format
  python aws_org_generator.py -o aws-accounts.yaml \\
    --alias-format "{name}-{id}"

Prerequisites:
  1. Deploy ProwlerRole across all accounts using CloudFormation StackSets:
     https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/organizations/#deploying-prowler-iam-roles-across-aws-organizations

  2. Ensure AWS credentials have Organizations read access:
     - organizations:ListAccounts
     - organizations:DescribeOrganization (optional)
        """,
    )

    parser.add_argument(
        "-o",
        "--output",
        default="aws-org-accounts.yaml",
        help="Output YAML file path (default: aws-org-accounts.yaml)",
    )

    parser.add_argument(
        "--role-name",
        default="ProwlerRole",
        help="IAM role name deployed across accounts (default: ProwlerRole)",
    )

    parser.add_argument(
        "--external-id",
        help="External ID for role assumption (recommended for security)",
    )

    parser.add_argument(
        "--session-name", help="Session name for role assumption (optional)"
    )

    parser.add_argument(
        "--duration-seconds",
        type=int,
        help="Session duration in seconds (optional, default: 3600)",
    )

    parser.add_argument(
        "--alias-format",
        default="{name}",
        help="Alias format template. Available: {name}, {id}, {email} (default: {name})",
    )

    parser.add_argument(
        "--exclude",
        help="Comma-separated list of account IDs to exclude",
    )

    parser.add_argument(
        "--include",
        help="Comma-separated list of account IDs to include (if set, only these are processed)",
    )

    parser.add_argument(
        "--profile",
        help="AWS CLI profile name (uses default credentials if not specified)",
    )

    parser.add_argument(
        "--region",
        help="AWS region (default: us-east-1, Organizations is global but needs a region)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configuration to stdout without writing file",
    )

    args = parser.parse_args()

    # Parse exclude/include lists
    exclude_accounts = (
        [acc.strip() for acc in args.exclude.split(",")] if args.exclude else []
    )
    include_accounts = (
        [acc.strip() for acc in args.include.split(",")] if args.include else []
    )

    print("Fetching accounts from AWS Organizations...")
    if args.profile:
        print(f"Using AWS profile: {args.profile}")

    # Get accounts from Organizations
    accounts = get_org_accounts(profile=args.profile, region=args.region)

    if not accounts:
        print("No active accounts found in organization.")
        return

    print(f"Found {len(accounts)} active accounts in organization")

    # Generate YAML configuration
    providers = generate_yaml_config(
        accounts=accounts,
        role_name=args.role_name,
        external_id=args.external_id,
        session_name=args.session_name,
        duration_seconds=args.duration_seconds,
        alias_format=args.alias_format,
        exclude_accounts=exclude_accounts,
        include_accounts=include_accounts,
    )

    if not providers:
        print("No providers generated after applying filters.")
        return

    print(f"Generated configuration for {len(providers)} accounts")

    # Output YAML
    yaml_content = yaml.dump(
        providers, default_flow_style=False, sort_keys=False, allow_unicode=True
    )

    if args.dry_run:
        print("\n--- Generated YAML Configuration ---\n")
        print(yaml_content)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        print(f"\nConfiguration written to: {args.output}")
        print("\nNext steps:")
        print(f"  1. Review the generated file: cat {args.output} | head -n 20")
        print(
            f"  2. Run bulk provisioning: python prowler_bulk_provisioning.py {args.output}"
        )


if __name__ == "__main__":
    main()
