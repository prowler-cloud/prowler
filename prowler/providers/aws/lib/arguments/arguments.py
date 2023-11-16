from argparse import ArgumentTypeError, Namespace

from prowler.providers.aws.aws_provider import get_aws_available_regions
from prowler.providers.aws.lib.arn.arn import arn_type


def init_parser(self):
    """Init the AWS Provider CLI parser"""
    aws_parser = self.subparsers.add_parser(
        "aws", parents=[self.common_providers_parser], help="AWS Provider"
    )
    # Authentication Methods
    aws_auth_subparser = aws_parser.add_argument_group("Authentication Modes")
    aws_auth_subparser.add_argument(
        "-p",
        "--profile",
        nargs="?",
        default=None,
        help="AWS profile to launch prowler with",
    )
    aws_auth_subparser.add_argument(
        "-R",
        "--role",
        nargs="?",
        default=None,
        help="ARN of the role to be assumed",
        # Pending ARN validation
    )
    aws_auth_subparser.add_argument(
        "--sts-endpoint-region",
        nargs="?",
        default=None,
        help="Specify the AWS STS endpoint region to use. Read more at https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html",
    )
    aws_auth_subparser.add_argument(
        "--mfa",
        action="store_true",
        help="IAM entity enforces MFA so you need to input the MFA ARN and the TOTP",
    )
    aws_auth_subparser.add_argument(
        "-T",
        "--session-duration",
        nargs="?",
        default=3600,
        type=validate_session_duration,
        help="Assumed role session duration in seconds, must be between 900 and 43200. Default: 3600",
        # Pending session duration validation
    )
    aws_auth_subparser.add_argument(
        "-I",
        "--external-id",
        nargs="?",
        default=None,
        help="External ID to be passed when assuming role",
    )
    # AWS Regions
    aws_regions_subparser = aws_parser.add_argument_group("AWS Regions")
    aws_regions_subparser.add_argument(
        "-f",
        "--region",
        "--filter-region",
        nargs="+",
        help="AWS region names to run Prowler against",
        choices=get_aws_available_regions(),
    )
    # AWS Organizations
    aws_orgs_subparser = aws_parser.add_argument_group("AWS Organizations")
    aws_orgs_subparser.add_argument(
        "-O",
        "--organizations-role",
        nargs="?",
        help="Specify AWS Organizations management role ARN to be assumed, to get Organization metadata",
    )
    # AWS Security Hub
    aws_security_hub_subparser = aws_parser.add_argument_group("AWS Security Hub")
    aws_security_hub_subparser.add_argument(
        "-S",
        "--security-hub",
        action="store_true",
        help="Send check output to AWS Security Hub",
    )
    aws_security_hub_subparser.add_argument(
        "--skip-sh-update",
        action="store_true",
        help="Skip updating previous findings of Prowler in Security Hub",
    )
    # AWS Quick Inventory
    aws_quick_inventory_subparser = aws_parser.add_argument_group("Quick Inventory")
    aws_quick_inventory_subparser.add_argument(
        "-i",
        "--quick-inventory",
        action="store_true",
        help="Run Prowler Quick Inventory. The inventory will be stored in an output csv by default",
    )
    # AWS Outputs
    aws_outputs_subparser = aws_parser.add_argument_group("AWS Outputs to S3")
    aws_outputs_bucket_parser = aws_outputs_subparser.add_mutually_exclusive_group()
    aws_outputs_bucket_parser.add_argument(
        "-B",
        "--output-bucket",
        nargs="?",
        default=None,
        help="Custom output bucket, requires -M <mode> and it can work also with -o flag.",
    )
    aws_outputs_bucket_parser.add_argument(
        "-D",
        "--output-bucket-no-assume",
        nargs="?",
        default=None,
        help="Same as -B but do not use the assumed role credentials to put objects to the bucket, instead uses the initial credentials.",
    )
    aws_3rd_party_subparser = aws_parser.add_argument_group("3rd Party Integrations")
    aws_3rd_party_subparser.add_argument(
        "-N",
        "--shodan",
        nargs="?",
        default=None,
        help="Shodan API key used by check ec2_elastic_ip_shodan.",
    )
    # Allowlist
    allowlist_subparser = aws_parser.add_argument_group("Allowlist")
    allowlist_subparser.add_argument(
        "-w",
        "--allowlist-file",
        nargs="?",
        default=None,
        help="Path for allowlist yaml file. See example prowler/config/aws_allowlist.yaml for reference and format. It also accepts AWS DynamoDB Table or Lambda ARNs or S3 URIs, see more in https://docs.prowler.cloud/en/latest/tutorials/allowlist/",
    )

    # Based Scans
    aws_based_scans_subparser = aws_parser.add_argument_group("AWS Based Scans")
    aws_based_scans_parser = aws_based_scans_subparser.add_mutually_exclusive_group()
    aws_based_scans_parser.add_argument(
        "--resource-tags",
        nargs="+",
        default=None,
        help="Scan only resources with specific AWS Tags (Key=Value), e.g., Environment=dev Project=prowler",
    )
    aws_based_scans_parser.add_argument(
        "--resource-arn",
        nargs="+",
        type=arn_type,
        default=None,
        help="Scan only resources with specific AWS Resource ARNs, e.g., arn:aws:iam::012345678910:user/test arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678",
    )

    # Boto3 Config
    boto3_config_subparser = aws_parser.add_argument_group("Boto3 Config")
    boto3_config_subparser.add_argument(
        "--aws-retries-max-attempts",
        nargs="?",
        default=None,
        type=int,
        help="Set the maximum attemps for the Boto3 standard retrier config (Default: 3)",
    )

    # Ignore Unused Services
    ignore_unused_services_subparser = aws_parser.add_argument_group(
        "Ignore Unused Services"
    )
    ignore_unused_services_subparser.add_argument(
        "--ignore-unused-services",
        action="store_true",
        help="Ignore findings in unused services",
    )


def validate_session_duration(duration):
    """validate_session_duration validates that the AWS STS Assume Role Session Duration is between 900 and 43200 seconds."""
    duration = int(duration)
    # Since the range(i,j) goes from i to j-1 we have to j+1
    if duration not in range(900, 43201):
        raise ArgumentTypeError("Session duration must be between 900 and 43200")
    return duration


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """validate_arguments returns {True, "} if the provider arguments passed are valid and can be used together. It performs an extra validation, specific for the AWS provider, apart from the argparse lib."""

    # Handle if session_duration is not the default value or external_id is set
    if (
        arguments.session_duration and arguments.session_duration != 3600
    ) or arguments.external_id:
        if not arguments.role:
            return (False, "To use -I/-T options -R option is needed")

    return (True, "")
