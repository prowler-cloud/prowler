import argparse
import sys
from argparse import RawTextHelpFormatter

from prowler.config.config import default_output_directory, prowler_version
from prowler.providers.aws.aws_provider import get_aws_available_regions


class ProwlerArgumentParser:
    # Set the default parser
    def __init__(self):
        # CLI Arguments
        self.parser = argparse.ArgumentParser(
            prog="prowler",
            formatter_class=RawTextHelpFormatter,
            epilog="""
To see the different available options on a specific provider, run:
    prowler {provider} -h|--help

Detailed documentation at https://docs.prowler.cloud
""",
        )
        # Default
        self.parser.add_argument(
            "-v",
            "--version",
            action="version",
            version=f"Prowler {prowler_version}",
            help="show Prowler version",
        )
        # Common arguments parser
        self.common_providers_parser = argparse.ArgumentParser(add_help=False)

        # Providers Parser
        self.subparsers = self.parser.add_subparsers(
            title="Prowler Available Cloud Providers",
            dest="provider",
        )

        self.__init_outputs_parser__()
        self.__init_logging_parser__()
        self.__init_checks_parser__()
        self.__init_exclude_checks_parser__()
        self.__init_list_checks_parser__()

        # Init Providers Arguments
        self.__init_aws_parser__()
        self.__init_azure_parser__()

    def parse(self, args=None) -> argparse.Namespace:
        """
        parse is a wrapper to call parse_args() and do some validation
        """
        # We can override sys.argv
        if args:
            sys.argv = args

        # Set AWS as the default provider if no provider is supplied
        if len(sys.argv) == 1:
            sys.argv = self.__set_default_provider__(sys.argv)

        # Help and Version flags cannot set a default provider
        if (
            len(sys.argv) >= 2
            and (sys.argv[1] not in ("-h", "--help"))
            and (sys.argv[1] not in ("-v", "--version"))
        ):
            # Since the provider is always the second argument, we are checking if
            # a flag, starting by "-", is supplied
            if "-" in sys.argv[1]:
                sys.argv = self.__set_default_provider__(sys.argv)

        # Parse arguments
        args = self.parser.parse_args()

        # A provider is always required
        if not args.provider:
            self.parser.error(
                "A provider is required to see its specific help options."
            )

        # Only Logging Configuration
        if args.only_logs:
            args.no_banner = True

        return args

    def __set_default_provider__(self, args: list) -> list:
        default_args = [args[0]]
        provider = "aws"
        default_args.append(provider)
        default_args.extend(args[1:])
        # Save the arguments with the default provider included
        return default_args

    def __init_outputs_parser__(self):
        # Outputs
        common_outputs_parser = self.common_providers_parser.add_argument_group(
            "Outputs"
        )
        common_outputs_parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Store or send only Prowler failed findings",
        )
        common_outputs_parser.add_argument(
            "-M",
            "--output-modes",
            nargs="+",
            help="Output modes, by default csv, html and json",
            default=["csv", "json", "html"],
            choices=["csv", "json", "json-asff", "html"],
        )
        common_outputs_parser.add_argument(
            "-F",
            "--output-filename",
            nargs="?",
            help="Custom output report name without the file extension, if not specified will use default output/prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format",
        )
        common_outputs_parser.add_argument(
            "-o",
            "--output-directory",
            nargs="?",
            help="Custom output directory, by default the folder where Prowler is stored",
            default=default_output_directory,
        )
        common_outputs_parser.add_argument(
            "--verbose",
            action="store_true",
            help="Display detailed information about findings",
        )
        common_outputs_parser.add_argument(
            "-b", "--no-banner", action="store_true", help="Hide Prowler banner"
        )

    def __init_logging_parser__(self):
        # Logging Options
        # Both options can be combined to only report to file some log level
        common_logging_parser = self.common_providers_parser.add_argument_group(
            "Logging"
        )
        common_logging_parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="CRITICAL",
            help="Select Log Level",
        )
        common_logging_parser.add_argument(
            "--log-file",
            nargs="?",
            help="Set log file name",
        )
        common_logging_parser.add_argument(
            "--only-logs",
            action="store_true",
            help="Print only Prowler logs by the stdout. This option sets --no-banner.",
        )

    def __init_exclude_checks_parser__(self):
        # Exclude checks options
        exclude_checks_parser = self.common_providers_parser.add_argument_group(
            "Exclude checks/services to run"
        )
        exclude_checks_parser.add_argument(
            "-e", "--excluded-checks", nargs="+", help="Checks to exclude"
        )
        exclude_checks_parser.add_argument(
            "--excluded-services", nargs="+", help="Services to exclude"
        )

    def __init_checks_parser__(self):
        # Set checks to execute
        common_checks_parser = self.common_providers_parser.add_argument_group(
            "Specify checks/services to run arguments"
        )
        # The following arguments needs to be set exclusivelly
        group = common_checks_parser.add_mutually_exclusive_group()
        group.add_argument(
            "-c", "--checks", nargs="+", help="List of checks to be executed."
        )
        group.add_argument(
            "-C",
            "--checks-file",
            nargs="?",
            help="JSON file containing the checks to be executed. See config/checklist_example.json",
        )
        group.add_argument(
            "-s", "--services", nargs="+", help="List of services to be executed."
        )
        group.add_argument(
            "--severity",
            nargs="+",
            help="List of severities to be executed [informational, low, medium, high, critical]",
            choices=["informational", "low", "medium", "high", "critical"],
        )
        group.add_argument(
            "--compliance",
            nargs="+",
            help="Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: ens_rd2022_aws)",
            choices=["ens_rd2022_aws", "cis_1.4_aws", "cis_1.5_aws"],
        )
        group.add_argument(
            "--categories",
            nargs="+",
            help="List of categories to be executed.",
            default=[],
            # Pending validate choices
        )

    def __init_list_checks_parser__(self):
        # List checks options
        list_checks_parser = self.common_providers_parser.add_argument_group(
            "List checks/services/categories/compliance-framework checks"
        )
        list_group = list_checks_parser.add_mutually_exclusive_group()
        list_group.add_argument(
            "-l", "--list-checks", action="store_true", help="List checks"
        )
        list_group.add_argument(
            "--list-services", action="store_true", help="List services"
        )
        list_group.add_argument(
            "--list-compliance", action="store_true", help="List compliance frameworks"
        )
        list_group.add_argument(
            "--list-compliance-requirements",
            nargs="+",
            help="List compliance requirements for a given requirement",
            choices=["ens_rd2022_aws", "cis_1.4_aws", "cis_1.5_aws"],
        )
        list_group.add_argument(
            "--list-categories",
            action="store_true",
            help="List the available check's categories",
        )

    def __init_aws_parser__(self):
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
            "-T",
            "--session-duration",
            nargs="?",
            default=3600,
            type=int,
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
        aws_3rd_party_subparser = aws_parser.add_argument_group(
            "3rd Party Integrations"
        )
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
            help="Path for allowlist yaml file. See example prowler/config/allowlist.yaml for reference and format. It also accepts AWS DynamoDB Table ARN or S3 URI, see more in https://docs.prowler.cloud/en/latest/tutorials/allowlist/",
        )

    def __init_azure_parser__(self):
        """Init the Azure Provider CLI parser"""
        azure_parser = self.subparsers.add_parser(
            "azure", parents=[self.common_providers_parser], help="Azure Provider"
        )
        # Authentication Modes
        azure_auth_subparser = azure_parser.add_argument_group("Authentication Modes")
        azure_auth_modes_group = azure_auth_subparser.add_mutually_exclusive_group()
        azure_auth_modes_group.add_argument(
            "--az-cli-auth",
            action="store_true",
            help="Use Azure cli credentials to log in against azure",
        )
        azure_auth_modes_group.add_argument(
            "--sp-env-auth",
            action="store_true",
            help="Use service principal env variables authentication to log in against azure",
        )
        azure_auth_modes_group.add_argument(
            "--browser-auth",
            action="store_true",
            help="Use browser authentication to log in against azure ",
        )
        azure_auth_modes_group.add_argument(
            "--managed-identity-auth",
            action="store_true",
            help="Use managed identity authentication to log in against azure ",
        )
        # Subscriptions
        azure_subscriptions_subparser = azure_parser.add_argument_group("Subscriptions")
        azure_subscriptions_subparser.add_argument(
            "--subscription-ids",
            nargs="+",
            default=[],
            help="Azure subscription ids to be scanned by prowler",
        )
