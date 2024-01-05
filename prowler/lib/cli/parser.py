import argparse
import sys
from argparse import RawTextHelpFormatter

from prowler.config.config import (
    available_compliance_frameworks,
    check_current_version,
    default_config_file_path,
    default_output_directory,
)
from prowler.providers.common.arguments import (
    init_providers_parser,
    validate_provider_arguments,
)


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
            action="store_true",
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
        self.__init_config_parser__()
        self.__init_custom_checks_metadata_parser__()

        # Init Providers Arguments
        init_providers_parser(self)

    def parse(self, args=None) -> argparse.Namespace:
        """
        parse is a wrapper to call parse_args() and do some validation
        """
        # We can override sys.argv
        if args:
            sys.argv = args

        if len(sys.argv) == 2 and sys.argv[1] in ("-v", "--version"):
            print(check_current_version())
            sys.exit(0)

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
        if args.only_logs or args.list_checks_json:
            args.no_banner = True

        # Extra validation for provider arguments
        valid, message = validate_provider_arguments(args)
        if not valid:
            self.parser.error(f"{args.provider}: {message}")

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
            "--status",
            nargs="+",
            help="Filter by the status of the findings [PASS, FAIL, INFO]",
            choices=["PASS", "FAIL", "INFO"],
        )
        common_outputs_parser.add_argument(
            "-M",
            "--output-modes",
            nargs="+",
            help="Output modes, by default csv, html and json",
            default=["csv", "json", "html", "json-ocsf"],
            choices=["csv", "json", "json-asff", "html", "json-ocsf"],
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
            "-z",
            "--ignore-exit-code-3",
            action="store_true",
            help="Failed checks do not trigger exit code 3",
        )
        common_outputs_parser.add_argument(
            "-b", "--no-banner", action="store_true", help="Hide Prowler banner"
        )
        common_outputs_parser.add_argument(
            "--slack",
            action="store_true",
            help="Send a summary of the execution with a Slack APP in your channel. Environment variables SLACK_API_TOKEN and SLACK_CHANNEL_ID are required (see more in https://docs.prowler.cloud/en/latest/tutorials/integrations/#slack).",
        )
        common_outputs_parser.add_argument(
            "--unix-timestamp",
            action="store_true",
            default=False,
            help="Set the output timestamp format as unix timestamps instead of iso format timestamps (default mode).",
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
            "Specify checks/services to run"
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
        common_checks_parser.add_argument(
            "--severity",
            nargs="+",
            help="List of severities to be executed [informational, low, medium, high, critical]",
            choices=["informational", "low", "medium", "high", "critical"],
        )
        group.add_argument(
            "--compliance",
            nargs="+",
            help="Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: ens_rd2022_aws)",
            choices=available_compliance_frameworks,
        )
        group.add_argument(
            "--categories",
            nargs="+",
            help="List of categories to be executed.",
            default=[],
            # Pending validate choices
        )
        common_checks_parser.add_argument(
            "-x",
            "--checks-folder",
            nargs="?",
            help="Specify external directory with custom checks (each check must have a folder with the required files, see more in https://docs.prowler.cloud/en/latest/tutorials/misc/#custom-checks).",
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
            "--list-checks-json",
            action="store_true",
            help="Output a list of checks in json for use with --checks-file",
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
            help="List compliance requirements for a given compliance framework",
            choices=available_compliance_frameworks,
        )
        list_group.add_argument(
            "--list-categories",
            action="store_true",
            help="List the available check's categories",
        )

    def __init_config_parser__(self):
        config_parser = self.common_providers_parser.add_argument_group("Configuration")
        config_parser.add_argument(
            "--config-file",
            nargs="?",
            default=default_config_file_path,
            help="Set configuration file path",
        )

    def __init_custom_checks_metadata_parser__(self):
        # CustomChecksMetadata
        custom_checks_metadata_subparser = (
            self.common_providers_parser.add_argument_group("Custom Checks Metadata")
        )
        custom_checks_metadata_subparser.add_argument(
            "--custom-checks-metadata-file",
            nargs="?",
            default=None,
            help="Path for the custom checks metadata YAML file. See example prowler/config/custom_checks_metadata_example.yaml for reference and format. See more in https://docs.prowler.cloud/en/latest/tutorials/custom-checks-metadata/",
        )
