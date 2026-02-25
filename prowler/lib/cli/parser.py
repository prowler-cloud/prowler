import argparse
import sys
from argparse import RawTextHelpFormatter

from dashboard.lib.arguments.arguments import init_dashboard_parser
from prowler.config.config import (
    available_compliance_frameworks,
    available_output_formats,
    check_current_version,
    default_config_file_path,
    default_fixer_config_file_path,
    default_output_directory,
)
from prowler.lib.check.models import Severity
from prowler.lib.outputs.common import Status
from prowler.providers.common.arguments import (
    init_providers_parser,
    validate_asff_usage,
    validate_provider_arguments,
)


class ProwlerArgumentParser:
    # Set the default parser
    def __init__(self):
        # CLI Arguments
        self.parser = argparse.ArgumentParser(
            prog="prowler",
            formatter_class=RawTextHelpFormatter,
            usage="prowler [-h] [--version] {aws,azure,gcp,kubernetes,m365,github,googleworkspace,nhn,mongodbatlas,oraclecloud,alibabacloud,cloudflare,openstack,dashboard,iac,image} ...",
            epilog="""
Available Cloud Providers:
  {aws,azure,gcp,kubernetes,m365,github,googleworkspace,iac,llm,image,nhn,mongodbatlas,oraclecloud,alibabacloud,cloudflare,openstack}
    aws                 AWS Provider
    azure               Azure Provider
    gcp                 GCP Provider
    kubernetes          Kubernetes Provider
    m365                Microsoft 365 Provider
    github              GitHub Provider
    googleworkspace     Google Workspace Provider
    cloudflare          Cloudflare Provider
    oraclecloud         Oracle Cloud Infrastructure Provider
    openstack           OpenStack Provider
    alibabacloud        Alibaba Cloud Provider
    iac                 IaC Provider (Beta)
    llm                 LLM Provider (Beta)
    image               Container Image Provider
    nhn                 NHN Provider (Unofficial)
    mongodbatlas        MongoDB Atlas Provider (Beta)

Available components:
    dashboard           Local dashboard

To see the different available options on a specific component, run:
    prowler {provider|dashboard} -h|--help

Detailed documentation at https://docs.prowler.com
""",
        )
        # Default
        self.parser.add_argument(
            "--version",
            "-v",
            action="store_true",
            help="show Prowler version",
        )
        # Common arguments parser
        self.common_providers_parser = argparse.ArgumentParser(add_help=False)

        # Providers Parser
        self.subparsers = self.parser.add_subparsers(
            title="Available Cloud Providers", dest="provider", help=argparse.SUPPRESS
        )

        self.__init_outputs_parser__()
        self.__init_logging_parser__()
        self.__init_checks_parser__()
        self.__init_exclude_checks_parser__()
        self.__init_list_checks_parser__()
        self.__init_mutelist_parser__()
        self.__init_config_parser__()
        self.__init_custom_checks_metadata_parser__()
        self.__init_third_party_integrations_parser__()

        # Init Providers Arguments
        init_providers_parser(self)

        # Dashboard Parser
        init_dashboard_parser(self)

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

            # Provider aliases mapping
            # Microsoft 365
            elif sys.argv[1] == "microsoft365":
                sys.argv[1] = "m365"
            # Oracle Cloud Infrastructure
            elif sys.argv[1] == "oci":
                sys.argv[1] = "oraclecloud"

        # Parse arguments
        args = self.parser.parse_args()

        # A provider is always required
        if not args.provider:
            self.parser.error(
                "A provider/component is required to see its specific help options."
            )

        # Only Logging Configuration
        if args.provider != "dashboard" and (args.only_logs or args.list_checks_json):
            args.no_banner = True

        # Extra validation for provider arguments
        valid, message = validate_provider_arguments(args)
        if not valid:
            self.parser.error(f"{args.provider}: {message}")

        asff_is_valid, asff_error = validate_asff_usage(
            args.provider, getattr(args, "output_formats", None)
        )
        if not asff_is_valid:
            self.parser.error(asff_error)

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
            help=f"Filter by the status of the findings {[status.value for status in Status]}",
            choices=[status.value for status in Status],
        )
        common_outputs_parser.add_argument(
            "--output-formats",
            "--output-modes",
            "-M",
            nargs="+",
            help="Output modes, by default csv and json-oscf are saved. When using AWS Security Hub integration, json-asff output is also saved.",
            default=["csv", "json-ocsf", "html"],
            choices=available_output_formats,
        )
        common_outputs_parser.add_argument(
            "--output-filename",
            "-F",
            nargs="?",
            help="Custom output report name without the file extension, if not specified will use default output/prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format",
        )
        common_outputs_parser.add_argument(
            "--output-directory",
            "-o",
            nargs="?",
            help="Custom output directory, by default the folder where Prowler is stored",
            default=default_output_directory,
        )
        common_outputs_parser.add_argument(
            "--verbose",
            action="store_true",
            help="Runs showing all checks executed and results",
        )
        common_outputs_parser.add_argument(
            "--ignore-exit-code-3",
            "-z",
            action="store_true",
            help="Failed checks do not trigger exit code 3",
        )
        common_outputs_parser.add_argument(
            "--no-banner", "-b", action="store_true", help="Hide Prowler banner"
        )
        common_outputs_parser.add_argument(
            "--no-color",
            action="store_true",
            help="Disable color codes in output",
        )

        common_outputs_parser.add_argument(
            "--unix-timestamp",
            action="store_true",
            default=False,
            help="Set the output timestamp format as unix timestamps instead of iso format timestamps (default mode).",
        )
        common_outputs_parser.add_argument(
            "--export-ocsf",
            action="store_true",
            help=(
                "Send OCSF output to Prowler Cloud ingestion endpoint. "
                "Requires PROWLER_API_KEY environment variable."
            ),
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
            "--excluded-check",
            "--excluded-checks",
            "-e",
            nargs="+",
            help="Checks to exclude",
        )
        exclude_checks_parser.add_argument(
            "--excluded-checks-file",
            nargs="?",
            help="JSON file containing the checks to be excluded. See config/checklist_example.json",
        )
        exclude_checks_parser.add_argument(
            "--excluded-service",
            "--excluded-services",
            nargs="+",
            help="Services to exclude",
        )

    def __init_checks_parser__(self):
        # Set checks to execute
        common_checks_parser = self.common_providers_parser.add_argument_group(
            "Specify checks/services to run"
        )
        # The following arguments needs to be set exclusivelly
        group = common_checks_parser.add_mutually_exclusive_group()
        group.add_argument(
            "--check",
            "--checks",
            "-c",
            nargs="+",
            help="List of checks to be executed.",
        )
        group.add_argument(
            "--checks-file",
            "-C",
            nargs="?",
            help="JSON file containing the checks to be executed. See config/checklist_example.json",
        )
        group.add_argument(
            "--service",
            "--services",
            "-s",
            nargs="+",
            help="List of services to be executed.",
        )
        common_checks_parser.add_argument(
            "--severity",
            "--severities",
            nargs="+",
            help=f"Severities to be executed {[severity.value for severity in Severity]}",
            choices=[severity.value for severity in Severity],
        )
        group.add_argument(
            "--compliance",
            nargs="+",
            help="Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: cis_3.0_aws)",
            choices=available_compliance_frameworks,
        )
        group.add_argument(
            "--category",
            "--categories",
            nargs="+",
            help="List of categories to be executed.",
            default=[],
            # TODO: Pending validate choices
        )
        common_checks_parser.add_argument(
            "--checks-folder",
            "-x",
            nargs="?",
            help="Specify external directory with custom checks (each check must have a folder with the required files, see more in https://docs.prowler.com/user-guide/cli/tutorials/misc#custom-checks-in-prowler).",
        )

    def __init_list_checks_parser__(self):
        # List checks options
        list_checks_parser = self.common_providers_parser.add_argument_group(
            "List checks/services/categories/compliance-framework checks"
        )
        list_group = list_checks_parser.add_mutually_exclusive_group()
        list_group.add_argument(
            "--list-checks", "-l", action="store_true", help="List checks"
        )
        list_group.add_argument(
            "--list-checks-json",
            action="store_true",
            help="Output a list of checks in json format to use with --checks-file option",
        )
        list_group.add_argument(
            "--list-services",
            action="store_true",
            help="List covered services by given provider",
        )
        list_group.add_argument(
            "--list-compliance",
            "--list-compliances",
            action="store_true",
            help="List all available compliance frameworks",
        )
        list_group.add_argument(
            "--list-compliance-requirements",
            nargs="+",
            help="List requirements and checks per compliance framework",
            choices=available_compliance_frameworks,
        )
        list_group.add_argument(
            "--list-categories",
            action="store_true",
            help="List the available check's categories",
        )
        list_group.add_argument(
            "--list-fixer",
            "--list-fixers",
            "--list-remediations",
            action="store_true",
            help="List fixers available for the provider",
        )

    def __init_mutelist_parser__(self):
        mutelist_subparser = self.common_providers_parser.add_argument_group("Mutelist")
        mutelist_subparser.add_argument(
            "--mutelist-file",
            "-w",
            nargs="?",
            help="Path for mutelist YAML file. See example prowler/config/<provider>_mutelist.yaml for reference and format. For AWS provider, it also accepts AWS DynamoDB Table, Lambda ARNs or S3 URIs, see more in https://docs.prowler.com/user-guide/cli/tutorials/mutelist",
        )

    def __init_config_parser__(self):
        config_parser = self.common_providers_parser.add_argument_group("Configuration")
        config_parser.add_argument(
            "--config-file",
            nargs="?",
            default=default_config_file_path,
            help="Set configuration file path",
        )
        config_parser.add_argument(
            "--fixer-config",
            nargs="?",
            default=default_fixer_config_file_path,
            help="Set configuration fixer file path",
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
            help="Path for the custom checks metadata YAML file. See example prowler/config/custom_checks_metadata_example.yaml for reference and format. See more in https://docs.prowler.com/user-guide/cli/tutorials/custom-checks-metadata/",
        )

    def __init_third_party_integrations_parser__(self):
        third_party_subparser = self.common_providers_parser.add_argument_group(
            "3rd Party Integrations"
        )
        third_party_subparser.add_argument(
            "--shodan",
            "-N",
            nargs="?",
            default=None,
            metavar="SHODAN_API_KEY",
            help="Check if any public IPs in your Cloud environments are exposed in Shodan.",
        )
        third_party_subparser.add_argument(
            "--slack",
            action="store_true",
            help="Send a summary of the execution with a Slack APP in your channel. Environment variables SLACK_API_TOKEN and SLACK_CHANNEL_NAME are required (see more in https://docs.prowler.com/user-guide/cli/tutorials/integrations#configuration-of-the-integration-with-slack/).",
        )
