#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from os import mkdir
from os.path import isdir

from config.config import (
    change_config_var,
    default_output_directory,
    output_file_timestamp,
)
from lib.banner import print_banner, print_version
from lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    exclude_checks_to_run,
    exclude_services_to_run,
    execute_checks,
    list_categories,
    list_services,
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_services,
    set_output_options,
)
from lib.check.checks_loader import load_checks_to_execute
from lib.check.compliance import update_checks_metadata_with_compliance
from lib.logger import logger, set_logging_config
from lib.outputs.outputs import (
    add_html_footer,
    close_json,
    display_compliance_table,
    display_summary_table,
    send_to_s3_bucket,
)
from providers.aws.aws_provider import aws_provider_set_session
from providers.aws.lib.allowlist.allowlist import parse_allowlist_file
from providers.aws.lib.security_hub.security_hub import (
    resolve_security_hub_previous_findings,
)
from providers.azure.azure_provider import azure_provider_set_session

if __name__ == "__main__":
    # CLI Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "provider",
        choices=["aws", "azure"],
        nargs="?",
        default="aws",
        help="Specify Cloud Provider",
    )

    # Arguments to set checks to run
    # The following arguments needs to be set exclusivelly
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--checks", nargs="+", help="List of checks")
    group.add_argument("-C", "--checks-file", nargs="?", help="List of checks")
    group.add_argument("-s", "--services", nargs="+", help="List of services")
    group.add_argument(
        "--severity",
        nargs="+",
        help="List of severities [informational, low, medium, high, critical]",
        choices=["informational", "low", "medium", "high", "critical"],
    )
    group.add_argument(
        "--compliance",
        nargs="+",
        help="Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: ens_rd2022_aws)",
        choices=["ens_rd2022_aws"],
    )
    group.add_argument("--categories", nargs="+", help="List of categories", default=[])

    # Exclude checks options
    parser.add_argument("-e", "--excluded-checks", nargs="+", help="Checks to exclude")
    parser.add_argument("--excluded-services", nargs="+", help="Services to exclude")
    # List checks options
    list_group = parser.add_mutually_exclusive_group()
    list_group.add_argument(
        "-L", "--list-groups", action="store_true", help="List groups"
    )
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
        nargs="?",
        help="List compliance requirements for a given requirement",
        choices=["ens_rd2022_aws"],
    )
    list_group.add_argument(
        "--list-categories",
        action="store_true",
        help="List the available check's categories",
    )

    parser.add_argument(
        "-b", "--no-banner", action="store_false", help="Hide Prowler banner"
    )
    parser.add_argument(
        "-V", "-v", "--version", action="store_true", help="Show Prowler version"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Show only Prowler failed findings"
    )

    # Both options can be combined to only report to file some log level
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="CRITICAL",
        help="Select Log Level",
    )
    parser.add_argument(
        "--log-file",
        nargs="?",
        help="Set log file name",
    )

    parser.add_argument(
        "-p",
        "--profile",
        nargs="?",
        default=None,
        help="AWS profile to launch prowler with",
    )
    parser.add_argument(
        "-R",
        "--role",
        nargs="?",
        default=None,
        help="ARN of the role to be assumed",
    )
    parser.add_argument(
        "-T",
        "--session-duration",
        nargs="?",
        default=3600,
        type=int,
        help="Assumed role session duration in seconds, by default 3600",
    )
    parser.add_argument(
        "-I",
        "--external-id",
        nargs="?",
        default=None,
        help="External ID to be passed when assuming role",
    )
    parser.add_argument(
        "-f",
        "--filter-region",
        nargs="+",
        help="AWS region names to run Prowler against",
    )
    parser.add_argument(
        "-M",
        "--output-modes",
        nargs="+",
        help="Output mode, by default csv",
        default=["csv", "json"],
        choices=["csv", "json", "json-asff", "html"],
    )
    parser.add_argument(
        "-F",
        "--output-filename",
        nargs="?",
        default=None,
        help="Custom output report name, if not specified will use default output/prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format.",
    )
    parser.add_argument(
        "-o",
        "--output-directory",
        nargs="?",
        help="Custom output directory, by default the folder where Prowler is stored",
        default=default_output_directory,
    )
    parser.add_argument(
        "-O",
        "--organizations-role",
        nargs="?",
        help="Specify AWS Organizations management role ARN to be assumed, to get Organization metadata",
    )
    parser.add_argument(
        "-S",
        "--security-hub",
        action="store_true",
        help="Send check output to AWS Security Hub",
    )
    bucket = parser.add_mutually_exclusive_group()
    bucket.add_argument(
        "-B",
        "--output-bucket",
        nargs="?",
        default=None,
        help="Custom output bucket, requires -M <mode> and it can work also with -o flag.",
    )
    bucket.add_argument(
        "-D",
        "--output-bucket-no-assume",
        nargs="?",
        default=None,
        help="Same as -B but do not use the assumed role credentials to put objects to the bucket, instead uses the initial credentials.",
    )
    parser.add_argument(
        "-N",
        "--shodan",
        nargs="?",
        default=None,
        help="Shodan API key used by check ec2_elastic_ip_shodan.",
    )
    parser.add_argument(
        "-w",
        "--allowlist-file",
        nargs="?",
        default=None,
        help="Path for allowlist yaml file, by default is 'providers/aws/allowlist.yaml'. See default yaml for reference and format.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display detailed information about findings.",
    )
    parser.add_argument(
        "--subscription-ids",
        nargs="+",
        default=[],
        help="Azure subscription ids to be scanned by prowler",
    )
    # Parse Arguments
    args = parser.parse_args()

    provider = args.provider
    checks = args.checks
    excluded_checks = args.excluded_checks
    excluded_services = args.excluded_services
    services = args.services
    categories = args.categories
    checks_file = args.checks_file
    output_directory = args.output_directory
    output_filename = args.output_filename
    severities = args.severity
    compliance_framework = args.compliance
    output_modes = args.output_modes

    # Azure options
    subscriptions = args.subscription_ids

    # We treat the compliance framework as another output format
    if compliance_framework:
        output_modes.extend(compliance_framework)

    # Set Logger configuration
    set_logging_config(args.log_file, args.log_level)

    # Role assumption input options tests
    if args.session_duration not in range(900, 43200):
        logger.critical("Value for -T option must be between 900 and 43200")
        sys.exit()
    if args.session_duration != 3600 or args.external_id:
        if not args.role:
            logger.critical("To use -I/-T options -R option is needed")
            sys.exit()

    if args.version:
        print_version()
        sys.exit()

    if args.no_banner:
        print_banner(args)

    if args.list_services:
        print_services(list_services(provider))
        sys.exit()

    if args.shodan:
        change_config_var("shodan_api_key", args.shodan)

    # Load checks metadata
    logger.debug("Loading checks metadata from .metadata.json files")
    bulk_checks_metadata = bulk_load_checks_metadata(provider)

    if args.list_categories:
        print_categories(list_categories(provider, bulk_checks_metadata))
        sys.exit()

    bulk_compliance_frameworks = {}
    # Load compliance frameworks
    logger.debug("Loading compliance frameworks from .json files")

    # Load the compliance framework if specified with --compliance
    # If some compliance argument is specified we have to load it
    if (
        args.list_compliance
        or args.list_compliance_requirements
        or compliance_framework
    ):
        bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
        # Complete checks metadata with the compliance framework specification
        update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )
        if args.list_compliance:
            print_compliance_frameworks(bulk_compliance_frameworks)
            sys.exit()
        if args.list_compliance_requirements:
            print_compliance_requirements(
                bulk_compliance_frameworks, args.list_compliance_requirements
            )
            sys.exit()

    # Load checks to execute
    checks_to_execute = load_checks_to_execute(
        bulk_checks_metadata,
        bulk_compliance_frameworks,
        checks_file,
        checks,
        services,
        severities,
        compliance_framework,
        categories,
        provider,
    )

    # Exclude checks if -e/--excluded-checks
    if excluded_checks:
        checks_to_execute = exclude_checks_to_run(checks_to_execute, excluded_checks)

    # Exclude services if -s/--excluded-services
    if excluded_services:
        checks_to_execute = exclude_services_to_run(
            checks_to_execute, excluded_services, provider
        )

    # Sort final check list
    checks_to_execute = sorted(checks_to_execute)

    # If -l/--list-checks passed as argument, print checks to execute and quit
    if args.list_checks:
        print_checks(provider, checks_to_execute, bulk_checks_metadata)
        sys.exit()

    # If security hub sending enabled, it is need to create json-asff output
    if args.security_hub:
        if not output_modes:
            output_modes = ["json-asff"]
        else:
            output_modes.append("json-asff")

    # Check output directory, if it is not created -> create it
    if output_directory:
        if not isdir(output_directory):
            if output_modes:
                mkdir(output_directory)

    if provider == "aws":
        # Set global session
        audit_info = aws_provider_set_session(
            args.profile,
            args.role,
            args.session_duration,
            args.external_id,
            args.filter_region,
            args.organizations_role,
        )
    elif provider == "azure":
        audit_info = azure_provider_set_session(subscriptions)

    # Check if custom output filename was input, if not, set the default
    if not output_filename:
        output_filename = (
            f"prowler-output-{audit_info.audited_account}-{output_file_timestamp}"
        )

    # Parse content from Allowlist file and get it, if necessary, from S3
    if args.allowlist_file:
        allowlist_file = parse_allowlist_file(audit_info, args.allowlist_file)
    else:
        allowlist_file = None

    # Setting output options
    audit_output_options = set_output_options(
        args.quiet,
        output_modes,
        output_directory,
        args.security_hub,
        output_filename,
        allowlist_file,
        bulk_checks_metadata,
        args.verbose,
    )

    # Execute checks
    findings = []
    if len(checks_to_execute):
        findings = execute_checks(
            checks_to_execute, provider, audit_info, audit_output_options
        )
    else:
        logger.error(
            "There are no checks to execute. Please, check your input arguments"
        )

    if output_modes:
        for mode in output_modes:
            # Close json file if exists
            if mode == "json" or mode == "json-asff":
                close_json(output_filename, output_directory, mode)
            if mode == "html":
                add_html_footer(output_filename, output_directory)
            # Send output to S3 if needed (-B / -D)
            if args.output_bucket or args.output_bucket_no_assume:
                output_bucket = args.output_bucket
                bucket_session = audit_info.audit_session
                # Check if -D was input
                if args.output_bucket_no_assume:
                    output_bucket = args.output_bucket_no_assume
                    bucket_session = audit_info.original_session
                send_to_s3_bucket(
                    output_filename,
                    output_directory,
                    mode,
                    output_bucket,
                    bucket_session,
                )

    # Resolve previous fails of Security Hub
    if args.security_hub:
        resolve_security_hub_previous_findings(output_directory, audit_info)

    # Display summary table
    display_summary_table(
        findings,
        audit_info,
        audit_output_options,
        provider,
    )

    if compliance_framework and findings:
        # Display compliance table
        display_compliance_table(
            findings,
            bulk_checks_metadata,
            compliance_framework,
            audit_output_options,
        )
