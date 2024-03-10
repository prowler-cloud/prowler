#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from colorama import Fore, Style

from prowler.config.config import get_available_compliance_frameworks
from prowler.lib.banner import print_banner
from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    exclude_checks_to_run,
    exclude_services_to_run,
    execute_checks,
    list_categories,
    list_checks_json,
    list_services,
    parse_checks_from_folder,
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_services,
    remove_custom_checks_module,
)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.custom_checks_metadata import (
    parse_custom_checks_metadata_file,
    update_checks_metadata,
)
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import logger, set_logging_config
from prowler.lib.outputs.compliance.compliance import display_compliance_table
from prowler.lib.outputs.json.json import close_json
from prowler.lib.outputs.outputs import extract_findings_statistics
from prowler.lib.outputs.summary_table import display_summary_table
from prowler.providers.aws.lib.s3.s3 import send_to_s3_bucket
from prowler.providers.aws.lib.security_hub.security_hub import (
    batch_send_to_security_hub,
    prepare_security_hub_findings,
    resolve_security_hub_previous_findings,
    verify_security_hub_integration_enabled_per_region,
)
from prowler.providers.common.common import set_global_provider_object


def prowler():
    # Parse Arguments
    parser = ProwlerArgumentParser()
    args = parser.parse()

    # Save Arguments
    provider = args.provider
    checks = args.checks
    excluded_checks = args.excluded_checks
    excluded_services = args.excluded_services
    services = args.services
    categories = args.categories
    checks_file = args.checks_file
    checks_folder = args.checks_folder
    severities = args.severity
    compliance_framework = args.compliance
    custom_checks_metadata_file = args.custom_checks_metadata_file

    if not args.no_banner:
        print_banner(args)

    # We treat the compliance framework as another output format
    if compliance_framework:
        args.output_modes.extend(compliance_framework)
    # If no input compliance framework, set all
    else:
        args.output_modes.extend(get_available_compliance_frameworks(provider))

    # Set Logger configuration
    set_logging_config(args.log_level, args.log_file, args.only_logs)

    if args.list_services:
        print_services(list_services(provider))
        sys.exit()

    # Load checks metadata
    logger.debug("Loading checks metadata from .metadata.json files")
    bulk_checks_metadata = bulk_load_checks_metadata(provider)

    if args.list_categories:
        print_categories(list_categories(bulk_checks_metadata))
        sys.exit()

    bulk_compliance_frameworks = {}
    # Load compliance frameworks
    logger.debug("Loading compliance frameworks from .json files")

    bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    # Complete checks metadata with the compliance framework specification
    bulk_checks_metadata = update_checks_metadata_with_compliance(
        bulk_compliance_frameworks, bulk_checks_metadata
    )
    # Update checks metadata if the --custom-checks-metadata-file is present
    custom_checks_metadata = None
    if custom_checks_metadata_file:
        custom_checks_metadata = parse_custom_checks_metadata_file(
            provider, custom_checks_metadata_file
        )
        bulk_checks_metadata = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
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

    # if --list-checks-json, dump a json file and exit
    if args.list_checks_json:
        print(list_checks_json(provider, sorted(checks_to_execute)))
        sys.exit()

    # If -l/--list-checks passed as argument, print checks to execute and quit
    if args.list_checks:
        print_checks(provider, sorted(checks_to_execute), bulk_checks_metadata)
        sys.exit()

    # Provider to scan
    global_provider = set_global_provider_object(args)

    # Print Provider Credentials
    if not args.only_logs:
        global_provider.print_credentials()

    # Import custom checks from folder
    if checks_folder:
        parse_checks_from_folder(global_provider, checks_folder)

    # Exclude checks if -e/--excluded-checks
    if excluded_checks:
        checks_to_execute = exclude_checks_to_run(checks_to_execute, excluded_checks)

    # Exclude services if --excluded-services
    if excluded_services:
        checks_to_execute = exclude_services_to_run(
            checks_to_execute, excluded_services, provider
        )

    # Once the audit_info is set and we have the eventual checks based on the resource identifier,
    # it is time to check what Prowler's checks are going to be executed
    # TODO: the following if is done within the function
    # if global_provider.audit_resources:
    checks_from_resources = global_provider.get_checks_to_execute_by_audit_resources()
    if checks_from_resources:
        checks_to_execute = checks_to_execute.intersection(checks_from_resources)

    # Sort final check list
    checks_to_execute = sorted(checks_to_execute)

    # Setup Mute List
    # TODO: this should be available for all the providers
    # Move the argument to the Prowler level to be available for all
    if hasattr(args, "mutelist_file"):
        global_provider.mutelist = args.mutelist_file

    # Setup Output Options
    global_provider.output_options = (args, bulk_checks_metadata)

    # TODO: adapt the quick inventory for the new AWS provider
    # Run the quick inventory for the provider if available
    # if hasattr(args, "quick_inventory") and args.quick_inventory:
    #     run_provider_quick_inventory(provider, global_provider.identity, args)
    #     sys.exit()

    # Execute checks
    findings = []

    if len(checks_to_execute):
        findings = execute_checks(
            checks_to_execute,
            global_provider,
            custom_checks_metadata,
        )
    else:
        logger.error(
            "There are no checks to execute. Please, check your input arguments"
        )

    # Extract findings stats
    stats = extract_findings_statistics(findings)

    # TODO: adapt the slack integration for the new AWS provider
    # if args.slack:
    #     if "SLACK_API_TOKEN" in os.environ and "SLACK_CHANNEL_ID" in os.environ:
    #         _ = send_slack_message(
    #             os.environ["SLACK_API_TOKEN"],
    #             os.environ["SLACK_CHANNEL_ID"],
    #             stats,
    #             provider,
    #             audit_info,
    #         )
    #     else:
    #         logger.critical(
    #             "Slack integration needs SLACK_API_TOKEN and SLACK_CHANNEL_ID environment variables (see more in https://docs.prowler.cloud/en/latest/tutorials/integrations/#slack)."
    #         )
    #         sys.exit(1)

    if args.output_modes:
        for mode in args.output_modes:
            # Close json file if exists
            if "json" in mode:
                close_json(
                    global_provider.output_options.output_filename,
                    args.output_directory,
                    mode,
                )

            # Send output to S3 if needed (-B / -D)
            if provider == "aws" and (
                args.output_bucket or args.output_bucket_no_assume
            ):
                output_bucket = args.output_bucket
                bucket_session = global_provider.session.current_session
                # Check if -D was input
                if args.output_bucket_no_assume:
                    output_bucket = args.output_bucket_no_assume
                    bucket_session = global_provider.session.original_session
                send_to_s3_bucket(
                    global_provider.output_options.output_filename,
                    args.output_directory,
                    mode,
                    output_bucket,
                    bucket_session,
                )

    # AWS Security Hub Integration
    if provider == "aws" and args.security_hub:
        print(
            f"{Style.BRIGHT}\nSending findings to AWS Security Hub, please wait...{Style.RESET_ALL}"
        )
        # Verify where AWS Security Hub is enabled
        aws_security_enabled_regions = []
        security_hub_regions = (
            global_provider.get_available_aws_service_regions("securityhub")
            if not global_provider.identity.audited_regions
            else global_provider.identity.audited_regions
        )
        for region in security_hub_regions:
            # Save the regions where AWS Security Hub is enabled
            if verify_security_hub_integration_enabled_per_region(
                global_provider.identity.partition,
                region,
                global_provider.session.current_session,
                global_provider.identity.account,
            ):
                aws_security_enabled_regions.append(region)

        # Prepare the findings to be sent to Security Hub
        security_hub_findings_per_region = prepare_security_hub_findings(
            findings,
            provider,
            global_provider.output_options,
            aws_security_enabled_regions,
        )

        # Send the findings to Security Hub
        findings_sent_to_security_hub = batch_send_to_security_hub(
            security_hub_findings_per_region, provider.session.current_session
        )

        print(
            f"{Style.BRIGHT}{Fore.GREEN}\n{findings_sent_to_security_hub} findings sent to AWS Security Hub!{Style.RESET_ALL}"
        )

        # Resolve previous fails of Security Hub
        if not args.skip_sh_update:
            print(
                f"{Style.BRIGHT}\nArchiving previous findings in AWS Security Hub, please wait...{Style.RESET_ALL}"
            )
            findings_archived_in_security_hub = resolve_security_hub_previous_findings(
                security_hub_findings_per_region,
                provider,
            )
            print(
                f"{Style.BRIGHT}{Fore.GREEN}\n{findings_archived_in_security_hub} findings archived in AWS Security Hub!{Style.RESET_ALL}"
            )

    # Display summary table
    if not args.only_logs:
        display_summary_table(
            findings,
            global_provider,
            global_provider.output_options,
        )

        if findings:
            compliance_overview = False
            if not compliance_framework:
                compliance_overview = True
                compliance_framework = get_available_compliance_frameworks(provider)
            for compliance in sorted(compliance_framework):
                # Display compliance table
                display_compliance_table(
                    findings,
                    bulk_checks_metadata,
                    compliance,
                    global_provider.output_options.output_filename,
                    global_provider.output_options.output_directory,
                    compliance_overview,
                )
            if compliance_overview:
                print(
                    f"\nDetailed compliance results are in {Fore.YELLOW}{global_provider.output_options.output_directory}/compliance/{Style.RESET_ALL}\n"
                )

    # If custom checks were passed, remove the modules
    if checks_folder:
        remove_custom_checks_module(checks_folder, provider)

    # If there are failed findings exit code 3, except if -z is input
    if not args.ignore_exit_code_3 and stats["total_fail"] > 0:
        sys.exit(3)


if __name__ == "__main__":
    prowler()
