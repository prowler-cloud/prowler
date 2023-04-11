#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from prowler.lib.banner import print_banner
from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    exclude_checks_to_run,
    exclude_services_to_run,
    execute_checks,
    list_categories,
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
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import logger, set_logging_config
from prowler.lib.outputs.compliance import display_compliance_table
from prowler.lib.outputs.html import add_html_footer, fill_html_overview_statistics
from prowler.lib.outputs.json import close_json
from prowler.lib.outputs.outputs import extract_findings_statistics, send_to_s3_bucket
from prowler.lib.outputs.summary_table import display_summary_table
from prowler.providers.aws.lib.security_hub.security_hub import (
    resolve_security_hub_previous_findings,
)
from prowler.providers.common.allowlist import set_provider_allowlist
from prowler.providers.common.audit_info import (
    set_provider_audit_info,
    set_provider_execution_parameters,
)
from prowler.providers.common.outputs import set_provider_output_options
from prowler.providers.common.quick_inventory import run_provider_quick_inventory


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

    # Import custom checks from folder
    if checks_folder:
        parse_checks_from_folder(checks_folder, provider)

    # We treat the compliance framework as another output format
    if compliance_framework:
        args.output_modes.extend(compliance_framework)

    # Set Logger configuration
    set_logging_config(args.log_level, args.log_file, args.only_logs)

    if not args.no_banner:
        print_banner(args)

    if args.list_services:
        print_services(list_services(provider))
        sys.exit()

    # Load checks metadata
    logger.debug("Loading checks metadata from .metadata.json files")
    bulk_checks_metadata = bulk_load_checks_metadata(provider)

    if args.list_categories:
        print_categories(list_categories(provider, bulk_checks_metadata))
        sys.exit()

    bulk_compliance_frameworks = {}
    # Load compliance frameworks
    logger.debug("Loading compliance frameworks from .json files")

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

    # Exclude services if --excluded-services
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

    # Set the audit info based on the selected provider
    audit_info = set_provider_audit_info(provider, args.__dict__)

    # Once the audit_info is set and we have the eventual checks based on the resource identifier,
    # it is time to check what Prowler's checks are going to be executed
    if audit_info.audit_resources:
        checks_to_execute = set_provider_execution_parameters(provider, audit_info)

    # Parse Allowlist
    allowlist_file = set_provider_allowlist(provider, audit_info, args)

    # Set output options based on the selected provider
    audit_output_options = set_provider_output_options(
        provider, args, audit_info, allowlist_file, bulk_checks_metadata
    )

    # Run the quick inventory for the provider if available
    if hasattr(args, "quick_inventory") and args.quick_inventory:
        run_provider_quick_inventory(provider, audit_info, args.output_directory)
        sys.exit()

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

    # Extract findings stats
    stats = extract_findings_statistics(findings)

    if args.output_modes:
        for mode in args.output_modes:
            # Close json file if exists
            if mode == "json" or mode == "json-asff":
                close_json(
                    audit_output_options.output_filename, args.output_directory, mode
                )
            if mode == "html":
                add_html_footer(
                    audit_output_options.output_filename, args.output_directory
                )
                fill_html_overview_statistics(
                    stats, audit_output_options.output_filename, args.output_directory
                )
            # Send output to S3 if needed (-B / -D)
            if provider == "aws" and (
                args.output_bucket or args.output_bucket_no_assume
            ):
                output_bucket = args.output_bucket
                bucket_session = audit_info.audit_session
                # Check if -D was input
                if args.output_bucket_no_assume:
                    output_bucket = args.output_bucket_no_assume
                    bucket_session = audit_info.original_session
                send_to_s3_bucket(
                    audit_output_options.output_filename,
                    args.output_directory,
                    mode,
                    output_bucket,
                    bucket_session,
                )

    # Resolve previous fails of Security Hub
    if provider == "aws" and args.security_hub and not args.skip_sh_update:
        resolve_security_hub_previous_findings(args.output_directory, audit_info)

    # Display summary table
    if not args.only_logs:
        display_summary_table(
            findings,
            audit_info,
            audit_output_options,
            provider,
        )

        if compliance_framework and findings:
            for compliance in compliance_framework:
                # Display compliance table
                display_compliance_table(
                    findings,
                    bulk_checks_metadata,
                    compliance,
                    audit_output_options.output_filename,
                    audit_output_options.output_directory,
                )

    # If custom checks were passed, remove the modules
    if checks_folder:
        remove_custom_checks_module(checks_folder, provider)

    # If there are failed findings exit code 3, except if -z is input
    if not args.ignore_exit_code_3 and stats["total_fail"] > 0:
        sys.exit(3)


if __name__ == "__main__":
    prowler()
