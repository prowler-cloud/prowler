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
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_services,
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
from prowler.providers.aws.lib.allowlist.allowlist import parse_allowlist_file
from prowler.providers.aws.lib.quick_inventory.quick_inventory import quick_inventory
from prowler.providers.aws.lib.security_hub.security_hub import (
    resolve_security_hub_previous_findings,
)
from prowler.providers.common.audit_info import set_provider_audit_info
from prowler.providers.common.outputs import set_provider_output_options


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
    severities = args.severity
    compliance_framework = args.compliance

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

    # Set the audit info based on the selected provider
    audit_info = set_provider_audit_info(provider, args.__dict__)

    # Parse content from Allowlist file and get it, if necessary, from S3
    if provider == "aws" and args.allowlist_file:
        allowlist_file = parse_allowlist_file(audit_info, args.allowlist_file)
    else:
        allowlist_file = None

    # Setting output options based on the selected provider
    audit_output_options = set_provider_output_options(
        provider, args, audit_info, allowlist_file, bulk_checks_metadata
    )

    # Quick Inventory for AWS
    if provider == "aws" and args.quick_inventory:
        quick_inventory(audit_info, args.output_directory)
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
    if provider == "aws" and args.security_hub:
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
            # Display compliance table
            display_compliance_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                audit_output_options.output_filename,
                audit_output_options.output_directory,
            )


if __name__ == "__main__":
    prowler()
