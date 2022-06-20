#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from lib.banner import print_banner, print_version
from lib.check.check import (
    exclude_checks_to_run,
    exclude_groups_to_run,
    exclude_services_to_run,
    import_check,
    list_groups,
    load_checks_to_execute,
    run_check,
)
from lib.logger import logger, logging_levels
from providers.aws.aws_provider import Input_Data, provider_set_session

if __name__ == "__main__":
    # CLI Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=["aws"], help="Specify Provider")

    # Arguments to set checks to run
    # The following arguments needs to be set exclusivelly
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--checks", nargs="+", help="List of checks")
    group.add_argument("-C", "--checks-file", nargs="?", help="List of checks")
    group.add_argument("-s", "--services", nargs="+", help="List of services")
    group.add_argument("-g", "--groups", nargs="+", help="List of groups")
    group.add_argument("-L", "--list-groups", action="store_true", help="List groups")
    parser.add_argument("-e", "--excluded-checks", nargs="+", help="Checks to exclude")
    parser.add_argument("-E", "--excluded-groups", nargs="+", help="Groups to exclude")
    parser.add_argument(
        "-S", "--excluded-services", nargs="+", help="Services to exclude"
    )

    # Arguments to list checks
    # The following arguments needs to be set exclusivelly
    # list = parser.add_mutually_exclusive_group()
    # list.add_argument("-L", "--list-groups", action="store_true", help="List groups")

    parser.add_argument(
        "-b", "--no-banner", action="store_false", help="Hide Prowler Banner"
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show Prowler version"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="ERROR",
        help="Select Log Level",
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
    # Parse Arguments
    args = parser.parse_args()

    provider = args.provider
    checks = args.checks
    excluded_checks = args.excluded_checks
    excluded_groups = args.excluded_groups
    excluded_services = args.excluded_services
    services = args.services
    groups = args.groups
    checks_file = args.checks_file

    # Set Logger
    logger.setLevel(logging_levels.get(args.log_level))

    # Role assumption input options tests
    if args.session_duration not in range(900, 43200):
        logger.critical("Value for -T option must be between 900 and 43200")
        quit()
    if args.session_duration != 3600 or args.external_id:
        if not args.role:
            logger.critical("To use -I/-T options -R option is needed")
            quit()

    if args.version:
        print_version()
        quit()

    if args.no_banner:
        print_banner()

    if args.list_groups:
        list_groups(provider)
        quit()

    # Setting session
    session_input = Input_Data(
        profile=args.profile,
        role_arn=args.role,
        session_duration=args.session_duration,
        external_id=args.external_id,
        regions=args.filter_region,
    )

    provider_set_session(session_input)

    # Load checks to execute
    logger.debug("Loading checks")
    checks_to_execute = load_checks_to_execute(
        checks_file, checks, services, groups, provider
    )
    # Exclude checks if -e/--excluded-checks
    if excluded_checks:
        checks_to_execute = exclude_checks_to_run(checks_to_execute, excluded_checks)

    # Exclude groups if -g/--excluded-groups
    if excluded_groups:
        checks_to_execute = exclude_groups_to_run(
            checks_to_execute, excluded_groups, provider
        )

    # Exclude services if -s/--excluded-services
    if excluded_services:
        checks_to_execute = exclude_services_to_run(
            checks_to_execute, excluded_services, provider
        )

    # Execute checks
    if len(checks_to_execute):
        for check_name in checks_to_execute:
            # Recover service from check name
            service = check_name.split("_")[0]
            try:
                # Import check module
                check_module_path = (
                    f"providers.{provider}.services.{service}.{check_name}.{check_name}"
                )
                lib = import_check(check_module_path)
                # Recover functions from check
                check_to_execute = getattr(lib, check_name)
                c = check_to_execute()
                # Run check
                run_check(c)

            # If check does not exists in the provider or is from another provider
            except ModuleNotFoundError:
                logger.error(
                    f"Check '{check_name}' was not found for the {provider.upper()} provider"
                )
    else:
        logger.error(
            "There are no checks to execute. Please, check your input arguments"
        )
