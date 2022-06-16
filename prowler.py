#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from lib.banner import print_banner, print_version
from lib.check.check import (
    exclude_checks_to_run,
    import_check,
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

    parser.add_argument("-e", "--excluded-checks", nargs="+", help="Checks to exclude")
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
        help="Role name to be assumed in account passed with -A",
    )
    parser.add_argument(
        "-A",
        "--account",
        nargs="?",
        default=None,
        help="AWS account id where the role passed by -R is assumed",
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
    # Parse Arguments
    args = parser.parse_args()

    provider = args.provider
    checks = args.checks
    excluded_checks = args.excluded_checks
    services = args.services
    groups = args.groups
    checks_file = args.checks_file
    
    # Role assumption input options tests
    if args.role or args.account:
        if not args.account:
            logger.critical(
                "It is needed to input an Account Id to assume the role (-A option) when an IAM Role is provided with -R"
            )
            quit()
        elif not args.role:
            logger.critical(
                "It is needed to input an IAM Role name (-R option) when an Account Id is provided with -A"
            )
            quit()
    if args.session_duration not in range(900, 43200):
        logger.critical("Value for -T option must be between 900 and 43200")
        quit()
    if args.session_duration != 3600 or args.external_id:
        if not args.account or not args.role:
            logger.critical("To use -I/-T options both -A and -R options are needed")
            quit()

    session_input = Input_Data(
        profile=args.profile,
        role_name=args.role,
        account_to_assume=args.account,
        session_duration=args.session_duration,
        external_id=args.external_id,
    )
    
    # Set Logger
    logger.setLevel(logging_levels.get(args.log_level))

    if args.version:
        print_version()
        quit()

    if args.no_banner:
        print_banner()

    # Setting session
    provider_set_session(session_input)

    # Load checks to execute
    logger.debug("Loading checks")
    checks_to_execute = load_checks_to_execute(
        checks_file, checks, services, groups, provider
    )
    # Exclude checks if -e
    if excluded_checks:
        checks_to_execute = exclude_checks_to_run(checks_to_execute, excluded_checks)

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
