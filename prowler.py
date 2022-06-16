#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import importlib
import pkgutil

from lib.banner import print_banner, print_version
from lib.logger import logger, logging_levels
from lib.outputs import report
from providers.aws.aws_provider import Input_Data, provider_set_session


def run_check(check):
    print(f"\nCheck Name: {check.CheckName}")
    findings = check.execute()
    report(findings)


def import_check(check_path):
    lib = importlib.import_module(f"{check_path}")
    return lib


def recover_modules_from_provider(provider):
    modules = []
    for module_name in pkgutil.walk_packages(
        importlib.import_module(f"providers.{provider}.services").__path__,
        importlib.import_module(f"providers.{provider}.services").__name__ + ".",
    ):
        if module_name.name.count(".") == 5:
            modules.append(module_name.name)
    return modules


if __name__ == "__main__":
    # start_time = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", help="Specify Provider: AWS")
    parser.add_argument(
        "-c", "--checks", nargs="+", help="Comma separated list of checks"
    )
    parser.add_argument(
        "-b", "--no-banner", action="store_false", help="Hide Prowler Banner"
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show Prowler version"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="CRITICAL",
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

    # Role assumption input options tests
    if args.role or args.account:
        if not args.account:
            logger.error(
                "It is needed to input an Account Id to assume the role (-A option) when an IAM Role is provided with -R"
            )
            quit()
        elif not args.role:
            logger.error(
                "It is needed to input an IAM Role name (-R option) when an Account Id is provided with -A"
            )
            quit()
    if args.session_duration not in range(900, 43200):
        logger.error("Value for -T option must be between 900 and 43200")
        quit()
    if args.session_duration or args.external_id:
        if not args.account or not args.role:
            logger.error("To use -I/-T options both -A and -R options are needed")
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

    # libreria para generar la lista de checks
    if checks:
        for check in checks:
            # Recover service from check name
            service = check.split("_")[0]
            # Import check module
            lib = import_check(
                f"providers.{provider}.services.{service}.{check}.{check}"
            )
            # Recover functions from check
            check_to_execute = getattr(lib, check)
            c = check_to_execute()
            # Run check
            run_check(c)

    else:
        # Get all check modules to run
        modules = recover_modules_from_provider(provider)
        # Run checks
        for check_module in modules:
            print(check_module)
            # Import check module
            lib = import_check(check_module)
            # Recover module from check name
            check_name = check_module.split(".")[5]
            # Recover functions from check
            check_to_execute = getattr(lib, check_name)
            c = check_to_execute()
            # Run check
            run_check(c)
