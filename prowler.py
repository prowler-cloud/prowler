#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import importlib
import pkgutil

from lib.banner import print_banner, print_version
from lib.logger import logger, logging_levels
from lib.outputs import report
from providers.aws.aws_provider import provider_set_profile


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
        "-c", "--checks", nargs="*", help="Comma separated list of checks"
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
        const="default",
        help="AWS profile to launch prowler with",
    )
    # Parse Arguments
    args = parser.parse_args()
    provider = args.provider
    checks = args.checks
    profile = args.profile

    if args.version:
        print_version()
        quit()

    if args.no_banner:
        print_banner()

    # Set Logger
    logger.setLevel(logging_levels.get(args.log_level))

    logger.info("Test info")
    logger.debug("Test debug")

    # Setting profile
    provider_set_profile(profile)

    # libreria para generar la lista de checks
    checks_to_execute = set()

    # LOADER
    # Handle if there are checks passed using -c/--checks
    if checks:
        for check_name in checks:
            checks_to_execute.add(check_name)

    # If there are no checks passed as argument
    else:
        # Get all check modules to run with the specifie provider
        modules = recover_modules_from_provider(provider)
        for check_module in modules:
            # Recover check name from import path (last part)
            check_name = check_module.split(".")[5]
            checks_to_execute.add(check_name)

    # Execute checks
    for check_name in checks_to_execute:
        # Recover service from check name
        service = check_name.split("_")[0]
        # Import check module
        # Validate check in service and provider
        lib = import_check(
            f"providers.{provider}.services.{service}.{check_name}.{check_name}"
        )
        # Recover functions from check
        check_to_execute = getattr(lib, check_name)
        c = check_to_execute()
        # Run check
        run_check(c)
