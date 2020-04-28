#!/usr/bin/env python3

"""
All Python Version of This. Goal is to have faster
Checks.
"""

import argparse
import logging
import os
import pathlib
import json
import csv

import boto3

import sniffy

if __name__ == "__main__":

    """
    Let's grab my runtime options
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--profile", help="AWS Profile to Use", required=True)
    parser.add_argument("-v", "--verbose", action="append_const", help="Verbosity Controls",
                        const=1, default=[])
    parser.add_argument("-d", "--checkd", help="Directory Containing Checks", default="./etc/prowler/check.d")
    parser.add_argument("-c", "--check", help="Run these Checks", action="append", default=[])
    parser.add_argument("--cache_dir", help="Directory to Cache Checks", default="/tmp/hk_cache/")
    parser.add_argument("--csv", help="Save a to this CSV", default=False)
    parser.add_argument("--json", help="Print a JSON of the data", default=False)

    args = parser.parse_args()

    VERBOSE = len(args.verbose)

    if VERBOSE == 0:
        logging.basicConfig(level=logging.ERROR)
    elif VERBOSE == 1:
        logging.basicConfig(level=logging.WARNING)
    elif VERBOSE == 2:
        logging.basicConfig(level=logging.INFO)
    elif VERBOSE > 2:
        logging.basicConfig(level=logging.DEBUG)

    logger = logging.getLogger("hunterkitty.py")

    # Load All Files in ./checks.d/
    if os.path.isdir(pathlib.Path(args.checkd)) is False:
        raise NotADirectoryError("{} Not a Directory".format(args.checkd))

    aws_session = boto3.session.Session(profile_name=args.profile)
    account_id = aws_session.client('sts').get_caller_identity()['Account']

    available_configs = list()
    for dirpath, dnames, fnames in os.walk(args.checkd):
        for possible_config in fnames:
            if possible_config.endswith(".json") or possible_config.endswith(".yaml"):
                this_config = sniffy.Smell(filepath=os.path.join(dirpath, possible_config),
                                           aws_session=aws_session,
                                           account_id=account_id,
                                           cache_dir=args.cache_dir)

                if this_config.validate() is True:
                    if len(args.check) > 0:
                        if this_config.id in args.check:
                            logger.debug("Config {} Added based on CLI Confiigs.".format(this_config.id))
                            available_configs.append(this_config)
                        else:
                            logger.info("Config {} Ignored based on CLI Configs.".format(this_config.id))
                    # TODO Add Group Logic Here
                    else:
                        logger.debug("Adding Config {}".format(this_config.id))
                        available_configs.append(this_config)

    audit_results = list()

    for this_smell in available_configs:

        # Add Only Fail Logic Here
        audit_results.extend(this_smell.execute())


    if args.csv is not False:

        field_names = ["platform", "account_id", "region", "subject", "pfi", "pfi_reason", "check_id", "check_title"]

        logger.info("Writing CSV Result to : {}".format(args.csv))

        with open(args.csv, "w") as csv_out_file:
            writer = csv.DictWriter(csv_out_file, field_names)

            writer.writeheader()

            for row in audit_results:
                writer.writerow({key: value for key, value in row.items() if key in field_names})

    if args.json is True:

        logger.info("Writing JSON Results to : {}".format(args.json))

        with open(args.json, "w") as json_out_file:
            json.dump(audit_results, json_out_file, default=str)

