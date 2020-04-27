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

        audit_results.extend(this_smell.execute())


    print(json.dumps(audit_results, default=str))














