import importlib
import sys
from shutil import rmtree

from prowler.config.config import default_output_directory
from prowler.lib.logger import logger


def clean_provider_local_output_directories(args):
    """
    clean_provider_local_output_directories deletes the output files generated locally in custom directories when the output is sent to a remote storage provider
    """
    try:
        # import provider cleaning function
        provider_clean_function = f"clean_{args.provider}_local_output_directories"
        getattr(importlib.import_module(__name__), provider_clean_function)(args)
    except AttributeError as attribute_exception:
        logger.info(
            f"Cleaning local output directories not initialized for provider {args.provider}: {attribute_exception}"
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


def clean_aws_local_output_directories(args):
    """clean_aws_local_output_directories deletes the output files generated locally in custom directories when output is sent to a remote storage provider for AWS"""
    if args.output_bucket or args.output_bucket_no_assume:
        if args.output_directory != default_output_directory:
            rmtree(args.output_directory)
