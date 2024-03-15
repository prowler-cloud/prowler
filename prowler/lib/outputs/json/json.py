import os
import sys

from prowler.config.config import (
    json_asff_file_suffix,
    json_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file


def close_json(output_filename, output_directory, mode):
    """close_json closes the output JSON file replacing the last comma with ]"""
    try:
        suffix = json_file_suffix
        if mode == "json-asff":
            suffix = json_asff_file_suffix
        elif mode == "json-ocsf":
            suffix = json_ocsf_file_suffix
        filename = f"{output_directory}/{output_filename}{suffix}"
        # Close JSON file if exists
        if os.path.isfile(filename):
            file_descriptor = open_file(
                filename,
                "a",
            )
            # Replace last comma for square bracket if not empty
            if file_descriptor.tell() > 0:
                if file_descriptor.tell() != 1:
                    file_descriptor.seek(file_descriptor.tell() - 1, os.SEEK_SET)
                file_descriptor.truncate()
                file_descriptor.write("]")
            file_descriptor.close()
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)
