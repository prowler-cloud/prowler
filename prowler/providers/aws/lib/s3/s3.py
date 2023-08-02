import sys

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger


def send_to_s3_bucket(
    output_filename, output_directory, output_mode, output_bucket_name, audit_session
):
    try:
        filename = ""
        # Get only last part of the path
        if output_mode == "csv":
            filename = f"{output_filename}{csv_file_suffix}"
        elif output_mode == "json":
            filename = f"{output_filename}{json_file_suffix}"
        elif output_mode == "json-asff":
            filename = f"{output_filename}{json_asff_file_suffix}"
        elif output_mode == "json-ocsf":
            filename = f"{output_filename}{json_ocsf_file_suffix}"
        elif output_mode == "html":
            filename = f"{output_filename}{html_file_suffix}"
        else:  # Compliance output mode
            filename = f"{output_filename}_{output_mode}{csv_file_suffix}"

        logger.info(f"Sending outputs to S3 bucket {output_bucket_name}")
        # File location
        file_name = output_directory + "/" + filename

        # S3 Object name
        bucket_directory = get_s3_object_path(output_directory)
        object_name = bucket_directory + "/" + output_mode + "/" + filename

        s3_client = audit_session.client("s3")
        s3_client.upload_file(file_name, output_bucket_name, object_name)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def get_s3_object_path(output_directory: str) -> str:
    bucket_remote_dir = output_directory
    while "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
        bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

    return bucket_remote_dir
