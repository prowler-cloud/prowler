from prowler.config.config import (
    available_output_formats,
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger


def send_to_s3_bucket(
    output_filename, output_directory, output_mode, output_bucket_name, audit_session
):
    try:
        # S3 Object name
        bucket_directory = get_s3_object_path(output_directory)
        filename = ""
        # Get only last part of the path
        if output_mode in available_output_formats:
            if output_mode == "csv":
                filename = f"{output_filename}{csv_file_suffix}"
            elif output_mode == "json-asff":
                filename = f"{output_filename}{json_asff_file_suffix}"
            elif output_mode == "json-ocsf":
                filename = f"{output_filename}{json_ocsf_file_suffix}"
            elif output_mode == "html":
                filename = f"{output_filename}{html_file_suffix}"
            file_name = output_directory + "/" + filename
            object_name = bucket_directory + "/" + output_mode + "/" + filename
        else:  # Compliance output mode
            filename = f"{output_filename}_{output_mode}{csv_file_suffix}"
            file_name = output_directory + "/compliance/" + filename
            object_name = bucket_directory + "/compliance/" + filename

        logger.info(f"Sending output file {filename} to S3 bucket {output_bucket_name}")

        s3_client = audit_session.client("s3")
        s3_client.upload_file(file_name, output_bucket_name, object_name)

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )


def get_s3_object_path(output_directory: str) -> str:
    bucket_remote_dir = output_directory
    if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
        bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

    return bucket_remote_dir
