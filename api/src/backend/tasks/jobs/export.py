import os
import zipfile

import boto3
import config.django.base as base
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from celery.utils.log import get_task_logger
from django.conf import settings

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_ocsf_file_suffix,
    output_file_timestamp,
)
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF

logger = get_task_logger(__name__)


# Predefined mapping for output formats and their configurations
OUTPUT_FORMATS_MAPPING = {
    "csv": {
        "class": CSV,
        "suffix": csv_file_suffix,
        "kwargs": {},
    },
    "json-ocsf": {"class": OCSF, "suffix": json_ocsf_file_suffix, "kwargs": {}},
    "html": {"class": HTML, "suffix": html_file_suffix, "kwargs": {"stats": {}}},
}


def _compress_output_files(output_directory: str) -> str:
    """
    Compress output files from all configured output formats into a ZIP archive.
    Args:
        output_directory (str): The directory where the output files are located.
            The function looks up all known suffixes in OUTPUT_FORMATS_MAPPING
            and compresses those files into a single ZIP.
    Returns:
        str: The full path to the newly created ZIP archive.
    """
    zip_path = f"{output_directory}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for suffix in [config["suffix"] for config in OUTPUT_FORMATS_MAPPING.values()]:
            zipf.write(
                f"{output_directory}{suffix}",
                f"output/{output_directory.split('/')[-1]}{suffix}",
            )

    return zip_path


def get_s3_client():
    """
    Create and return a boto3 S3 client using AWS credentials from environment variables.

    This function attempts to initialize an S3 client by reading the AWS access key, secret key,
    session token, and region from environment variables. It then validates the client by listing
    available S3 buckets. If an error occurs during this process (for example, due to missing or
    invalid credentials), it falls back to creating an S3 client without explicitly provided credentials,
    which may rely on other configuration sources (e.g., IAM roles).

    Returns:
        boto3.client: A configured S3 client instance.

    Raises:
        ClientError, NoCredentialsError, or ParamValidationError if both attempts to create a client fail.
    """
    s3_client = None
    try:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=settings.DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN,
            region_name=settings.DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION,
        )
        s3_client.list_buckets()
    except (ClientError, NoCredentialsError, ParamValidationError, ValueError):
        s3_client = boto3.client("s3")
        s3_client.list_buckets()

    return s3_client


def _upload_to_s3(tenant_id: str, zip_path: str, scan_id: str) -> str:
    """
    Upload the specified ZIP file to an S3 bucket.
    If the S3 bucket environment variables are not configured,
    the function returns None without performing an upload.
    Args:
        tenant_id (str): The tenant identifier, used as part of the S3 key prefix.
        zip_path (str): The local file system path to the ZIP file to be uploaded.
        scan_id (str): The scan identifier, used as part of the S3 key prefix.
    Returns:
        str: The S3 URI of the uploaded file (e.g., "s3://<bucket>/<key>") if successful.
        None: If the required environment variables for the S3 bucket are not set.
    Raises:
        botocore.exceptions.ClientError: If the upload attempt to S3 fails for any reason.
    """
    if not base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET:
        return

    try:
        s3 = get_s3_client()
        s3_key = f"{tenant_id}/{scan_id}/{os.path.basename(zip_path)}"
        s3.upload_file(
            Filename=zip_path,
            Bucket=base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET,
            Key=s3_key,
        )
        return f"s3://{base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET}/{s3_key}"
    except (ClientError, NoCredentialsError, ParamValidationError, ValueError) as e:
        logger.error(f"S3 upload failed: {str(e)}")


def _generate_output_directory(
    output_directory, prowler_provider: object, tenant_id: str, scan_id: str
) -> str:
    """
    Generate a file system path for the output directory of a prowler scan.

    This function constructs the output directory path by combining a base
    temporary output directory, the tenant ID, the scan ID, and details about
    the prowler provider along with a timestamp. The resulting path is used to
    store the output files of a prowler scan.

    Note:
        This function depends on one external variable:
          - `output_file_timestamp`: A timestamp (as a string) used to uniquely identify the output.

    Args:
        output_directory (str): The base output directory.
        prowler_provider (object): An identifier or descriptor for the prowler provider.
                                   Typically, this is a string indicating the provider (e.g., "aws").
        tenant_id (str): The unique identifier for the tenant.
        scan_id (str): The unique identifier for the scan.

    Returns:
        str: The constructed file system path for the prowler scan output directory.

    Example:
        >>> _generate_output_directory("/tmp", "aws", "tenant-1234", "scan-5678")
        '/tmp/tenant-1234/aws/scan-5678/prowler-output-2023-02-15T12:34:56'
    """
    path = (
        f"{output_directory}/{tenant_id}/{scan_id}/prowler-output-"
        f"{prowler_provider}-{output_file_timestamp}"
    )
    os.makedirs("/".join(path.split("/")[:-1]), exist_ok=True)

    return path
