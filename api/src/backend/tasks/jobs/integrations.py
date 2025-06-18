import os

from celery.utils.log import get_task_logger

from api.db_utils import rls_transaction
from api.models import Integration
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.common.models import Connection

logger = get_task_logger(__name__)


def get_s3_client_from_integration(
    integration: Integration,
) -> tuple[bool, S3 | Connection]:
    """
    Create and return a boto3 S3 client using AWS credentials from an integration.

    Args:
        integration (Integration): The integration to get the S3 client from.

    Returns:
        tuple[bool, S3 | Connection]: A tuple containing a boolean indicating if the connection was successful and the S3 client or connection object.
    """
    session = AwsProvider(**integration.credentials).session.current_session
    s3 = S3(
        session=session,
        bucket_name=integration.configuration["bucket_name"],
        output_directory=integration.configuration["output_directory"],
    )
    connection = s3.test_connection(
        session=session,
        bucket_name=integration.configuration["bucket_name"],
    )

    if connection.is_connected:
        return True, s3

    return False, connection


def upload_s3_integration(tenant_id: str, provider_id: str, file_path: str):
    """
    Upload the specified output files to an S3 bucket from an integration.
    If the S3 bucket environment variables are not configured,
    the function returns None without performing an upload.

    Args:
        tenant_id (str): The tenant identifier, used as part of the S3 key prefix.
        provider_id (str): The provider identifier, used as part of the S3 key prefix.
        file_path (str): The local file system path to the output files to be uploaded.

    Returns:
        str: The S3 URI of the uploaded file (e.g., "s3://<bucket>/<key>") if successful.
        None: If the required environment variables for the S3 bucket are not set.

    Raises:
        botocore.exceptions.ClientError: If the upload attempt to S3 fails for any reason.
    """
    with rls_transaction(tenant_id):
        integrations = Integration.objects.filter(
            integrationproviderrelationship__provider_id=provider_id,
            integration_type=Integration.IntegrationChoices.S3,
        )

    if not integrations:
        logger.error(f"No S3 integrations found for provider {provider_id}")
        return

    for integration in integrations:
        integration_configuration = integration.configuration
        integration_bucket_name = integration_configuration.get("bucket_name")
        integration_output_directory = integration_configuration.get("output_directory")

        connected, s3 = get_s3_client_from_integration(integration)
        if connected:
            try:
                for filename in os.listdir(file_path):
                    local_path = os.path.join(file_path, filename)
                    if not os.path.isfile(local_path):
                        continue
                    file_key = f"{integration_output_directory}/{filename}"
                    s3.upload_file(
                        filename=local_path,
                        bucket_name=integration_bucket_name,
                        key=file_key,
                    )
            except Exception as e:
                logger.error(
                    f"S3 output upload failed for integration {integration.id}: {e}"
                )

            try:
                compliance_dir = os.path.join(file_path, "compliance")
                for filename in os.listdir(compliance_dir):
                    local_path = os.path.join(compliance_dir, filename)
                    if not os.path.isfile(local_path):
                        continue
                    file_key = f"{integration_output_directory}/compliance/{filename}"
                    s3.upload_file(
                        filename=local_path,
                        bucket_name=integration_bucket_name,
                        key=file_key,
                    )
            except Exception as e:
                logger.error(
                    f"S3 compliance upload failed for integration {integration.id}: {e}"
                )
        else:
            logger.error(
                f"S3 upload failed for integration {integration.id}: {s3.error}"
            )
