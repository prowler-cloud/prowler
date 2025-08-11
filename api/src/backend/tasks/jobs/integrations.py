import os
from glob import glob

from celery.utils.log import get_task_logger

from api.db_utils import rls_transaction
from api.models import Integration
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF
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
    s3 = S3(
        **integration.credentials,
        bucket_name=integration.configuration["bucket_name"],
        output_directory=integration.configuration["output_directory"],
    )

    connection = s3.test_connection(
        **integration.credentials,
        bucket_name=integration.configuration["bucket_name"],
    )

    if connection.is_connected:
        return True, s3

    return False, connection


def upload_s3_integration(
    tenant_id: str, provider_id: str, output_directory: str
) -> bool:
    """
    Upload the specified output files to an S3 bucket from an integration.
    Reconstructs output objects from files in the output directory instead of using serialized data.

    Args:
        tenant_id (str): The tenant identifier, used as part of the S3 key prefix.
        provider_id (str): The provider identifier, used as part of the S3 key prefix.
        output_directory (str): Path to the directory containing output files.

    Returns:
        bool: True if all integrations were executed, False otherwise.

    Raises:
        botocore.exceptions.ClientError: If the upload attempt to S3 fails for any reason.
    """
    logger.info(f"Processing S3 integrations for provider {provider_id}")

    try:
        with rls_transaction(tenant_id):
            integrations = list(
                Integration.objects.filter(
                    integrationproviderrelationship__provider_id=provider_id,
                    integration_type=Integration.IntegrationChoices.AMAZON_S3,
                    enabled=True,
                )
            )

        if not integrations:
            logger.error(f"No S3 integrations found for provider {provider_id}")
            return False

        integration_executions = 0
        for integration in integrations:
            try:
                connected, s3 = get_s3_client_from_integration(integration)
            except Exception as e:
                logger.info(
                    f"S3 connection failed for integration {integration.id}: {e}"
                )
                integration.connected = False
                integration.save()
                continue

            if connected:
                try:
                    # Reconstruct generated_outputs from files in output directory
                    # This approach scans the output directory for files and creates the appropriate
                    # output objects based on file extensions and naming patterns.
                    generated_outputs = {"regular": [], "compliance": []}

                    # Find and recreate regular outputs (CSV, HTML, OCSF)
                    output_file_patterns = {
                        ".csv": CSV,
                        ".html": HTML,
                        ".ocsf.json": OCSF,
                        ".asff.json": ASFF,
                    }

                    base_dir = os.path.dirname(output_directory)
                    for extension, output_class in output_file_patterns.items():
                        pattern = f"{output_directory}*{extension}"
                        for file_path in glob(pattern):
                            if os.path.exists(file_path):
                                output = output_class(findings=[], file_path=file_path)
                                output.create_file_descriptor(file_path)
                                generated_outputs["regular"].append(output)

                    # Find and recreate compliance outputs
                    compliance_pattern = os.path.join(base_dir, "compliance", "*.csv")
                    for file_path in glob(compliance_pattern):
                        if os.path.exists(file_path):
                            output = GenericCompliance(
                                findings=[],
                                compliance=None,
                                file_path=file_path,
                                file_extension=".csv",
                            )
                            output.create_file_descriptor(file_path)
                            generated_outputs["compliance"].append(output)

                    # Use send_to_bucket with recreated generated_outputs objects
                    s3.send_to_bucket(generated_outputs)
                except Exception as e:
                    logger.error(
                        f"S3 upload failed for integration {integration.id}: {e}"
                    )
                    continue
                integration_executions += 1
            else:
                integration.connected = False
                integration.save()
                logger.error(
                    f"S3 upload failed, connection failed for integration {integration.id}: {s3.error}"
                )

        result = integration_executions == len(integrations)
        if result:
            logger.info(
                f"All the S3 integrations completed successfully for provider {provider_id}"
            )
        else:
            logger.info(f"Some S3 integrations failed for provider {provider_id}")
        return result
    except Exception as e:
        logger.error(f"S3 integrations failed for provider {provider_id}: {str(e)}")
        return False
