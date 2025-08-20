import os
from glob import glob

from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from tasks.utils import batched

from api.db_utils import rls_transaction
from api.models import Finding, Integration, Provider
from api.utils import initialize_prowler_provider
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding as FindingOutput
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
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


def get_security_hub_client_from_integration(
    integration: Integration, provider: Provider, findings: list
) -> tuple[bool, SecurityHub | Connection]:
    """
    Create and return a SecurityHub client using AWS credentials from an integration.

    Args:
        integration (Integration): The integration to get the Security Hub client from.
        provider (Provider): The provider object containing account info.
        findings (list): List of findings in ASFF format to send to Security Hub.

    Returns:
        tuple[bool, SecurityHub | Connection]: A tuple containing a boolean indicating
        if the connection was successful and the SecurityHub client or connection object.
    """
    # Initialize prowler provider to get aws_account_id and aws_partition
    prowler_provider = initialize_prowler_provider(provider)

    # Check if integration has credentials
    if integration.credentials:
        # Use integration credentials directly
        connection = SecurityHub.test_connection(
            aws_account_id=prowler_provider.identity.account,
            aws_partition=prowler_provider.identity.partition,
            raise_on_exception=False,
            **integration.credentials,
        )
    else:
        credentials = prowler_provider.session.current_session.get_credentials()
        connection = SecurityHub.test_connection(
            aws_account_id=prowler_provider.identity.account,
            aws_partition=prowler_provider.identity.partition,
            aws_access_key_id=credentials.access_key,
            aws_secret_access_key=credentials.secret_key,
            aws_session_token=credentials.token,
            raise_on_exception=False,
        )

    if connection.is_connected:
        # Check if regions are already saved in configuration
        regions_config = integration.configuration.get("regions", None)

        if not regions_config:
            # If not saved, calculate them
            all_security_hub_regions = (
                prowler_provider.get_available_aws_service_regions(
                    "securityhub",
                    prowler_provider.identity.partition,
                    prowler_provider.identity.audited_regions,
                )
                if not prowler_provider.identity.audited_regions
                else prowler_provider.identity.audited_regions
            )

            # Create temporary SecurityHub instance to get enabled regions
            temp_security_hub = SecurityHub(
                aws_account_id=prowler_provider.identity.account,
                aws_partition=prowler_provider.identity.partition,
                aws_session=prowler_provider.session.current_session,
                findings=[],
                send_only_fails=False,
                aws_security_hub_available_regions=all_security_hub_regions,
            )

            # Get enabled regions as a set
            enabled_regions = set(temp_security_hub._enabled_regions.keys())
            all_regions_set = set(all_security_hub_regions)

            # Create regions status dictionary
            regions_status = {}
            for region in all_regions_set:
                regions_status[region] = region in enabled_regions

            # Save regions information in the integration configuration
            integration.configuration["regions"] = regions_status
            integration.save()

            # Use only enabled regions for SecurityHub client
            security_hub_regions = list(enabled_regions)
        else:
            # Extract only enabled regions from the saved configuration
            security_hub_regions = [
                region for region, enabled in regions_config.items() if enabled
            ]

        # Create SecurityHub client with all necessary parameters
        security_hub = SecurityHub(
            aws_account_id=prowler_provider.identity.account,
            aws_partition=prowler_provider.identity.partition,
            aws_session=prowler_provider.session.current_session,
            findings=findings,
            send_only_fails=integration.configuration.get("send_only_fails", False),
            aws_security_hub_available_regions=security_hub_regions,
        )
        return True, security_hub

    return False, connection


def upload_security_hub_integration(
    tenant_id: str, provider_id: str, scan_id: str
) -> bool:
    """
    Upload findings to AWS Security Hub using configured integrations.

    This function retrieves findings from the database, transforms them to ASFF format,
    and sends them to AWS Security Hub using the configured integration credentials.

    Args:
        tenant_id (str): The tenant identifier.
        provider_id (str): The provider identifier.
        scan_id (str): The scan identifier for which to send findings.

    Returns:
        bool: True if all integrations executed successfully, False otherwise.
    """
    logger.info(f"Processing Security Hub integrations for provider {provider_id}")

    try:
        with rls_transaction(tenant_id):
            # Get Security Hub integrations for this provider
            integrations = list(
                Integration.objects.filter(
                    integrationproviderrelationship__provider_id=provider_id,
                    integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB,
                    enabled=True,
                )
            )

            if not integrations:
                logger.error(
                    f"No Security Hub integrations found for provider {provider_id}"
                )
                return False

            # Get the provider object
            provider = Provider.objects.get(id=provider_id)

            # Initialize prowler provider for finding transformation
            prowler_provider = initialize_prowler_provider(provider)

            # Get findings from database and transform them to ASFF format
            logger.info(f"Transforming findings for scan {scan_id}")
            asff_findings = []

            # Process findings in batches to avoid memory issues
            qs = Finding.all_objects.filter(scan_id=scan_id).order_by("uid").iterator()
            for batch, _ in batched(qs, DJANGO_FINDINGS_BATCH_SIZE):
                # Transform findings using the same method as the report generation
                transformed_findings = [
                    FindingOutput.transform_api_finding(finding, prowler_provider)
                    for finding in batch
                ]

                # Convert to ASFF format using the ASFF transformer
                asff_transformer = ASFF(
                    findings=transformed_findings,
                    file_path="",  # Not needed for integration
                    file_extension="json",
                )
                asff_transformer.transform(transformed_findings)

                # Add the transformed ASFF data to our findings list
                asff_findings.extend(asff_transformer.data)

                # Clear the transformer data for memory efficiency
                asff_transformer._data.clear()

        if not asff_findings:
            logger.info(f"No findings to send to Security Hub for scan {scan_id}")
            return True

        logger.info(f"Found {len(asff_findings)} findings to send to Security Hub")

        # Process each Security Hub integration
        integration_executions = 0
        for integration in integrations:
            try:
                # Filter findings based on send_only_fails configuration for this integration
                send_only_fails = integration.configuration.get(
                    "send_only_fails", False
                )

                if send_only_fails:
                    logger.info(
                        f"Filtering to only send FAILED findings for integration {integration.id}"
                    )
                    # Filter the already transformed ASFF findings to only include FAILED status
                    filtered_asff_findings = [
                        finding
                        for finding in asff_findings
                        if finding.Compliance.Status == "FAILED"
                    ]
                else:
                    filtered_asff_findings = asff_findings

                # Create Security Hub client with integration credentials
                connected, security_hub = get_security_hub_client_from_integration(
                    integration, provider, filtered_asff_findings
                )

                if not connected:
                    logger.error(
                        f"Security Hub connection failed for integration {integration.id}: {security_hub.error}"
                    )
                    # Mark integration as disconnected
                    with rls_transaction(tenant_id):
                        integration.connected = False
                        integration.save()
                    continue

                # Send findings to Security Hub
                logger.info(
                    f"Sending {len(filtered_asff_findings)} findings to Security Hub via integration {integration.id}"
                )
                findings_sent = security_hub.batch_send_to_security_hub()

                if findings_sent > 0:
                    logger.info(
                        f"Successfully sent {findings_sent} findings to Security Hub via integration {integration.id}"
                    )
                    integration_executions += 1
                else:
                    logger.warning(
                        f"No findings were sent to Security Hub via integration {integration.id}"
                    )

                # Archive previous findings if configured to do so
                if not integration.configuration.get("skip_archive_previous", False):
                    logger.info(
                        f"Archiving previous findings in Security Hub via integration {integration.id}"
                    )
                    try:
                        findings_archived = security_hub.archive_previous_findings()
                        logger.info(
                            f"Successfully archived {findings_archived} previous findings in Security Hub"
                        )
                    except Exception as archive_error:
                        logger.warning(
                            f"Failed to archive previous findings: {str(archive_error)}"
                        )

            except Exception as e:
                logger.error(
                    f"Security Hub integration {integration.id} failed: {str(e)}"
                )
                continue

        result = integration_executions == len(integrations)
        if result:
            logger.info(
                f"All Security Hub integrations completed successfully for provider {provider_id}"
            )
        else:
            logger.error(
                f"Some Security Hub integrations failed for provider {provider_id}"
            )

        return result

    except Exception as e:
        logger.error(
            f"Security Hub integrations failed for provider {provider_id}: {str(e)}"
        )
        return False
