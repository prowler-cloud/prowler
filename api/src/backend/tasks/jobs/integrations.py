import os
import time
from glob import glob

from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from django.db import OperationalError
from tasks.utils import batched

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import REPLICA_MAX_ATTEMPTS, REPLICA_RETRY_BASE_DELAY, rls_transaction
from api.models import Finding, Integration, Provider
from api.utils import initialize_prowler_integration, initialize_prowler_provider
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding as FindingOutput
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.exceptions.exceptions import (
    SecurityHubNoEnabledRegionsError,
)
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
    integration: Integration, tenant_id: str, findings: list
) -> tuple[bool, SecurityHub | Connection]:
    """
    Create and return a SecurityHub client using AWS credentials from an integration.

    Args:
        integration (Integration): The integration to get the Security Hub client from.
        tenant_id (str): The tenant identifier.
        findings (list): List of findings in ASFF format to send to Security Hub.

    Returns:
        tuple[bool, SecurityHub | Connection]: A tuple containing a boolean indicating
        if the connection was successful and the SecurityHub client or connection object.
    """
    # Get the provider associated with this integration
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        provider_relationship = integration.integrationproviderrelationship_set.first()
        if not provider_relationship:
            return Connection(
                is_connected=False, error="No provider associated with this integration"
            )
        provider_uid = provider_relationship.provider.uid
        provider_secret = provider_relationship.provider.secret.secret

    credentials = (
        integration.credentials if integration.credentials else provider_secret
    )
    connection = SecurityHub.test_connection(
        aws_account_id=provider_uid,
        raise_on_exception=False,
        **credentials,
    )

    if connection.is_connected:
        all_security_hub_regions = AwsProvider.get_available_aws_service_regions(
            "securityhub", connection.partition
        )

        # Create regions status dictionary
        regions_status = {}
        for region in set(all_security_hub_regions):
            regions_status[region] = region in connection.enabled_regions

        # Save regions information in the integration configuration
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            integration.configuration["regions"] = regions_status
            integration.save()

        # Create SecurityHub client with all necessary parameters
        security_hub = SecurityHub(
            aws_account_id=provider_uid,
            findings=findings,
            send_only_fails=integration.configuration.get("send_only_fails", False),
            aws_security_hub_available_regions=list(connection.enabled_regions),
            **credentials,
        )
        return True, security_hub
    else:
        # Reset regions information if connection fails and integration is not connected
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            integration.connected = False
            integration.configuration["regions"] = {}
            integration.save()

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

        # Process each Security Hub integration
        integration_executions = 0
        total_findings_sent = {}  # Track findings sent per integration

        for integration in integrations:
            try:
                # Initialize Security Hub client for this integration
                # We'll create the client once and reuse it for all batches
                security_hub_client = None
                send_only_fails = integration.configuration.get(
                    "send_only_fails", False
                )
                total_findings_sent[integration.id] = 0

                # Process findings in batches to avoid memory issues
                max_attempts = REPLICA_MAX_ATTEMPTS if READ_REPLICA_ALIAS else 1
                has_findings = False
                batch_number = 0

                for attempt in range(1, max_attempts + 1):
                    read_alias = None
                    if READ_REPLICA_ALIAS:
                        read_alias = (
                            READ_REPLICA_ALIAS
                            if attempt < max_attempts
                            else MainRouter.default_db
                        )

                    try:
                        batch_number = 0
                        has_findings = False
                        with rls_transaction(
                            tenant_id,
                            using=read_alias,
                            retry_on_replica=False,
                        ):
                            qs = (
                                Finding.all_objects.filter(
                                    tenant_id=tenant_id, scan_id=scan_id
                                )
                                .order_by("uid")
                                .iterator()
                            )

                            for batch, _ in batched(qs, DJANGO_FINDINGS_BATCH_SIZE):
                                batch_number += 1
                                has_findings = True

                                # Transform findings for this batch
                                transformed_findings = [
                                    FindingOutput.transform_api_finding(
                                        finding, prowler_provider
                                    )
                                    for finding in batch
                                ]

                                # Convert to ASFF format
                                asff_transformer = ASFF(
                                    findings=transformed_findings,
                                    file_path="",
                                    file_extension="json",
                                )
                                asff_transformer.transform(transformed_findings)

                                # Get the batch of ASFF findings
                                batch_asff_findings = asff_transformer.data

                                if batch_asff_findings:
                                    # Create Security Hub client for first batch or reuse existing
                                    if not security_hub_client:
                                        connected, security_hub = (
                                            get_security_hub_client_from_integration(
                                                integration,
                                                tenant_id,
                                                batch_asff_findings,
                                            )
                                        )

                                        if not connected:
                                            if isinstance(
                                                security_hub.error,
                                                SecurityHubNoEnabledRegionsError,
                                            ):
                                                logger.warning(
                                                    f"Security Hub integration {integration.id} has no enabled regions"
                                                )
                                            else:
                                                logger.error(
                                                    f"Security Hub connection failed for integration {integration.id}: "
                                                    f"{security_hub.error}"
                                                )
                                            break  # Skip this integration

                                        security_hub_client = security_hub
                                        logger.info(
                                            f"Sending {'fail' if send_only_fails else 'all'} findings to Security Hub via "
                                            f"integration {integration.id}"
                                        )
                                    else:
                                        # Update findings in existing client for this batch
                                        security_hub_client._findings_per_region = (
                                            security_hub_client.filter(
                                                batch_asff_findings,
                                                send_only_fails,
                                            )
                                        )

                                    # Send this batch to Security Hub
                                    try:
                                        findings_sent = security_hub_client.batch_send_to_security_hub()
                                        total_findings_sent[integration.id] += (
                                            findings_sent
                                        )

                                        if findings_sent > 0:
                                            logger.debug(
                                                f"Sent batch {batch_number} with {findings_sent} findings to Security Hub"
                                            )
                                    except Exception as batch_error:
                                        logger.error(
                                            f"Failed to send batch {batch_number} to Security Hub: {str(batch_error)}"
                                        )

                                # Clear memory after processing each batch
                                asff_transformer._data.clear()
                                del batch_asff_findings
                                del transformed_findings

                        break
                    except OperationalError as e:
                        if attempt == max_attempts:
                            raise

                        delay = REPLICA_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                        logger.info(
                            "RLS query failed during Security Hub integration "
                            f"(attempt {attempt}/{max_attempts}), retrying in {delay}s. Error: {e}"
                        )
                        time.sleep(delay)

                if not has_findings:
                    logger.info(
                        f"No findings to send to Security Hub for scan {scan_id}"
                    )
                    integration_executions += 1
                elif security_hub_client:
                    if total_findings_sent[integration.id] > 0:
                        logger.info(
                            f"Successfully sent {total_findings_sent[integration.id]} total findings to Security Hub via integration {integration.id}"
                        )
                        integration_executions += 1
                    else:
                        logger.warning(
                            f"No findings were sent to Security Hub via integration {integration.id}"
                        )

                    # Archive previous findings if configured to do so
                    if integration.configuration.get(
                        "archive_previous_findings", False
                    ):
                        logger.info(
                            f"Archiving previous findings in Security Hub via integration {integration.id}"
                        )
                        try:
                            findings_archived = (
                                security_hub_client.archive_previous_findings()
                            )
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

        result = integration_executions == len(integrations)
        if result:
            logger.info(
                f"All Security Hub integrations completed successfully for provider {provider_id}"
            )

        return result

    except Exception as e:
        logger.error(
            f"Security Hub integrations failed for provider {provider_id}: {str(e)}"
        )
        return False


def send_findings_to_jira(
    tenant_id: str,
    integration_id: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
):
    with rls_transaction(tenant_id):
        integration = Integration.objects.get(id=integration_id)
        jira_integration = initialize_prowler_integration(integration)

    num_tickets_created = 0
    for finding_id in finding_ids:
        with rls_transaction(tenant_id):
            finding_instance = (
                Finding.all_objects.select_related("scan__provider")
                .prefetch_related("resources")
                .get(id=finding_id)
            )

            # Extract resource information
            resource = (
                finding_instance.resources.first()
                if finding_instance.resources.exists()
                else None
            )
            resource_uid = resource.uid if resource else ""
            resource_name = resource.name if resource else ""
            resource_tags = {}
            if resource and hasattr(resource, "tags"):
                resource_tags = resource.get_tags(tenant_id)

            # Get region
            region = resource.region if resource and resource.region else ""

            # Extract remediation information from check_metadata
            check_metadata = finding_instance.check_metadata
            remediation = check_metadata.get("remediation", {})
            recommendation = remediation.get("recommendation", {})
            remediation_code = remediation.get("code", {})

            # Send the individual finding to Jira
            result = jira_integration.send_finding(
                check_id=finding_instance.check_id,
                check_title=check_metadata.get("checktitle", ""),
                severity=finding_instance.severity,
                status=finding_instance.status,
                status_extended=finding_instance.status_extended or "",
                provider=finding_instance.scan.provider.provider,
                region=region,
                resource_uid=resource_uid,
                resource_name=resource_name,
                risk=check_metadata.get("risk", ""),
                recommendation_text=recommendation.get("text", ""),
                recommendation_url=recommendation.get("url", ""),
                remediation_code_native_iac=remediation_code.get("nativeiac", ""),
                remediation_code_terraform=remediation_code.get("terraform", ""),
                remediation_code_cli=remediation_code.get("cli", ""),
                remediation_code_other=remediation_code.get("other", ""),
                resource_tags=resource_tags,
                compliance=finding_instance.compliance or {},
                project_key=project_key,
                issue_type=issue_type,
            )
            if result:
                num_tickets_created += 1
            else:
                logger.error(f"Failed to send finding {finding_id} to Jira")

    return {
        "created_count": num_tickets_created,
        "failed_count": len(finding_ids) - num_tickets_created,
    }
