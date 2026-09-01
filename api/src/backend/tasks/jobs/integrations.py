import os
import time
from datetime import UTC, datetime
from glob import glob
from urllib.parse import quote
from uuid import uuid4

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import REPLICA_MAX_ATTEMPTS, REPLICA_RETRY_BASE_DELAY, rls_transaction
from api.models import Finding, Integration, JiraIssue, Provider
from api.rls import Tenant
from api.utils import initialize_prowler_integration, initialize_prowler_provider
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from django.conf import settings
from django.db import IntegrityError, OperationalError
from django.utils import timezone
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding as FindingOutput
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.jira.jira import Jira
from prowler.lib.outputs.jira.models import (
    JiraCreationOutcome,
    JiraCreationResult,
    JiraIssueLookupOutcome,
    JiraIssueReference,
    JiraIssueSearchMatch,
    JiraIssueSearchOutcome,
    JiraIssueSearchResult,
    JiraIssueStatusResult,
)
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.exceptions.exceptions import (
    SecurityHubNoEnabledRegionsError,
)
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from prowler.providers.common.models import Connection
from tasks.utils import batched

logger = get_task_logger(__name__)

JIRA_GENERIC_SEND_ERROR = "Failed to create Jira issue."


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

        # Persist the successful connection check and regions information
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            integration.connected = True
            integration.connection_last_checked_at = datetime.now(tz=UTC)
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


JIRA_LABEL_PREFIX = "prowler"


def build_jira_finding_url(finding_uid: str) -> str:
    """Build the Prowler UI link for a finding, or "" when no UI base URL is set.

    The link filters by the finding ``uid`` rather than the per-scan record id so
    it keeps resolving after the finding is seen again in later scans.
    """
    base_url = getattr(settings, "UI_BASE_URL", "")
    if not base_url or not finding_uid:
        return ""
    return f"{base_url}/findings?filter[uid]={quote(finding_uid, safe='')}"


def build_jira_issue_labels(
    finding_uid: str, provider: str, severity: str, check_id: str
) -> list[str]:
    """Build the deterministic label set written to every Jira issue.

    Labels are prefixed to avoid colliding with customer labels and sanitized so
    Jira never rejects them; the finding-uid label is what lets a ticket be traced
    back (or JQL-filtered) to its finding.
    """
    raw_labels = [
        JIRA_LABEL_PREFIX,
        f"{JIRA_LABEL_PREFIX}-{provider}" if provider else "",
        f"{JIRA_LABEL_PREFIX}-{severity}" if severity else "",
        f"{JIRA_LABEL_PREFIX}-{check_id}" if check_id else "",
        Jira.build_finding_label(finding_uid),
    ]
    return Jira.sanitize_labels(raw_labels)


def get_tenant_name(tenant_id: str) -> str:
    """Return the tenant name for the Jira issue "Tenant Info" row, or "" if unknown.

    The name is informational only, so a lookup failure must never block the send.
    """
    try:
        return (
            Tenant.objects.filter(id=tenant_id).values_list("name", flat=True).first()
            or ""
        )
    except Exception:
        logger.warning("Could not resolve tenant name for %s", tenant_id)
        return ""


# Findings are pre-checked in bounded index lookups however many a dispatch carries.
JIRA_DEDUP_CHUNK_SIZE = 500
JIRA_SKIPPED_REPORT_LIMIT = 100
JIRA_ERROR_REPORT_MAX_LENGTH = 8192


def _load_finding_refs(finding_ids: list[str]) -> dict[str, tuple[str, str]]:
    """Map finding id -> (provider id, finding uid) for the batch, in one query."""
    refs = {}
    for finding_id, provider_id, uid in Finding.all_objects.filter(
        id__in=finding_ids
    ).values_list("id", "scan__provider_id", "uid"):
        refs[str(finding_id)] = (str(provider_id), uid)
    return refs


def _load_existing_jira_issues(
    tenant_id: str, integration_id: str, refs: dict[str, tuple[str, str]]
) -> dict[tuple[str, str], JiraIssue]:
    """Load the Jira issue rows already linked to the batch's findings.

    Grouped by provider and chunked so each query is a bounded index lookup on
    (tenant, integration, provider, finding_uid).
    """
    uids_by_provider: dict[str, list[str]] = {}
    for provider_id, uid in refs.values():
        uids_by_provider.setdefault(provider_id, []).append(uid)

    existing: dict[tuple[str, str], JiraIssue] = {}
    for provider_id, uids in uids_by_provider.items():
        for start in range(0, len(uids), JIRA_DEDUP_CHUNK_SIZE):
            chunk = uids[start : start + JIRA_DEDUP_CHUNK_SIZE]
            for row in JiraIssue.objects.filter(
                tenant_id=tenant_id,
                integration_id=integration_id,
                provider_id=provider_id,
                finding_uid__in=chunk,
            ):
                existing[(str(row.provider_id), row.finding_uid)] = row
    return existing


def _refresh_jira_issue_statuses(
    jira_integration: Jira, rows: list[JiraIssue]
) -> dict[str, JiraIssueStatusResult]:
    """Fetch linked issue statuses without holding a database transaction."""
    if not rows:
        return {}
    references = [
        JiraIssueReference(issue_id=row.issue_id, issue_key=row.issue_key)
        for row in rows
    ]
    try:
        results = jira_integration.get_issues_status(references)
    except Exception:
        logger.exception("Could not refresh Jira issue statuses")
        results = []

    if not isinstance(results, list) or len(results) != len(references):
        results = [None] * len(references)

    statuses = {}
    for row, reference, status_result in zip(rows, references, results):
        if (
            not isinstance(status_result, JiraIssueStatusResult)
            or status_result.reference != reference
        ):
            status_result = JiraIssueStatusResult(
                reference=reference,
                outcome=JiraIssueLookupOutcome.UNKNOWN,
                error_code="malformed_status_result",
                error_message="Jira returned an invalid issue status result.",
            )
        statuses[str(row.id)] = status_result
    return statuses


def _apply_jira_issue_status(
    tenant_id: str, row: JiraIssue, status_result: JiraIssueStatusResult
) -> bool:
    """Cache a conclusive status if it still describes this linked issue."""
    if status_result.outcome not in {
        JiraIssueLookupOutcome.OPEN,
        JiraIssueLookupOutcome.DONE,
        JiraIssueLookupOutcome.MOVED,
    }:
        return False

    current_values = (
        status_result.current_issue_id,
        status_result.current_issue_key,
        status_result.current_issue_url,
        status_result.status,
        status_result.status_category,
    )
    if not all(isinstance(value, str) and value.strip() for value in current_values):
        return False
    if status_result.current_issue_id != row.issue_id:
        return False
    moved = status_result.outcome == JiraIssueLookupOutcome.MOVED
    key_changed = status_result.current_issue_key != row.issue_key
    if moved != key_changed:
        return False
    if status_result.status_category not in {
        JiraIssue.StatusCategoryChoices.NEW,
        JiraIssue.StatusCategoryChoices.INDETERMINATE,
        JiraIssue.StatusCategoryChoices.DONE,
    }:
        return False
    if (
        status_result.outcome == JiraIssueLookupOutcome.OPEN
        and status_result.status_category == JiraIssue.StatusCategoryChoices.DONE
    ) or (
        status_result.outcome == JiraIssueLookupOutcome.DONE
        and status_result.status_category != JiraIssue.StatusCategoryChoices.DONE
    ):
        return False

    now = timezone.now()
    updates = {
        "issue_status": status_result.status[:64],
        "issue_status_category": status_result.status_category[:16],
        "status_synced_at": now,
        "updated_at": now,
    }
    if moved:
        updates.update(
            issue_key=status_result.current_issue_key[:64],
            issue_url=status_result.current_issue_url[:2048],
        )
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        updated = JiraIssue.objects.filter(
            id=row.id,
            issue_id=row.issue_id,
            issue_key=row.issue_key,
            delivery_attempt_token__isnull=True,
        ).update(**updates)
    if not updated:
        return False
    for field, value in updates.items():
        if field != "updated_at":
            setattr(row, field, value)
    return True


def _update_latest_jira_finding_id(
    tenant_id: str, row: JiraIssue, finding_id: str
) -> None:
    # Finding IDs are monotonic UUIDv7 values, so ordering reflects scan recency
    # and prevents stale dispatches from moving the ledger pointer backward.
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        JiraIssue.objects.filter(id=row.id, finding_id__lt=finding_id).update(
            finding_id=finding_id,
            updated_at=timezone.now(),
        )


def _reserve_initial_jira_issue(
    tenant_id: str,
    integration_id: str,
    provider_id: str,
    finding_uid: str,
    finding_id: str,
) -> JiraIssue | None:
    """Reserve a new finding identity; the unique constraint chooses the sender."""
    try:
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            return JiraIssue.objects.create(
                tenant_id=tenant_id,
                integration_id=integration_id,
                provider_id=provider_id,
                finding_uid=finding_uid,
                finding_id=finding_id,
                delivery_attempt_token=uuid4(),
            )
    except IntegrityError:
        return None


def _reserve_jira_issue_replacement(
    tenant_id: str, row: JiraIssue, finding_id: str
) -> JiraIssue | None:
    """Reserve replacement of a Done issue while preserving the current link."""
    delivery_attempt_token = uuid4()
    try:
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            updated = JiraIssue.objects.filter(
                id=row.id,
                issue_id=row.issue_id,
                issue_key=row.issue_key,
                issue_status_category=JiraIssue.StatusCategoryChoices.DONE,
                delivery_attempt_token__isnull=True,
            ).update(
                finding_id=finding_id,
                delivery_attempt_token=delivery_attempt_token,
                updated_at=timezone.now(),
            )
    except IntegrityError:
        return None
    if not updated:
        return None
    row.finding_id = finding_id
    row.delivery_attempt_token = delivery_attempt_token
    return row


def _link_jira_issue(
    tenant_id: str,
    row: JiraIssue,
    delivery_attempt_token,
    *,
    issue_id: str,
    issue_key: str,
    issue_url: str,
    project_key: str,
    finding_id: str,
) -> bool:
    """Link a confirmed issue only if this worker still owns the marker."""
    values = (issue_id, issue_key, issue_url, project_key)
    if not all(isinstance(value, str) and value.strip() for value in values):
        return False
    updates = {
        "issue_id": issue_id[:64],
        "issue_key": issue_key[:64],
        "issue_url": issue_url[:2048],
        "project_key": project_key[:64],
        "finding_id": finding_id,
        "issue_status": None,
        "issue_status_category": None,
        "status_synced_at": None,
        "delivery_attempt_token": None,
        "updated_at": timezone.now(),
    }
    filters = {"id": row.id, "delivery_attempt_token": delivery_attempt_token}
    if row.issue_id is None:
        filters["issue_id__isnull"] = True
    else:
        filters["issue_id"] = row.issue_id
    try:
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            updated = JiraIssue.objects.filter(**filters).update(**updates)
    except IntegrityError:
        return False
    if not updated:
        return False
    for field, value in updates.items():
        if field != "updated_at":
            setattr(row, field, value)
    return True


def _release_jira_delivery_attempt(
    tenant_id: str, row: JiraIssue, delivery_attempt_token
) -> bool:
    """Release a confirmed failure without removing a previous issue link."""
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        queryset = JiraIssue.objects.filter(
            id=row.id,
            delivery_attempt_token=delivery_attempt_token,
        )
        if row.issue_id is None:
            deleted, _ = queryset.filter(issue_id__isnull=True).delete()
            released = bool(deleted)
        else:
            released = bool(
                queryset.filter(issue_id=row.issue_id).update(
                    delivery_attempt_token=None,
                    updated_at=timezone.now(),
                )
            )
    if released:
        row.delivery_attempt_token = None
    return released


def _skipped_entry(finding_id: str, row: JiraIssue | None = None) -> dict:
    return {
        "finding_id": str(finding_id),
        "issue_key": row.issue_key if row else None,
        "issue_url": row.issue_url if row else None,
        "issue_status": row.issue_status if row else None,
    }


def _recover_pending_jira_issue(
    tenant_id: str,
    jira_integration: Jira,
    row: JiraIssue,
    finding_id: str,
) -> bool:
    """Link exactly one marker match; every other result remains reserved."""
    delivery_attempt_token = row.delivery_attempt_token
    try:
        search_result = jira_integration.search_issues_by_delivery_attempt(
            str(delivery_attempt_token)
        )
    except Exception:
        logger.exception("Could not search Jira delivery marker for row %s", row.id)
        return False
    if (
        not isinstance(search_result, JiraIssueSearchResult)
        or search_result.outcome != JiraIssueSearchOutcome.SUCCESS
        or len(search_result.matches) != 1
    ):
        return False
    match = search_result.matches[0]
    if not isinstance(match, JiraIssueSearchMatch) or not all(
        isinstance(value, str) and value.strip()
        for value in (match.issue_id, match.issue_key, match.issue_url)
    ):
        return False
    project_key, separator, _ = match.issue_key.rpartition("-")
    if not separator or not project_key:
        return False
    return _link_jira_issue(
        tenant_id,
        row,
        delivery_attempt_token,
        issue_id=match.issue_id,
        issue_key=match.issue_key,
        issue_url=match.issue_url,
        project_key=project_key,
        finding_id=finding_id,
    )


def _get_jira_send_payload(
    tenant_id: str,
    finding_id: str,
    project_key: str,
    issue_type: str,
    tenant_info: str,
) -> dict:
    """Build a finding payload inside RLS, ready for an external Jira call."""
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        finding = (
            Finding.all_objects.select_related("scan__provider")
            .prefetch_related("resources")
            .get(id=finding_id)
        )
        resource = finding.resources.first() if finding.resources.exists() else None
        resource_tags = (
            resource.get_tags(tenant_id)
            if resource and hasattr(resource, "tags")
            else {}
        )
        check_metadata = finding.check_metadata or {}
        remediation = check_metadata.get("remediation", {}) or {}
        recommendation = remediation.get("recommendation", {}) or {}
        remediation_code = remediation.get("code", {}) or {}
        provider_type = finding.scan.provider.provider
        return {
            "check_id": finding.check_id,
            "check_title": check_metadata.get("checktitle", ""),
            "severity": finding.severity,
            "status": finding.status,
            "status_extended": finding.status_extended or "",
            "provider": provider_type,
            "region": resource.region if resource and resource.region else "",
            "resource_uid": resource.uid if resource else "",
            "resource_name": resource.name if resource else "",
            "risk": check_metadata.get("risk", ""),
            "recommendation_text": recommendation.get("text", ""),
            "recommendation_url": recommendation.get("url", ""),
            "remediation_code_native_iac": remediation_code.get("nativeiac", ""),
            "remediation_code_terraform": remediation_code.get("terraform", ""),
            "remediation_code_cli": remediation_code.get("cli", ""),
            "remediation_code_other": remediation_code.get("other", ""),
            "resource_tags": resource_tags,
            "compliance": finding.compliance or {},
            "project_key": project_key,
            "issue_type": issue_type,
            "issue_labels": build_jira_issue_labels(
                finding_uid=finding.uid,
                provider=provider_type,
                severity=finding.severity,
                check_id=finding.check_id,
            ),
            "finding_url": build_jira_finding_url(finding.uid),
            "tenant_info": tenant_info,
        }


def _send_reserved_jira_finding(
    jira_integration: Jira, payload: dict, delivery_attempt_token
) -> JiraCreationResult:
    try:
        creation_result = jira_integration.send_finding(
            **payload,
            delivery_attempt_marker=str(delivery_attempt_token),
        )
    except Exception:
        logger.exception("Jira raised while sending a reserved finding")
        return JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            delivery_marker=str(delivery_attempt_token),
            error_code="unexpected_send_exception",
            error_message=JIRA_GENERIC_SEND_ERROR,
        )
    if not isinstance(creation_result, JiraCreationResult):
        return JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            delivery_marker=str(delivery_attempt_token),
            error_code="invalid_creation_result",
            error_message=JIRA_GENERIC_SEND_ERROR,
        )
    return creation_result


def _jira_creation_error(creation_result: JiraCreationResult) -> str:
    message = str(creation_result.error_message or JIRA_GENERIC_SEND_ERROR).strip()
    return message[:2048] or JIRA_GENERIC_SEND_ERROR


def send_findings_to_jira(
    tenant_id: str,
    integration_id: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
):
    """Deliver findings through the finding-to-Jira ledger."""
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        integration = Integration.objects.get(id=integration_id)
        tenant_info = get_tenant_name(tenant_id)
        finding_refs = _load_finding_refs(finding_ids)
        existing = _load_existing_jira_issues(tenant_id, integration_id, finding_refs)
    jira_integration = initialize_prowler_integration(integration)

    status_rows = [
        row
        for row in existing.values()
        if row.is_linked and row.delivery_attempt_token is None
    ]
    statuses = _refresh_jira_issue_statuses(jira_integration, status_rows)

    created_count = 0
    failed_count = 0
    skipped_count = 0
    skipped = []
    error_messages = []
    processed_identities = set()

    def record_skip(finding_id: str, row: JiraIssue | None = None) -> None:
        nonlocal skipped_count
        skipped_count += 1
        if len(skipped) < JIRA_SKIPPED_REPORT_LIMIT:
            skipped.append(_skipped_entry(finding_id, row))

    for finding_id in finding_ids:
        finding_id = str(finding_id)
        finding_ref = finding_refs.get(finding_id)
        if finding_ref is None:
            logger.warning("Finding %s could not be loaded for Jira", finding_id)
            failed_count += 1
            error_messages.append(JIRA_GENERIC_SEND_ERROR)
            continue

        provider_id, finding_uid = finding_ref
        identity = (provider_id, finding_uid)
        row = existing.get(identity)
        if row is not None:
            _update_latest_jira_finding_id(tenant_id, row, finding_id)
        if identity in processed_identities:
            record_skip(finding_id, row)
            continue
        processed_identities.add(identity)

        if row is not None and row.delivery_attempt_token is not None:
            if _recover_pending_jira_issue(
                tenant_id, jira_integration, row, finding_id
            ):
                created_count += 1
            else:
                record_skip(finding_id, row)
            continue

        needs_replacement = False
        if row is not None and row.is_linked:
            status_result = statuses.get(str(row.id))
            if status_result is None or not _apply_jira_issue_status(
                tenant_id, row, status_result
            ):
                record_skip(finding_id, row)
                continue
            needs_replacement = (
                status_result.outcome == JiraIssueLookupOutcome.DONE
                or (
                    status_result.outcome == JiraIssueLookupOutcome.MOVED
                    and status_result.status_category
                    == JiraIssue.StatusCategoryChoices.DONE
                )
            )
            if not needs_replacement:
                record_skip(finding_id, row)
                continue
        elif row is not None:
            record_skip(finding_id, row)
            continue

        try:
            payload = _get_jira_send_payload(
                tenant_id,
                finding_id,
                project_key,
                issue_type,
                tenant_info,
            )
        except Exception:
            logger.exception("Failed to build finding %s for Jira", finding_id)
            failed_count += 1
            error_messages.append(JIRA_GENERIC_SEND_ERROR)
            continue

        if needs_replacement:
            row = _reserve_jira_issue_replacement(tenant_id, row, finding_id)
        else:
            row = _reserve_initial_jira_issue(
                tenant_id,
                integration_id,
                provider_id,
                finding_uid,
                finding_id,
            )
        if row is None:
            record_skip(finding_id, existing.get(identity))
            continue
        existing[identity] = row

        delivery_attempt_token = row.delivery_attempt_token
        creation_result = _send_reserved_jira_finding(
            jira_integration, payload, delivery_attempt_token
        )
        if creation_result.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS:
            linked = _link_jira_issue(
                tenant_id,
                row,
                delivery_attempt_token,
                issue_id=creation_result.issue_id,
                issue_key=creation_result.issue_key,
                issue_url=creation_result.issue_url,
                project_key=project_key,
                finding_id=finding_id,
            )
            if linked:
                created_count += 1
                logger.info(
                    "Finding %s sent to Jira as %s",
                    finding_id,
                    creation_result.issue_key,
                )
            else:
                failed_count += 1
                error_messages.append(JIRA_GENERIC_SEND_ERROR)
            continue

        failed_count += 1
        error_messages.append(_jira_creation_error(creation_result))
        if creation_result.outcome in {
            JiraCreationOutcome.CONFIRMED_REJECTION,
            JiraCreationOutcome.RETRYABLE_FAILURE,
        }:
            _release_jira_delivery_attempt(tenant_id, row, delivery_attempt_token)
            if row.issue_id is None:
                existing.pop(identity, None)

    result = {
        "created_count": created_count,
        "failed_count": failed_count,
        "skipped_count": skipped_count,
    }
    if error_messages:
        result["error"] = "; ".join(dict.fromkeys(error_messages))[
            :JIRA_ERROR_REPORT_MAX_LENGTH
        ]
    if skipped:
        result["skipped"] = skipped
    return result
