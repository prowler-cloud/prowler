import os
import time
from datetime import UTC, datetime, timedelta
from glob import glob
from urllib.parse import quote

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
from prowler.lib.outputs.jira.exceptions.exceptions import JiraBaseException
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
JIRA_LABEL_MAX_LENGTH = 255


def sanitize_jira_label(label: str) -> str:
    """Make a value safe to use as a Jira label.

    Jira rejects labels containing whitespace or longer than 255 characters. The
    transformation is deterministic so the same finding always yields the same
    label: whitespace runs become a single underscore, control characters are
    dropped and the result is truncated. Mirrors ``Jira.sanitize_label`` in the
    SDK; kept local so the API does not depend on an unreleased SDK symbol.
    """
    if not label:
        return ""
    cleaned = "".join(ch for ch in str(label) if ch.isprintable() or ch.isspace())
    return "_".join(cleaned.split())[:JIRA_LABEL_MAX_LENGTH]


def sanitize_jira_labels(labels: list[str]) -> list[str]:
    """Sanitize a list of labels, dropping empties and duplicates (order kept)."""
    result: list[str] = []
    for label in labels or []:
        sanitized = sanitize_jira_label(label)
        if sanitized and sanitized not in result:
            result.append(sanitized)
    return result


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
        f"{JIRA_LABEL_PREFIX}-finding-{finding_uid}" if finding_uid else "",
    ]
    return sanitize_jira_labels(raw_labels)


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


# Findings are pre-checked against existing Jira issues in chunks so the IN list
# stays bounded however many findings a dispatch carries
JIRA_DEDUP_CHUNK_SIZE = 500
# A reservation (row without issue key) older than this belongs to a run that
# died mid-send and can be reclaimed
JIRA_RESERVATION_TTL = timedelta(minutes=15)
# Cap on the per-finding detail returned in the task result; counts are exact
JIRA_SKIPPED_REPORT_LIMIT = 100


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
    tenant_id: str, jira_integration, rows: list[JiraIssue]
) -> dict[str, dict] | None:
    """Fetch the current Jira status of linked rows and cache it on them.

    Returns the statuses keyed by issue key (keys missing from the result no
    longer exist in Jira), or None when Jira could not be queried, in which case
    the cached values are left untouched.
    """
    keys = [row.issue_key for row in rows if row.issue_key]
    if not keys:
        return {}
    try:
        statuses = jira_integration.get_issues_status(keys)
    except JiraBaseException as error:
        logger.warning(
            "Could not refresh Jira issue statuses, keeping cached values: %s",
            error.message or error,
        )
        return None
    except Exception:
        logger.exception("Could not refresh Jira issue statuses, keeping cached values")
        return None

    now = timezone.now()
    for row in rows:
        status = statuses.get(row.issue_key)
        if status is None:
            # The issue is gone: keep the key for reference but mark it as done so
            # the next send creates a fresh issue
            row.issue_status = ""
            row.issue_status_category = JiraIssue.StatusCategoryChoices.DONE
        else:
            row.issue_status = status.get("status", "")[:64]
            row.issue_status_category = status.get("status_category", "")[:16]
        row.status_synced_at = now
    with rls_transaction(tenant_id):
        JiraIssue.objects.bulk_update(
            rows, ["issue_status", "issue_status_category", "status_synced_at"]
        )
    return statuses


def _reserve_jira_issue(
    tenant_id: str,
    integration_id: str,
    provider_id: str,
    finding_uid: str,
    finding_id: str,
    project_key: str,
) -> JiraIssue | None:
    """Claim the (integration, provider, finding uid) slot before calling Jira.

    The unique constraint makes this the arbiter between concurrent runs: only
    the run that inserts the row (or reclaims an expired reservation) sends the
    finding. Returns None when another run owns the slot.
    """
    with rls_transaction(tenant_id):
        try:
            row, created = JiraIssue.objects.get_or_create(
                tenant_id=tenant_id,
                integration_id=integration_id,
                provider_id=provider_id,
                finding_uid=finding_uid,
                defaults={"finding_id": finding_id, "project_key": project_key},
            )
        except IntegrityError:
            return None
        if created:
            return row
        if row.issue_key:
            # Linked by a concurrent run between the pre-check and now
            return None
        if timezone.now() - row.updated_at < JIRA_RESERVATION_TTL:
            # Another run is sending this finding right now
            return None
        # Expired reservation from a run that died mid-send: reclaim it
        row.finding_id = finding_id
        row.project_key = project_key
        row.save(update_fields=["finding_id", "project_key", "updated_at"])
        return row


def _link_jira_issue(
    tenant_id: str, row: JiraIssue, issue: dict, finding_id: str, project_key: str
) -> None:
    """Point the row at the issue Jira just created."""
    with rls_transaction(tenant_id):
        row.issue_key = (issue.get("key") or "")[:64]
        row.issue_id = str(issue.get("id") or "")[:64]
        row.issue_url = (issue.get("url") or "")[:2048]
        row.project_key = project_key
        row.finding_id = finding_id
        row.issue_status = ""
        row.issue_status_category = JiraIssue.StatusCategoryChoices.NEW
        row.status_synced_at = None
        row.save(
            update_fields=[
                "issue_key",
                "issue_id",
                "issue_url",
                "project_key",
                "finding_id",
                "issue_status",
                "issue_status_category",
                "status_synced_at",
                "updated_at",
            ]
        )


def _release_jira_issue(tenant_id: str, row: JiraIssue) -> None:
    """Drop a reservation whose send failed so the finding can be retried."""
    if row.issue_key:
        # A previously linked (now closed) issue stays linked; the send failed so
        # there is nothing newer to point at
        return
    with rls_transaction(tenant_id):
        JiraIssue.objects.filter(id=row.id, issue_key="").delete()


def _skipped_entry(finding_id: str, row: JiraIssue) -> dict:
    return {
        "finding_id": str(finding_id),
        "issue_key": row.issue_key,
        "issue_url": row.issue_url,
        "issue_status": row.issue_status,
    }


def send_findings_to_jira(
    tenant_id: str,
    integration_id: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
):
    """Create one Jira issue per finding, skipping findings that already have one.

    Findings are matched to existing issues by (integration, provider, finding
    uid), so a finding that was already sent in a previous scan is recognised.
    Findings whose linked issue is still open are skipped and reported; findings
    whose issue is closed or was deleted in Jira get a new issue that replaces
    the link.
    """
    with rls_transaction(tenant_id):
        integration = Integration.objects.get(id=integration_id)
        jira_integration = initialize_prowler_integration(integration)
        tenant_info = get_tenant_name(tenant_id)
        finding_refs = _load_finding_refs(finding_ids)
        existing = _load_existing_jira_issues(tenant_id, integration_id, finding_refs)

    # Refresh the status of the linked issues in bulk so closed/deleted ones can be
    # replaced. If Jira cannot be queried the linked findings are skipped as-is.
    linked_rows = [row for row in existing.values() if row.issue_key]
    statuses = (
        _refresh_jira_issue_statuses(tenant_id, jira_integration, linked_rows)
        if linked_rows
        else {}
    )

    num_tickets_created = 0
    skipped: list[dict] = []
    error_messages: list[str] = []
    created_rows: list[JiraIssue] = []
    for finding_id in finding_ids:
        finding_id = str(finding_id)
        provider_id, finding_uid = finding_refs.get(finding_id, (None, None))
        row = existing.get((provider_id, finding_uid)) if provider_id else None
        if row is not None:
            if row.issue_key:
                if statuses is None or not row.is_done:
                    # Still open (or status unknown): already ticketed
                    skipped.append(_skipped_entry(finding_id, row))
                    continue
                # Closed or deleted in Jira: create a replacement below
            elif timezone.now() - row.updated_at < JIRA_RESERVATION_TTL:
                # Another run is sending this finding right now
                skipped.append(_skipped_entry(finding_id, row))
                continue

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

            provider_type = finding_instance.scan.provider.provider
            if provider_id is None:
                provider_id = str(finding_instance.scan.provider_id)
                finding_uid = finding_instance.uid
            issue_labels = build_jira_issue_labels(
                finding_uid=finding_uid,
                provider=provider_type,
                severity=finding_instance.severity,
                check_id=finding_instance.check_id,
            )
            finding_url = build_jira_finding_url(finding_uid)

        if row is None:
            row = _reserve_jira_issue(
                tenant_id,
                integration_id,
                provider_id,
                finding_uid,
                finding_id,
                project_key,
            )
            if row is None:
                skipped.append({"finding_id": finding_id})
                continue

        try:
            # Send the individual finding to Jira
            result = jira_integration.send_finding(
                check_id=finding_instance.check_id,
                check_title=check_metadata.get("checktitle", ""),
                severity=finding_instance.severity,
                status=finding_instance.status,
                status_extended=finding_instance.status_extended or "",
                provider=provider_type,
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
                issue_labels=issue_labels,
                finding_url=finding_url,
                tenant_info=tenant_info,
            )
        except JiraBaseException as error:
            error_message = error.message or JIRA_GENERIC_SEND_ERROR
            logger.exception(
                "Failed to send finding %s to Jira: %s", finding_id, error_message
            )
            error_messages.append(error_message)
            _release_jira_issue(tenant_id, row)
            continue
        except Exception:
            logger.exception("Failed to send finding %s to Jira", finding_id)
            error_messages.append(JIRA_GENERIC_SEND_ERROR)
            _release_jira_issue(tenant_id, row)
            continue

        if result:
            num_tickets_created += 1
            issue = result if isinstance(result, dict) else {}
            logger.info(
                "Finding %s sent to Jira as %s", finding_id, issue.get("key") or result
            )
            _link_jira_issue(tenant_id, row, issue, finding_id, project_key)
            created_rows.append(row)
        else:
            error_message = JIRA_GENERIC_SEND_ERROR
            logger.error(error_message)
            error_messages.append(error_message)
            _release_jira_issue(tenant_id, row)

    # Record the initial status of the issues just created, in bulk
    if created_rows:
        _refresh_jira_issue_statuses(
            tenant_id, jira_integration, [row for row in created_rows if row.issue_key]
        )

    result = {
        "created_count": num_tickets_created,
        "skipped_count": len(skipped),
        "failed_count": len(finding_ids) - num_tickets_created - len(skipped),
    }
    if skipped:
        result["skipped"] = skipped[:JIRA_SKIPPED_REPORT_LIMIT]
    if error_messages:
        result["error"] = "; ".join(dict.fromkeys(error_messages))

    return result
