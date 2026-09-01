import os
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from glob import glob
from urllib.parse import quote
from uuid import UUID, uuid4

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import REPLICA_MAX_ATTEMPTS, REPLICA_RETRY_BASE_DELAY, rls_transaction
from api.models import (
    Finding,
    Integration,
    JiraIssue,
    Provider,
    Resource,
    ResourceTag,
)
from api.rls import Tenant
from api.utils import initialize_prowler_integration, initialize_prowler_provider
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from django.conf import settings
from django.db import IntegrityError, OperationalError
from django.db.models import Case, F, Prefetch, Q, UUIDField, Value, When
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


JIRA_CLAIM_LEASE = timedelta(minutes=15)
JIRA_RESULT_LIMIT = 100
JIRA_RECONCILE_INITIAL_DELAY_SECONDS = 30
JIRA_RECONCILE_MAX_DELAY_SECONDS = 15 * 60
JIRA_RECONCILIATION_BATCH_SIZE = 100

JIRA_LEDGER_FIELDS = (
    "id",
    "tenant_id",
    "integration_id",
    "provider_id",
    "finding_uid",
    "finding_id",
    "issue_id",
    "issue_key",
    "issue_url",
    "project_key",
    "issue_type",
    "issue_status",
    "issue_status_category",
    "status_synced_at",
    "attempt_state",
    "claim_token",
    "claim_expires_at",
    "delivery_attempt_token",
    "attempt_operation",
    "attempt_project_key",
    "attempt_issue_type",
    "attempt_count",
    "last_attempt_at",
    "last_error_code",
    "last_error_message",
    "next_reconcile_at",
)


def _delivery_summary() -> dict:
    return {
        "created_count": 0,
        "skipped_count": 0,
        "deferred_count": 0,
        "uncertain_count": 0,
        "failed_count": 0,
        "results": [],
        "truncated": False,
    }


def _delivery_result(
    *,
    finding_id: str,
    finding_uid: str | None,
    provider_id: str | None,
    outcome: str,
    row: JiraIssue | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> dict:
    return {
        "finding_id": str(finding_id),
        "finding_uid": finding_uid,
        "provider_id": str(provider_id) if provider_id else None,
        "outcome": outcome,
        "issue_key": row.issue_key if row else None,
        "issue_url": row.issue_url if row else None,
        "error_code": error_code,
        "error_message": error_message,
    }


def _record_delivery_result(summary: dict, result: dict) -> None:
    summary[f"{result['outcome']}_count"] += 1
    if len(summary["results"]) < JIRA_RESULT_LIMIT:
        summary["results"].append(result)
    else:
        summary["truncated"] = True


def _safe_error(
    error_code: str | None,
    error_message: str | None,
    *,
    fallback_code: str,
    fallback_message: str,
) -> tuple[str, str]:
    return (
        str(error_code or fallback_code)[:128],
        str(error_message or fallback_message)[:2048],
    )


def _load_jira_delivery_page(
    tenant_id: str, integration_id: str, finding_ids: list[str]
) -> tuple[dict[str, Finding], dict[tuple[str, str], JiraIssue]]:
    """Materialize one bounded delivery page and its ledger precheck rows."""
    resource_queryset = (
        Resource.all_objects.only("id", "uid", "name", "region")
        .order_by("id")
        .prefetch_related(
            Prefetch(
                "tags",
                queryset=ResourceTag.objects.only("id", "key", "value"),
                to_attr="_jira_tags",
            )
        )
    )
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        findings = list(
            Finding.all_objects.filter(id__in=finding_ids)
            .select_related("scan__provider")
            .only(
                "id",
                "uid",
                "check_id",
                "check_metadata",
                "severity",
                "status",
                "status_extended",
                "compliance",
                "scan_id",
                "scan__provider_id",
                "scan__provider__id",
                "scan__provider__provider",
            )
            .prefetch_related(
                Prefetch(
                    "resources", queryset=resource_queryset, to_attr="_jira_resources"
                )
            )
        )

        identities_by_provider: dict[str, set[str]] = {}
        for finding in findings:
            identities_by_provider.setdefault(str(finding.scan.provider_id), set()).add(
                finding.uid
            )

        identity_filter = Q()
        for provider_id, finding_uids in identities_by_provider.items():
            identity_filter |= Q(provider_id=provider_id, finding_uid__in=finding_uids)

        ledger_rows = []
        if identity_filter:
            ledger_rows = list(
                JiraIssue.objects.filter(
                    identity_filter,
                    tenant_id=tenant_id,
                    integration_id=integration_id,
                ).only(*JIRA_LEDGER_FIELDS)
            )

        latest_findings = {}
        for finding in findings:
            identity = (str(finding.scan.provider_id), finding.uid)
            current = latest_findings.get(identity)
            if current is None or finding.id > current.id:
                latest_findings[identity] = finding

        finding_id_updates = []
        for row in ledger_rows:
            finding = latest_findings.get((str(row.provider_id), row.finding_uid))
            if finding is not None and finding.id > row.finding_id:
                finding_id_updates.append((row, finding.id))

        if finding_id_updates:
            now = timezone.now()
            JiraIssue.objects.filter(
                id__in=[row.id for row, _ in finding_id_updates]
            ).update(
                finding_id=Case(
                    *[
                        When(
                            id=row.id,
                            finding_id__lt=finding_id,
                            then=Value(finding_id),
                        )
                        for row, finding_id in finding_id_updates
                    ],
                    default=F("finding_id"),
                    output_field=UUIDField(),
                ),
                updated_at=now,
            )
            for row, finding_id in finding_id_updates:
                row.finding_id = finding_id

    return (
        {str(finding.id): finding for finding in findings},
        {(str(row.provider_id), row.finding_uid): row for row in ledger_rows},
    )


def _unknown_status_result(
    row: JiraIssue,
    *,
    error_code: str = "status_lookup_failed",
    error_message: str = "Jira could not confirm the issue status.",
) -> JiraIssueStatusResult:
    return JiraIssueStatusResult(
        reference=JiraIssueReference(issue_id=row.issue_id, issue_key=row.issue_key),
        outcome=JiraIssueLookupOutcome.UNKNOWN,
        error_code=error_code,
        error_message=error_message,
    )


def _refresh_jira_issue_statuses(
    tenant_id: str, jira_integration: Jira, rows: list[JiraIssue]
) -> dict[str, JiraIssueStatusResult | None]:
    """Refresh linked rows by immutable Jira ID without accepting stale writes."""
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
        results = [
            _unknown_status_result(row, error_code="status_lookup_exception")
            for row in rows
        ]

    if not isinstance(results, list) or len(results) != len(rows):
        results = [
            _unknown_status_result(row, error_code="malformed_status_result")
            for row in rows
        ]

    resolved: dict[str, JiraIssueStatusResult | None] = {}
    now = timezone.now()
    for row, reference, status_result in zip(rows, references, results):
        if (
            not isinstance(status_result, JiraIssueStatusResult)
            or status_result.reference != reference
        ):
            status_result = _unknown_status_result(
                row, error_code="malformed_status_result"
            )

        resolved[str(row.id)] = status_result
        if status_result.outcome not in {
            JiraIssueLookupOutcome.OPEN,
            JiraIssueLookupOutcome.DONE,
            JiraIssueLookupOutcome.MOVED,
        }:
            continue
        if (
            status_result.current_issue_id != row.issue_id
            or not status_result.current_issue_key
            or not status_result.current_issue_url
        ):
            resolved[str(row.id)] = _unknown_status_result(
                row, error_code="mismatched_issue_identity"
            )
            continue

        updates = {
            "issue_status": (status_result.status or "")[:64],
            "issue_status_category": (status_result.status_category or "")[:16],
            "status_synced_at": now,
            "updated_at": now,
        }
        if status_result.outcome == JiraIssueLookupOutcome.MOVED:
            updates.update(
                issue_key=status_result.current_issue_key[:64],
                issue_url=status_result.current_issue_url[:2048],
            )
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            updated = JiraIssue.objects.filter(
                id=row.id,
                issue_id=row.issue_id,
                attempt_state=JiraIssue.AttemptStateChoices.IDLE,
            ).update(**updates)
        if not updated:
            resolved[str(row.id)] = None
            continue
        for field, value in updates.items():
            if field != "updated_at":
                setattr(row, field, value)

    return resolved


def _filter_current_issue(queryset, issue_id: str | None):
    if issue_id is None:
        return queryset.filter(issue_id__isnull=True)
    return queryset.filter(issue_id=issue_id)


def _create_initial_claim(
    tenant_id: str,
    integration_id: str,
    finding: Finding,
    project_key: str,
    issue_type: str,
    claim_token: str,
) -> JiraIssue | None:
    now = timezone.now()
    try:
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            row, created = JiraIssue.objects.get_or_create(
                tenant_id=tenant_id,
                integration_id=integration_id,
                provider_id=finding.scan.provider_id,
                finding_uid=finding.uid,
                defaults={
                    "finding_id": finding.id,
                    "attempt_state": JiraIssue.AttemptStateChoices.CREATING,
                    "claim_token": claim_token,
                    "claim_expires_at": now + JIRA_CLAIM_LEASE,
                    "delivery_attempt_token": uuid4(),
                    "attempt_operation": JiraIssue.AttemptOperationChoices.INITIAL,
                    "attempt_project_key": project_key,
                    "attempt_issue_type": issue_type,
                    "attempt_count": 1,
                    "last_attempt_at": now,
                },
            )
    except IntegrityError:
        return None
    return row if created else None


def _claim_existing_attempt(
    tenant_id: str,
    row: JiraIssue,
    finding_id: str,
    claim_token: str,
    *,
    reconcile: bool,
    new_operation: str | None = None,
    project_key: str | None = None,
    issue_type: str | None = None,
) -> JiraIssue | None:
    """Acquire an existing row with a compare-and-set against its loaded state."""
    now = timezone.now()
    if row.attempt_state == JiraIssue.AttemptStateChoices.CREATING:
        if (
            row.claim_token != claim_token
            and row.claim_expires_at
            and row.claim_expires_at > now
        ):
            return None
        expected_claim = {
            "claim_token": row.claim_token,
            "claim_expires_at": row.claim_expires_at,
        }
    else:
        expected_claim = {"claim_token__isnull": True, "claim_expires_at__isnull": True}

    candidate_finding_id = UUID(str(finding_id))
    updates = {
        "finding_id": max(row.finding_id, candidate_finding_id),
        "attempt_state": JiraIssue.AttemptStateChoices.CREATING,
        "claim_token": claim_token,
        "claim_expires_at": now + JIRA_CLAIM_LEASE,
        "attempt_count": row.attempt_count + 1,
        "last_attempt_at": now,
        "last_error_code": None,
        "last_error_message": None,
        "next_reconcile_at": None,
        "updated_at": now,
    }
    if new_operation:
        updates.update(
            delivery_attempt_token=uuid4(),
            attempt_operation=new_operation,
            attempt_project_key=project_key,
            attempt_issue_type=issue_type,
        )
    elif not reconcile:
        updates.update(
            attempt_project_key=project_key,
            attempt_issue_type=issue_type,
        )

    with rls_transaction(tenant_id, using=MainRouter.default_db):
        queryset = JiraIssue.objects.filter(
            id=row.id,
            finding_id=row.finding_id,
            attempt_state=row.attempt_state,
            delivery_attempt_token=row.delivery_attempt_token,
            **expected_claim,
        )
        updated = _filter_current_issue(queryset, row.issue_id).update(**updates)
    if not updated:
        return None
    for field, value in updates.items():
        if field != "updated_at":
            setattr(row, field, value)
    return row


def _owned_claim_queryset(row: JiraIssue, claim_token: str):
    queryset = JiraIssue.objects.filter(
        id=row.id,
        attempt_state=JiraIssue.AttemptStateChoices.CREATING,
        claim_token=claim_token,
        delivery_attempt_token=row.delivery_attempt_token,
    )
    return _filter_current_issue(queryset, row.issue_id)


def _finish_owned_success(
    tenant_id: str,
    row: JiraIssue,
    claim_token: str,
    *,
    issue_id: str,
    issue_key: str,
    issue_url: str,
) -> bool:
    now = timezone.now()
    updates = {
        "issue_id": issue_id[:64],
        "issue_key": issue_key[:64],
        "issue_url": issue_url[:2048],
        "project_key": row.attempt_project_key,
        "issue_type": row.attempt_issue_type,
        "issue_status": None,
        "issue_status_category": None,
        "status_synced_at": None,
        "attempt_state": JiraIssue.AttemptStateChoices.IDLE,
        "claim_token": None,
        "claim_expires_at": None,
        "last_error_code": None,
        "last_error_message": None,
        "next_reconcile_at": None,
        "updated_at": now,
    }
    try:
        with rls_transaction(tenant_id, using=MainRouter.default_db):
            updated = _owned_claim_queryset(row, claim_token).update(**updates)
    except IntegrityError:
        return False
    if updated:
        for field, value in updates.items():
            if field != "updated_at":
                setattr(row, field, value)
    return bool(updated)


def _finish_owned_failure(
    tenant_id: str,
    row: JiraIssue,
    claim_token: str,
    *,
    attempt_state: str,
    error_code: str,
    error_message: str,
) -> bool:
    updates = {
        "attempt_state": attempt_state,
        "claim_token": None,
        "claim_expires_at": None,
        "last_error_code": error_code,
        "last_error_message": error_message,
        "next_reconcile_at": None,
        "updated_at": timezone.now(),
    }
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        updated = _owned_claim_queryset(row, claim_token).update(**updates)
    if updated:
        for field, value in updates.items():
            if field != "updated_at":
                setattr(row, field, value)
    return bool(updated)


def _retry_after_seconds(value: str | None, now: datetime) -> int | None:
    if not value:
        return None
    try:
        return max(0, int(value.strip()))
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        return max(0, int((retry_at - now).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


def _reconcile_delay_seconds(row: JiraIssue, retry_after: str | None) -> int:
    exponent = min(max(row.attempt_count - 1, 0), 5)
    backoff = min(
        JIRA_RECONCILE_INITIAL_DELAY_SECONDS * (2**exponent),
        JIRA_RECONCILE_MAX_DELAY_SECONDS,
    )
    retry_after_seconds = _retry_after_seconds(retry_after, timezone.now())
    return max(backoff, retry_after_seconds or 0)


def _finish_owned_uncertain(
    tenant_id: str,
    row: JiraIssue,
    claim_token: str,
    *,
    error_code: str,
    error_message: str,
    retry_after: str | None = None,
    automatic_retry: bool = True,
) -> bool:
    now = timezone.now()
    updates = {
        "attempt_state": JiraIssue.AttemptStateChoices.UNCERTAIN,
        "claim_token": None,
        "claim_expires_at": None,
        "last_error_code": error_code,
        "last_error_message": error_message,
        "next_reconcile_at": (
            now + timedelta(seconds=_reconcile_delay_seconds(row, retry_after))
            if automatic_retry
            else None
        ),
        "updated_at": now,
    }
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        updated = _owned_claim_queryset(row, claim_token).update(**updates)
    if updated:
        for field, value in updates.items():
            if field != "updated_at":
                setattr(row, field, value)
    return bool(updated)


def _deferred_result(finding: Finding, row: JiraIssue, code: str) -> dict:
    return _delivery_result(
        finding_id=str(finding.id),
        finding_uid=finding.uid,
        provider_id=str(finding.scan.provider_id),
        outcome="deferred",
        row=row,
        error_code=code,
        error_message="Another Jira delivery attempt is in progress.",
    )


def _reconcile_claimed_attempt(
    tenant_id: str,
    jira_integration: Jira,
    row: JiraIssue,
    claim_token: str,
) -> dict:
    try:
        search_result = jira_integration.search_issues_by_delivery_attempt(
            str(row.delivery_attempt_token)
        )
    except Exception:
        logger.exception("Jira delivery-marker lookup failed for ledger row %s", row.id)
        search_result = JiraIssueSearchResult(
            outcome=JiraIssueSearchOutcome.UNKNOWN,
            error_code="marker_lookup_exception",
            error_message="Jira could not reconcile the delivery attempt.",
        )
    if not isinstance(search_result, JiraIssueSearchResult) or not isinstance(
        search_result.matches, tuple
    ):
        search_result = JiraIssueSearchResult(
            outcome=JiraIssueSearchOutcome.UNKNOWN,
            error_code="malformed_marker_lookup",
            error_message="Jira returned an invalid reconciliation result.",
        )

    if search_result.outcome == JiraIssueSearchOutcome.SUCCESS:
        if len(search_result.matches) == 1:
            match = search_result.matches[0]
            if isinstance(match, JiraIssueSearchMatch) and all(
                isinstance(value, str) and value.strip()
                for value in (match.issue_id, match.issue_key, match.issue_url)
            ):
                if _finish_owned_success(
                    tenant_id,
                    row,
                    claim_token,
                    issue_id=match.issue_id,
                    issue_key=match.issue_key,
                    issue_url=match.issue_url,
                ):
                    return _delivery_result(
                        finding_id=str(row.finding_id),
                        finding_uid=row.finding_uid,
                        provider_id=str(row.provider_id),
                        outcome="created",
                        row=row,
                    )
                error_code = "jira_issue_already_linked"
                error_message = "The reconciled Jira issue could not be linked safely."
                automatic_retry = False
            else:
                error_code = "malformed_marker_match"
                error_message = "Jira returned an invalid issue during reconciliation."
                automatic_retry = True
        elif len(search_result.matches) > 1:
            error_code = "multiple_marker_matches"
            error_message = "Multiple Jira issues match this delivery attempt."
            automatic_retry = False
        else:
            error_code = "marker_not_found"
            error_message = "Jira has not returned an issue for this delivery attempt."
            automatic_retry = True
    else:
        error_code, error_message = _safe_error(
            search_result.error_code,
            search_result.error_message,
            fallback_code="marker_lookup_failed",
            fallback_message="Jira could not reconcile the delivery attempt.",
        )
        automatic_retry = True

    if not _finish_owned_uncertain(
        tenant_id,
        row,
        claim_token,
        error_code=error_code,
        error_message=error_message,
        retry_after=search_result.retry_after,
        automatic_retry=automatic_retry,
    ):
        return _delivery_result(
            finding_id=str(row.finding_id),
            finding_uid=row.finding_uid,
            provider_id=str(row.provider_id),
            outcome="deferred",
            row=row,
            error_code="ledger_changed",
            error_message="The Jira delivery state changed during reconciliation.",
        )
    return _delivery_result(
        finding_id=str(row.finding_id),
        finding_uid=row.finding_uid,
        provider_id=str(row.provider_id),
        outcome="uncertain",
        row=row,
        error_code=error_code,
        error_message=error_message,
    )


def _send_claimed_finding(
    tenant_id: str,
    jira_integration: Jira,
    finding: Finding,
    row: JiraIssue,
    claim_token: str,
    tenant_info: str,
) -> dict:
    resources = getattr(finding, "_jira_resources", [])
    resource = resources[0] if resources else None
    resource_tags = (
        {tag.key: tag.value for tag in getattr(resource, "_jira_tags", [])}
        if resource
        else {}
    )
    check_metadata = finding.check_metadata or {}
    remediation = check_metadata.get("remediation", {}) or {}
    recommendation = remediation.get("recommendation", {}) or {}
    remediation_code = remediation.get("code", {}) or {}
    provider_type = finding.scan.provider.provider

    try:
        creation_result = jira_integration.send_finding(
            check_id=finding.check_id,
            check_title=check_metadata.get("checktitle", ""),
            severity=finding.severity,
            status=finding.status,
            status_extended=finding.status_extended or "",
            provider=provider_type,
            region=resource.region if resource and resource.region else "",
            resource_uid=resource.uid if resource else "",
            resource_name=resource.name if resource else "",
            risk=check_metadata.get("risk", ""),
            recommendation_text=recommendation.get("text", ""),
            recommendation_url=recommendation.get("url", ""),
            remediation_code_native_iac=remediation_code.get("nativeiac", ""),
            remediation_code_terraform=remediation_code.get("terraform", ""),
            remediation_code_cli=remediation_code.get("cli", ""),
            remediation_code_other=remediation_code.get("other", ""),
            resource_tags=resource_tags,
            compliance=finding.compliance or {},
            project_key=row.attempt_project_key,
            issue_type=row.attempt_issue_type,
            issue_labels=build_jira_issue_labels(
                finding_uid=finding.uid,
                provider=provider_type,
                severity=finding.severity,
                check_id=finding.check_id,
            ),
            delivery_attempt_marker=str(row.delivery_attempt_token),
            finding_url=build_jira_finding_url(finding.uid),
            tenant_info=tenant_info,
        )
    except Exception:
        logger.exception("Failed to send finding %s to Jira", finding.id)
        creation_result = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            delivery_marker=str(row.delivery_attempt_token),
            error_code="unexpected_send_exception",
            error_message="Jira did not confirm whether it created the issue.",
        )

    if not isinstance(creation_result, JiraCreationResult):
        creation_result = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            delivery_marker=str(row.delivery_attempt_token),
            error_code="invalid_creation_result",
            error_message="Jira returned an invalid issue creation result.",
        )

    if creation_result.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS and not all(
        isinstance(value, str) and value.strip()
        for value in (
            creation_result.issue_id,
            creation_result.issue_key,
            creation_result.issue_url,
        )
    ):
        creation_result = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            delivery_marker=str(row.delivery_attempt_token),
            error_code="invalid_creation_result",
            error_message="Jira returned an invalid issue creation result.",
        )

    if creation_result.outcome == JiraCreationOutcome.CONFIRMED_SUCCESS:
        linked = _finish_owned_success(
            tenant_id,
            row,
            claim_token,
            issue_id=creation_result.issue_id,
            issue_key=creation_result.issue_key,
            issue_url=creation_result.issue_url,
        )
        if linked:
            logger.info("Finding %s sent to Jira as %s", finding.id, row.issue_key)
            return _delivery_result(
                finding_id=str(finding.id),
                finding_uid=finding.uid,
                provider_id=str(finding.scan.provider_id),
                outcome="created",
                row=row,
            )
        error_code = "jira_issue_already_linked"
        error_message = "The confirmed Jira issue could not be linked safely."
        if _finish_owned_uncertain(
            tenant_id,
            row,
            claim_token,
            error_code=error_code,
            error_message=error_message,
        ):
            return _delivery_result(
                finding_id=str(finding.id),
                finding_uid=finding.uid,
                provider_id=str(finding.scan.provider_id),
                outcome="uncertain",
                row=row,
                error_code=error_code,
                error_message=error_message,
            )
        return _deferred_result(finding, row, "ledger_changed")

    error_code, error_message = _safe_error(
        creation_result.error_code,
        creation_result.error_message,
        fallback_code="jira_creation_failed",
        fallback_message=JIRA_GENERIC_SEND_ERROR,
    )
    if creation_result.outcome == JiraCreationOutcome.UNCERTAIN:
        updated = _finish_owned_uncertain(
            tenant_id,
            row,
            claim_token,
            error_code=error_code,
            error_message=error_message,
            retry_after=creation_result.retry_after,
        )
        outcome = "uncertain"
    elif creation_result.outcome in {
        JiraCreationOutcome.CONFIRMED_REJECTION,
        JiraCreationOutcome.RETRYABLE_FAILURE,
    }:
        attempt_state = (
            JiraIssue.AttemptStateChoices.TERMINAL_FAILURE
            if creation_result.outcome == JiraCreationOutcome.CONFIRMED_REJECTION
            else JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE
        )
        updated = _finish_owned_failure(
            tenant_id,
            row,
            claim_token,
            attempt_state=attempt_state,
            error_code=error_code,
            error_message=error_message,
        )
        outcome = "failed"
    else:
        error_code = "invalid_creation_outcome"
        error_message = "Jira returned an invalid issue creation result."
        updated = _finish_owned_uncertain(
            tenant_id,
            row,
            claim_token,
            error_code=error_code,
            error_message=error_message,
        )
        outcome = "uncertain"
    if not updated:
        return _deferred_result(finding, row, "ledger_changed")
    return _delivery_result(
        finding_id=str(finding.id),
        finding_uid=finding.uid,
        provider_id=str(finding.scan.provider_id),
        outcome=outcome,
        row=row,
        error_code=error_code,
        error_message=error_message,
    )


def _process_jira_delivery_page(
    tenant_id: str,
    integration_id: str,
    jira_integration: Jira,
    tenant_info: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
    claim_token: str,
    force_replace: bool,
    actor_id: str | None,
) -> list[dict]:
    findings, ledger = _load_jira_delivery_page(tenant_id, integration_id, finding_ids)
    linked_idle_rows = [
        row
        for row in ledger.values()
        if row.is_linked and row.attempt_state == JiraIssue.AttemptStateChoices.IDLE
    ]
    statuses = _refresh_jira_issue_statuses(
        tenant_id, jira_integration, linked_idle_rows
    )

    results = []
    for finding_id in finding_ids:
        finding = findings.get(str(finding_id))
        if finding is None:
            results.append(
                _delivery_result(
                    finding_id=str(finding_id),
                    finding_uid=None,
                    provider_id=None,
                    outcome="failed",
                    error_code="finding_not_found",
                    error_message="The finding could not be loaded.",
                )
            )
            continue

        identity = (str(finding.scan.provider_id), finding.uid)
        row = ledger.get(identity)
        if row is None:
            row = _create_initial_claim(
                tenant_id,
                integration_id,
                finding,
                project_key,
                issue_type,
                claim_token,
            )
            if row is None:
                results.append(
                    _delivery_result(
                        finding_id=str(finding.id),
                        finding_uid=finding.uid,
                        provider_id=str(finding.scan.provider_id),
                        outcome="deferred",
                        error_code="claim_conflict",
                        error_message="Another Jira delivery attempt acquired this finding.",
                    )
                )
                continue
            results.append(
                _send_claimed_finding(
                    tenant_id,
                    jira_integration,
                    finding,
                    row,
                    claim_token,
                    tenant_info,
                )
            )
            continue

        if row.attempt_state in {
            JiraIssue.AttemptStateChoices.CREATING,
            JiraIssue.AttemptStateChoices.UNCERTAIN,
        }:
            claimed = _claim_existing_attempt(
                tenant_id,
                row,
                str(finding.id),
                claim_token,
                reconcile=True,
            )
            if claimed is None:
                results.append(_deferred_result(finding, row, "active_claim"))
            else:
                results.append(
                    _reconcile_claimed_attempt(
                        tenant_id, jira_integration, claimed, claim_token
                    )
                )
            continue

        if row.attempt_state in {
            JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            JiraIssue.AttemptStateChoices.TERMINAL_FAILURE,
        }:
            claimed = _claim_existing_attempt(
                tenant_id,
                row,
                str(finding.id),
                claim_token,
                reconcile=False,
                project_key=project_key,
                issue_type=issue_type,
            )
            if claimed is None:
                results.append(_deferred_result(finding, row, "claim_conflict"))
            else:
                results.append(
                    _send_claimed_finding(
                        tenant_id,
                        jira_integration,
                        finding,
                        claimed,
                        claim_token,
                        tenant_info,
                    )
                )
            continue

        if row.is_linked:
            status_result = statuses.get(str(row.id))
            if status_result is None:
                results.append(_deferred_result(finding, row, "ledger_changed"))
                continue
            if status_result.outcome in {
                JiraIssueLookupOutcome.OPEN,
                JiraIssueLookupOutcome.MOVED,
            }:
                results.append(
                    _delivery_result(
                        finding_id=str(finding.id),
                        finding_uid=finding.uid,
                        provider_id=str(finding.scan.provider_id),
                        outcome="skipped",
                        row=row,
                    )
                )
                continue
            unknown_status = status_result.outcome in {
                JiraIssueLookupOutcome.MISSING,
                JiraIssueLookupOutcome.FORBIDDEN,
                JiraIssueLookupOutcome.UNKNOWN,
            }
            if unknown_status and not force_replace:
                error_code, error_message = _safe_error(
                    status_result.error_code,
                    status_result.error_message,
                    fallback_code="jira_status_unknown",
                    fallback_message="Jira could not confirm the linked issue status.",
                )
                results.append(
                    _delivery_result(
                        finding_id=str(finding.id),
                        finding_uid=finding.uid,
                        provider_id=str(finding.scan.provider_id),
                        outcome="skipped",
                        row=row,
                        error_code=error_code,
                        error_message=error_message,
                    )
                )
                continue

            claimed = _claim_existing_attempt(
                tenant_id,
                row,
                str(finding.id),
                claim_token,
                reconcile=False,
                new_operation=JiraIssue.AttemptOperationChoices.REPLACEMENT,
                project_key=project_key,
                issue_type=issue_type,
            )
            if claimed is None:
                results.append(_deferred_result(finding, row, "claim_conflict"))
            else:
                if unknown_status and force_replace:
                    logger.warning(
                        "jira_force_replacement",
                        extra={
                            "user_id": actor_id,
                            "tenant_id": str(tenant_id),
                            "metadata": {
                                "integration_id": str(integration_id),
                                "provider_id": str(finding.scan.provider_id),
                                "finding_uid": finding.uid,
                                "old_issue_id": row.issue_id,
                                "old_issue_key": row.issue_key,
                                "old_issue_url": row.issue_url,
                            },
                        },
                    )
                results.append(
                    _send_claimed_finding(
                        tenant_id,
                        jira_integration,
                        finding,
                        claimed,
                        claim_token,
                        tenant_info,
                    )
                )
            continue

        claimed = _claim_existing_attempt(
            tenant_id,
            row,
            str(finding.id),
            claim_token,
            reconcile=False,
            new_operation=JiraIssue.AttemptOperationChoices.INITIAL,
            project_key=project_key,
            issue_type=issue_type,
        )
        if claimed is None:
            results.append(_deferred_result(finding, row, "claim_conflict"))
        else:
            results.append(
                _send_claimed_finding(
                    tenant_id,
                    jira_integration,
                    finding,
                    claimed,
                    claim_token,
                    tenant_info,
                )
            )
    return results


def send_findings_to_jira(
    tenant_id: str,
    integration_id: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
    *,
    task_id: str | None = None,
    force_replace: bool = False,
    actor_id: str | None = None,
) -> dict:
    """Deliver findings through the concurrency-safe Jira issue ledger."""
    claim_token = str(task_id or uuid4())
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        integration = Integration.objects.only(
            "id", "tenant_id", "integration_type", "configuration", "_credentials"
        ).get(id=integration_id)
        tenant_info = get_tenant_name(tenant_id)
    jira_integration = initialize_prowler_integration(integration)

    summary = _delivery_summary()
    for page, _ in batched(
        [str(finding_id) for finding_id in finding_ids],
        DJANGO_FINDINGS_BATCH_SIZE,
    ):
        if not page:
            continue
        page_results = _process_jira_delivery_page(
            tenant_id,
            integration_id,
            jira_integration,
            tenant_info,
            project_key,
            issue_type,
            page,
            claim_token,
            force_replace,
            actor_id,
        )
        for result in page_results:
            _record_delivery_result(summary, result)
    return summary


def reconcile_due_jira_issues(
    tenant_id: str,
    integration_id: str,
    *,
    task_id: str,
    limit: int = JIRA_RECONCILIATION_BATCH_SIZE,
) -> dict:
    """Reconcile due uncertain and stale creating rows without issuing a POST."""
    now = timezone.now()
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        integration = Integration.objects.only(
            "id", "tenant_id", "integration_type", "configuration", "_credentials"
        ).get(id=integration_id)
        rows = list(
            JiraIssue.objects.filter(
                tenant_id=tenant_id,
                integration_id=integration_id,
            )
            .filter(
                Q(
                    attempt_state=JiraIssue.AttemptStateChoices.UNCERTAIN,
                    next_reconcile_at__lte=now,
                )
                | Q(
                    attempt_state=JiraIssue.AttemptStateChoices.CREATING,
                    claim_expires_at__lte=now,
                )
            )
            .only(*JIRA_LEDGER_FIELDS)
            .order_by("next_reconcile_at", "claim_expires_at", "id")[:limit]
        )
    jira_integration = initialize_prowler_integration(integration)
    summary = _delivery_summary()
    claim_token = str(task_id)
    for row in rows:
        claimed = _claim_existing_attempt(
            tenant_id,
            row,
            str(row.finding_id),
            claim_token,
            reconcile=True,
        )
        result = (
            _reconcile_claimed_attempt(
                tenant_id, jira_integration, claimed, claim_token
            )
            if claimed
            else _delivery_result(
                finding_id=str(row.finding_id),
                finding_uid=row.finding_uid,
                provider_id=str(row.provider_id),
                outcome="deferred",
                row=row,
                error_code="claim_conflict",
                error_message="Another Jira reconciliation acquired this attempt.",
            )
        )
        _record_delivery_result(summary, result)
    return summary
