from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0047_remove_integration_unique_configuration_per_tenant"),
    ]

    operations = [
        # Composite index for filtering by tenant, scan and individual status columns
        # The new indexes with INCLUDE clause provide better performance for specific queries
        AddIndexConcurrently(
            model_name="scansummary",
            index=models.Index(
                fields=["tenant_id", "scan_id", "fail", "_pass", "muted"],
                name="ss_tenant_scan_status_cols_idx",
            ),
        ),
        # Index for severity grouping with status columns included (CRITICAL for findings_severity endpoint)
        # This complements ss_tenant_scan_severity_idx by allowing Index-Only Scans
        AddIndexConcurrently(
            model_name="scansummary",
            index=models.Index(
                fields=["tenant_id", "scan_id", "severity"],
                include=("fail", "_pass", "muted", "total"),
                name="ss_tenant_scan_sev_status_idx",
            ),
        ),
        # Index for service filtering with status columns (CRITICAL for services endpoint)
        # This complements ss_tenant_scan_service_idx by allowing Index-Only Scans
        AddIndexConcurrently(
            model_name="scansummary",
            index=models.Index(
                fields=["tenant_id", "scan_id", "service"],
                include=("fail", "_pass", "muted", "total", "severity"),
                name="ss_tenant_scan_svc_status_idx",
            ),
        ),
        # Index for region filtering with status columns
        AddIndexConcurrently(
            model_name="scansummary",
            index=models.Index(
                fields=["tenant_id", "scan_id", "region"],
                include=("fail", "_pass", "muted", "total", "severity"),
                name="ss_tenant_scan_reg_status_idx",
            ),
        ),
    ]
