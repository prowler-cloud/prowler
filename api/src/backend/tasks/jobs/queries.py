"""
Shared SQL queries for tasks.

This module centralizes raw SQL queries used across multiple task modules
to ensure consistency and maintainability.
"""

# =============================================================================
# COMPLIANCE SCORE QUERIES
# =============================================================================

# Upsert provider compliance scores from a scan's compliance requirements.
# Uses FAIL-dominant aggregation: FAIL > MANUAL > PASS
# Parameters: [tenant_id, scan_id]
COMPLIANCE_UPSERT_PROVIDER_SCORE_SQL = """
    INSERT INTO provider_compliance_scores
        (id, tenant_id, provider_id, scan_id, compliance_id, requirement_id,
         requirement_status, scan_completed_at)
    SELECT
        gen_random_uuid(),
        agg.tenant_id,
        agg.provider_id,
        agg.scan_id,
        agg.compliance_id,
        agg.requirement_id,
        agg.requirement_status,
        agg.completed_at
    FROM (
        SELECT DISTINCT ON (cro.compliance_id, cro.requirement_id)
            cro.tenant_id,
            s.provider_id,
            cro.scan_id,
            cro.compliance_id,
            cro.requirement_id,
            (CASE
                WHEN bool_or(cro.requirement_status = 'FAIL')
                    OVER (PARTITION BY cro.compliance_id, cro.requirement_id) THEN 'FAIL'
                WHEN bool_or(cro.requirement_status = 'MANUAL')
                    OVER (PARTITION BY cro.compliance_id, cro.requirement_id) THEN 'MANUAL'
                ELSE 'PASS'
            END)::status as requirement_status,
            s.completed_at
        FROM compliance_requirements_overviews cro
        JOIN scans s ON s.id = cro.scan_id
        WHERE cro.tenant_id = %s AND cro.scan_id = %s
        ORDER BY cro.compliance_id, cro.requirement_id
    ) agg
    ON CONFLICT (tenant_id, provider_id, compliance_id, requirement_id)
    DO UPDATE SET
        requirement_status = EXCLUDED.requirement_status,
        scan_id = EXCLUDED.scan_id,
        scan_completed_at = EXCLUDED.scan_completed_at
    WHERE EXCLUDED.scan_completed_at > provider_compliance_scores.scan_completed_at
"""

# Upsert tenant compliance summary for specific compliance IDs.
# Aggregates across all providers with FAIL-dominant logic at requirement level.
# Parameters: [tenant_id, tenant_id, compliance_ids_array]
COMPLIANCE_UPSERT_TENANT_SUMMARY_SQL = """
    INSERT INTO tenant_compliance_summaries
        (id, tenant_id, compliance_id,
         requirements_passed, requirements_failed, requirements_manual,
         total_requirements, updated_at)
    SELECT
        gen_random_uuid(),
        %s as tenant_id,
        compliance_id,
        COUNT(*) FILTER (WHERE req_status = 'PASS') as requirements_passed,
        COUNT(*) FILTER (WHERE req_status = 'FAIL') as requirements_failed,
        COUNT(*) FILTER (WHERE req_status = 'MANUAL') as requirements_manual,
        COUNT(*) as total_requirements,
        NOW() as updated_at
    FROM (
        SELECT
            compliance_id,
            requirement_id,
            CASE
                WHEN bool_or(requirement_status = 'FAIL') THEN 'FAIL'
                WHEN bool_or(requirement_status = 'MANUAL') THEN 'MANUAL'
                ELSE 'PASS'
            END as req_status
        FROM provider_compliance_scores
        WHERE tenant_id = %s AND compliance_id = ANY(%s)
        GROUP BY compliance_id, requirement_id
    ) req_agg
    GROUP BY compliance_id
    ON CONFLICT (tenant_id, compliance_id)
    DO UPDATE SET
        requirements_passed = EXCLUDED.requirements_passed,
        requirements_failed = EXCLUDED.requirements_failed,
        requirements_manual = EXCLUDED.requirements_manual,
        total_requirements = EXCLUDED.total_requirements,
        updated_at = NOW()
"""

# Delete tenant compliance summaries with no remaining provider scores.
# Parameters: [tenant_id, compliance_ids_array]
COMPLIANCE_DELETE_EMPTY_TENANT_SUMMARY_SQL = """
    DELETE FROM tenant_compliance_summaries tcs
    WHERE tcs.tenant_id = %s
      AND tcs.compliance_id = ANY(%s)
      AND NOT EXISTS (
          SELECT 1
          FROM provider_compliance_scores pcs
          WHERE pcs.tenant_id = tcs.tenant_id
            AND pcs.compliance_id = tcs.compliance_id
      )
"""

# Upsert tenant compliance summary for ALL compliance IDs in tenant.
# Used by backfill when recalculating entire tenant summary.
# Parameters: [tenant_id, tenant_id]
COMPLIANCE_UPSERT_TENANT_SUMMARY_ALL_SQL = """
    INSERT INTO tenant_compliance_summaries
        (id, tenant_id, compliance_id,
         requirements_passed, requirements_failed, requirements_manual,
         total_requirements, updated_at)
    SELECT
        gen_random_uuid(),
        %s as tenant_id,
        compliance_id,
        COUNT(*) FILTER (WHERE req_status = 'PASS') as requirements_passed,
        COUNT(*) FILTER (WHERE req_status = 'FAIL') as requirements_failed,
        COUNT(*) FILTER (WHERE req_status = 'MANUAL') as requirements_manual,
        COUNT(*) as total_requirements,
        NOW() as updated_at
    FROM (
        SELECT
            compliance_id,
            requirement_id,
            CASE
                WHEN bool_or(requirement_status = 'FAIL') THEN 'FAIL'
                WHEN bool_or(requirement_status = 'MANUAL') THEN 'MANUAL'
                ELSE 'PASS'
            END as req_status
        FROM provider_compliance_scores
        WHERE tenant_id = %s
        GROUP BY compliance_id, requirement_id
    ) req_agg
    GROUP BY compliance_id
    ON CONFLICT (tenant_id, compliance_id)
    DO UPDATE SET
        requirements_passed = EXCLUDED.requirements_passed,
        requirements_failed = EXCLUDED.requirements_failed,
        requirements_manual = EXCLUDED.requirements_manual,
        total_requirements = EXCLUDED.total_requirements,
        updated_at = NOW()
"""
