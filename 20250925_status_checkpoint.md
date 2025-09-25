# Status Checkpoint — GitHub Organization Base Permissions Check (Issue #8662)

Date: 2025-09-25
Branch: feature/github-org-base-permissions-check
Target PR: ask-23/prowler → master

## Summary
Implemented a new GitHub organization-level security check to verify that an organization’s default repository permission (base permission for members) is configured to a strict level. The check passes when base permission is "read" or "none", and fails when it is "write" or "admin" (or any other non-strict value). Unknown/undisclosed permission values are skipped.

This implementation follows Prowler’s established architecture and coding patterns (provider/service/check structure), uses the existing Organization service and CheckReportGithub reporting model, and integrates via a new check folder under the GitHub provider.

- Check ID: `organization_default_repository_permission_strict`
- Provider: `github`
- Service: `organization`
- Severity: `high`
- ResourceType: `GitHubOrganization`

## Files Created / Modified

1) Created — Check logic
- `prowler/providers/github/services/organization/organization_default_repository_permission_strict/organization_default_repository_permission_strict.py`
  - Defines class `organization_default_repository_permission_strict(Check)`.
  - Iterates organizations from `organization_client`, evaluates `org.base_permission`.
  - Reports PASS for `read`/`none`, FAIL otherwise; skips when unknown.

2) Created — Check metadata
- `prowler/providers/github/services/organization/organization_default_repository_permission_strict/organization_default_repository_permission_strict.metadata.json`
  - Standard metadata fields aligned with other GitHub organization checks.
  - Includes Provider, CheckID, ServiceName, Severity, and RelatedUrl to GitHub docs.

3) Modified — Organization service model and processing
- `prowler/providers/github/services/organization/organization_service.py`
  - Added `base_permission: Optional[str] = None` to `Org` model.
  - In `_process_organization`, populate `base_permission` from `org.default_repository_permission` (safe getattr with error logging).

4) Created — Unit tests (6 total)
- `tests/providers/github/services/organization/organization_default_repository_permission_strict/organization_default_repository_permission_strict_test.py`
  - Coverage:
    - No organizations → 0 findings
    - PASS when base permission is `read`
    - PASS when base permission is `none`
    - FAIL when base permission is `write`
    - FAIL when base permission is `admin`
    - Skip (no finding) when base permission is `None` (unknown)

## Test Results (Local)
Environment:
- Python: 3.12.10 (set via `poetry env use python3.12`)
- Poetry: 2.2.1

Commands:
```
poetry install
poetry run pytest -q tests/providers/github/services/organization/organization_default_repository_permission_strict/organization_default_repository_permission_strict_test.py
```

Result:
```
6 passed in 0.20s
```

## Technical Approach (TDD)
- Red:
  - Added focused unit tests capturing PASS/FAIL/skip scenarios and behavior with no organizations.
- Green:
  - Implemented the check logic and metadata, conforming to Prowler’s check structure.
- Refactor:
  - Enhanced the Organization service `Org` model to include `base_permission` and populated the field in `_process_organization`.
- Verify:
  - Ran the new test file; all tests passed locally under Poetry.

## Integration Points with Prowler Architecture
- Provider architecture: New check resides under `prowler/providers/github/services/organization/<check_id>/` alongside other organization checks.
- Service client: Reuses `organization_client` to enumerate organizations.
- Reporting model: Uses `CheckReportGithub` and `metadata()` from the base `Check` class to construct standardized findings.
- Organization data model: Extends `Org` (Pydantic BaseModel) to include `base_permission` while preserving existing fields and behavior.
- Error handling: Gracefully handles missing permissions by skipping a finding (consistent with other checks when data is unavailable).

## Compliance Alignment
- Control: CIS Control 1.3.8 (tighten default repository permissions across an organization)
- Interpretation: Organizations should set base repository permission for members to the least privilege required — typically `read` or `none`. Higher defaults like `write` or `admin` risk widespread unauthorized or accidental modifications.
- Check behavior:
  - PASS: `read` or `none`
  - FAIL: `write`, `admin`, or other elevated defaults
  - SKIP: Unknown/unreadable permission

## Notes and Considerations
- This check is organization-level since base permissions are configured at the org level (not per-repo).
- RelatedUrl in metadata points to GitHub documentation for managing base permissions.
- Further enhancements: Map this check into the appropriate compliance frameworks in `prowler/compliance` if required by maintainers.

## Next Steps
- Open PR from branch `feature/github-org-base-permissions-check` to master in `ask-23/prowler`.
- Await review feedback.
- Optionally wire to compliance mappings per maintainer guidance.

