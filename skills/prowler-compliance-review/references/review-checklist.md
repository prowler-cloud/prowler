# Compliance PR Review References

## Related Skills

- [prowler-compliance](../../prowler-compliance/SKILL.md) - Authoring frameworks, schema references
- [prowler-pr](../../prowler-pr/SKILL.md) - PR conventions and checklist
- [prowler-changelog](../../prowler-changelog/SKILL.md) - Changelog fragments

## Documentation (local)

- `docs/developer-guide/security-compliance-framework.mdx` - both schemas, guardrails, validation
- `docs/user-guide/compliance/tutorials/compliance.mdx`, `cross-provider-compliance.mdx`

## File Locations

| File Type | Location |
|---|---|
| Universal framework | `prowler/compliance/<framework>_<version>.json` |
| Legacy framework | `prowler/compliance/<provider>/<framework>_<version>_<provider>.json` |
| Models / loaders | `prowler/lib/check/compliance_models.py` |
| Legacy formatters | `prowler/lib/outputs/compliance/<framework>/` |
| API CSV exporter map (legacy only) | `api/src/backend/tasks/jobs/export.py` (`COMPLIANCE_CLASS_MAP`) |
| UI mapper (optional) | `ui/lib/compliance/compliance-mapper.ts` |
| Dashboard (optional) | `dashboard/compliance/<key with dots as underscores>.py`, fallback `generic.py` |
| Changelog fragment | `prowler/changelog.d/<slug>.<type>.md` |
| Checks | `prowler/providers/<provider>/services/<service>/<check>/` |
| Integrity tests | `tests/lib/check/compliance_catalog_integrity_test.py`, `tests/lib/check/universal_compliance_models_test.py` |

## PR Review Summary Template

```markdown
## Compliance Framework Review Summary

| Check | Result |
|-------|--------|
| Schema (universal / legacy) and justified | PASS/FAIL |
| Loads with real model | PASS/FAIL |
| Catalog integrity test | PASS/FAIL (N missing checks) |
| Validator | PASS/FAIL |
| Mapping quality (sampled) | PASS/FAIL |
| Changelog fragment | PASS/FAIL |

### Statistics
- Total requirements: N
- Providers: ...
- Requirements without checks (manual): N
- Unique checks referenced: N

### Recommendation
APPROVE / REQUEST CHANGES / FAIL

### Issues Found
1. ...
```
