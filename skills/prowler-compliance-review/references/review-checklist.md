# Compliance PR Review References

## Related Skills

- [prowler-compliance](../../prowler-compliance/SKILL.md) - Creating compliance frameworks
- [prowler-pr](../../prowler-pr/SKILL.md) - PR conventions and checklist

## Documentation

- [Prowler Developer Guide](https://docs.prowler.com/developer-guide/introduction)
- [Compliance Framework Structure](https://docs.prowler.com/developer-guide/compliance)

## File Locations

| File Type | Location |
|-----------|----------|
| Compliance JSON | `prowler/compliance/{provider}/{framework}.json` |
| Dashboard | `dashboard/compliance/{framework}_{provider}.py` |
| CHANGELOG | `prowler/CHANGELOG.md` |
| Checks | `prowler/providers/{provider}/services/{service}/{check}/` |

## Validation Script

Run the validation script from the project root:

```bash
python3 skills/prowler-compliance-review/assets/validate_compliance.py \
  prowler/compliance/{provider}/{framework}.json
```

## PR Review Summary Template

When completing a compliance framework review, use this summary format:

```markdown
## Compliance Framework Review Summary

| Check | Result |
|-------|--------|
| JSON Valid | PASS/FAIL |
| All Checks Exist | PASS/FAIL (N missing) |
| No Duplicate IDs | PASS/FAIL |
| CHANGELOG Entry | PASS/FAIL |
| Dashboard File | PASS/FAIL |

### Statistics
- Total Requirements: N
- Automated: N
- Manual: N
- Unique Checks: N

### Recommendation
APPROVE / REQUEST CHANGES / FAIL

### Issues Found
1. ...
```
