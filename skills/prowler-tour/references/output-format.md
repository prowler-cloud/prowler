# Tour Alignment Report — output format

The report is consumed downstream. Field names, order, and headings are
load-bearing — do not rename, reorder, or omit them.

## Template

```text
## Tour Alignment Report
**Tour:** `<tour-id>@v<version>`
**Files touched:** <comma-separated list of files in the change>

### Drift detected
- <one bullet per drift item; include file:line where available>

### Recommended actions
1. <numbered, actionable steps the developer should take>

### Version bump verdict
- <BUMP | NO bump> — <one-line rationale>
```

## Rules

- One report per affected tour. If multiple tours are affected, separate
  reports with a `---` line.
- If no drift is detected for an affected tour, still emit the report:
  put "No drift detected." under "Drift detected" and "None required."
  under "Recommended actions". The verdict line is still mandatory.
- The verdict is exactly one of `BUMP` or `NO bump` — see the
  version-bump decision tree in `SKILL.md`.
