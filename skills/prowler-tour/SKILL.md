---
name: prowler-tour
description: >
  Keeps product-tour definitions aligned with the UI features they describe.
  Trigger: When modifying UI components that have associated tours, editing tour
  definition files, or renaming data-tour-id attributes.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Editing a UI file containing data-tour-id attributes"
    - "Adding, updating, or removing a tour definition (*.tour.ts)"
    - "Renaming or removing a data-tour-id attribute value"
    - "Changing button labels or section headings on a tour-covered page"
    - "Restructuring routes or layouts covered by a tour"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

# prowler-tour

Keeps product-tour definitions under `ui/lib/tours/*.tour.ts` aligned with the
UI surfaces they describe. **Report-only in v1.** This skill never edits tour
files; it reports the drift it finds and recommends actions.

## Early-exit rule

Run this check first. Most UI edits are not tour-related — exit cheaply.

1. Glob `ui/lib/tours/*.tour.ts`.
2. For each tour, check whether any `coversFiles` glob pattern matches any
   file in the current change.
3. If no tour matches, respond **exactly**:

   > No tour affected — skipping alignment check

   and exit. Do not proceed to the checklist.
4. If at least one tour matches, continue to "Drift checklist" for that tour.

## Drift checklist

For each affected tour, evaluate every item. Skip items that obviously do
not apply, but state clearly which ones you checked.

1. **Orphan selectors** — every step's `target` (which composes to
   `data-tour-id="<tour-id>-<step.target>"`) must resolve to a real element
   in the codebase. Grep `ui/` for the expected attribute value; report
   any step whose target is missing.
2. **Renamed selectors** — a `data-tour-id` attribute was edited in this
   change. Match it back to any tour step referencing the old value.
3. **Outdated copy** — a popover `title`/`description` references a button
   label, heading, or term that no longer exists on the covered page.
4. **Obsolete steps** — a step describes a section, panel, or workflow
   that was removed.
5. **Missing steps** — a new feature was added on the covered surface
   without a corresponding step (e.g. a new panel, a new primary action,
   a new wizard stage).
6. **Reordered flow** — the user's path through the feature changed (e.g.
   query builder moved before scan selection) and the step order no
   longer reflects it.

## Version-bump decision tree

Apply per tour after listing drift:

- **NO bump** when the change is cosmetic. Examples: fix a typo, soften
  copy, rename a `data-tour-id` selector while keeping the same step,
  swap one screenshot for another, tighten wording.
- **BUMP `version`** when the user-visible flow changes materially.
  Examples: a new step was added or removed; the order changed; an
  anchored target was retargeted to a different panel; the tour now
  covers a new feature on the surface.

When in doubt, ask: "Would a user who already saw the previous version
miss something useful by not seeing this one?" If yes, bump.

## Mandatory output format

Use this exact structure. Skipping fields or reordering them prevents
the report from being machine-readable downstream.

```
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

If multiple tours are affected, emit one report per tour, separated by `---`.

If no drift is detected for an affected tour, still emit the report with
"No drift detected." under "Drift detected" and "None required." under
"Recommended actions". The verdict line is still mandatory.

## What this skill MUST NOT do (v1)

- Do not edit `*.tour.ts` files. The skill is report-only until the
  report-only mode proves itself in practice.
- Do not edit UI files to add or rename `data-tour-id` attributes.
- Do not invent new tours. Authoring a new tour is a separate, deliberate
  decision — the developer makes it, not the skill.
- Do not flag drift in tours whose `coversFiles` do not match any file
  in the current change. Stick to the early-exit rule.

## See also

- `references/tours-architecture.md` — design context and links to the
  abstraction layer source.
- `assets/tour-template.ts` — boilerplate for authoring a new `*.tour.ts`.
