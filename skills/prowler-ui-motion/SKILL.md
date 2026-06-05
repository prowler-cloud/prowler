---
name: prowler-ui-motion
description: >
  Prowler UI visible microinteraction rules for shadcn primitives, forms, tabs, expandable rows, status states, and motion QA.
  Trigger: Creating/modifying UI motion, transitions, animations, microinteractions, Radix/shadcn primitives, or interactive table rows.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Creating/modifying UI motion"
    - "Creating/modifying microinteractions"
    - "Creating/modifying shadcn primitives"
    - "Creating/modifying expandable rows"
---

## When to Use

Use this skill before adding or changing visible UI motion in Prowler: shadcn/Radix primitives, form controls, overlays, tabs, expandable rows, table affordances, status badges, progress, spinners, skeleton handoffs, and icon-only actions.

## Critical Patterns

- Prefer shadcn/Tailwind motion; do not add new HeroUI motion surfaces.
- Motion must be visible, not theoretical: use durations humans can perceive (`200ms–700ms` depending on scope).
- Preserve Radix state semantics; animate via classes, force-mounted indicators, `data-state`, or `asChild` wrappers without breaking accessibility.
- Always include `motion-reduce` behavior for transform/animation-heavy changes.
- Opening and closing must both animate when the component supports unmount/exit behavior.
- Keep row/background transitions separate from control/checkmark transitions; do not couple table selection backgrounds to checkbox internals.
- Avoid feature-local motion copies when a shared primitive owns the interaction.
- For skeleton/loading handoffs, load `prowler-ui-skeletons` and follow its boundary/reveal rules.

## Decision Gates

| Surface                                             | Required motion contract                                                           |
| --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Dialog, Drawer, Popover, Dropdown, Select, Combobox | Enter and exit motion; preserve focus/portal behavior.                             |
| Tabs                                                | Content switch should fade/slide; inactive panels must not flash.                  |
| Checkbox, Radio, pills, badges                      | Background/icon/content state changes should transition together.                  |
| Input, SearchInput, Textarea, Dropzone              | Focus border, clear button, placeholder/selection affordances need visible timing. |
| Collapsible, Tree, expandable table row             | Expand and collapse must both animate height/opacity/chevron.                      |
| StatusBadge, Progress, Spinner                      | State/color/value changes should feel smooth and respect reduced motion.           |
| Data table affordances                              | Row hover/selection may animate, but do not break table layout semantics.          |

## Execution Steps

1. Identify whether the interaction belongs to a shared primitive or a feature-local surface.
2. Add the smallest shared motion primitive that covers the behavior.
3. Verify enter and exit paths, including closed/unmounted states.
4. Add focused unit tests for shared primitives or reusable motion contracts.
5. Provide at least one real UI route/flow where the user can visually test the motion.

## Commands

```bash
cd ui && pnpm run typecheck
cd ui && pnpm test:unit <focused-test-files>
```

## Resources

- `skills/prowler-ui-skeletons/SKILL.md` — skeleton scanner and content reveal rules.
- `skills/prowler-ui/SKILL.md` — component placement and shadcn vs HeroUI rules.
