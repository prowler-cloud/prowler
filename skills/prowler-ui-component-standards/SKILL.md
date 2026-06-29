---
name: prowler-ui-component-standards
description: "Trigger: creating, modifying, or reviewing Prowler UI components, modals, selects, buttons, styles, colors, scans page UI, providers page UI. Enforce shadcn component reuse and design-token discipline."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke:
    - "Creating/modifying Prowler UI components"
    - "Reviewing Prowler UI components"
    - "Working with Prowler UI modals, selects, buttons, or colors"
---

## Activation Contract

Use this skill before creating, modifying, or reviewing Prowler UI components, especially modals, selects, buttons, tables, filters, scans UI, providers UI, and styling.

Do not use this skill for backend/API-only work.

## Hard Rules

- Use only `import { Modal } from "@/components/shadcn/modal"` for modal UI. Do not create custom modal wrappers or one-off modal primitives.
- Use `components/shadcn/select/select` for selectors. If a new visual style is required, add a supported variant/size API to the original select component instead of extending it ad hoc at the call site.
- Follow the `Button` pattern: variants, sizes, tones, disabled styling, icon styling, and semantic visual states belong in the shared shadcn component API, not scattered class overrides.
- Do not pass custom visual `className` overrides to reusable primitives such as `Button`, `SelectTrigger`, `SelectItem`, modal controls, badges, or similar shared controls. For example, do not write `className="text-text-success-primary opacity-80 disabled:opacity-60"` on a button/select at the feature call site. Add or extend a shared `variant`, `size`, `tone`, or semantic prop on the component instead.
- Do not invent raw Tailwind colors such as `border-orange-600/70`, `bg-blue-950/40`, or hardcoded color utilities in feature components.
- Always reuse existing design tokens from `global.css` for colors. If no existing token clearly fits, stop and ask the developer/design owner what semantic token to use or add; do not invent new colors or near-duplicate tokens on your own.
- Do not add new HeroUI usage. Use shadcn + Tailwind tokens.
- Do not inline custom component behavior when equivalent UI exists in scans or providers pages.

## Decision Gates

| Situation                                                                        | Action                                                                                                               |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Need modal                                                                       | Use `@/components/shadcn/modal`; inspect scans/providers modal usage first                                           |
| Need select visual variant                                                       | Add/extend variant or size in `components/shadcn/select/select`, then consume it                                     |
| Need button visual variant, tone, icon color, disabled opacity, or CTA emphasis  | Add/extend `components/shadcn/button/button` variant/size/tone API, then consume it without call-site visual classes |
| Need select visual variant, tone, item color, trigger opacity, or disabled style | Add/extend `components/shadcn/select/select`, then consume it without call-site visual classes                       |
| Need color                                                                       | Reuse an existing `global.css` token; if no token clearly fits, ask the developer/design owner before adding one     |
| Reviewing UI PR                                                                  | Flag custom modals, raw color utilities, ad hoc select classes, and duplicated scans/providers patterns              |

## Execution Steps

1. Inspect existing scans/providers UI for comparable modal/select/button patterns before writing new UI.
2. Search shared shadcn components for supported variants and sizes.
3. If missing, update the shared component API first with a semantic variant/size/tone prop.
4. Search `global.css` for existing semantic color tokens and reuse them. If no existing token clearly matches the intended meaning, stop and ask the developer/design owner before adding a token.
5. Keep feature components consuming component variants and tokens only; do not use call-site `className` for colors, opacity, hover/focus/disabled states, or status styling on shared controls.
6. Add or update tests for behavior; visual class changes should be covered through stable component API where practical.

## Output Contract

Report:

- Shared component APIs reused or extended.
- Existing `global.css` tokens reused, or the developer-approved new token if one was explicitly requested.
- Scans/providers references checked.
- Any remaining raw Tailwind color utilities, call-site visual `className` overrides on shared controls, or custom modal/select patterns.

## References

- `ui/app/(prowler)/scans/`
- `ui/app/(prowler)/providers/`
- `ui/components/shadcn/modal`
- `ui/components/shadcn/select/select.tsx`
- `ui/components/shadcn/button/button.tsx`
- `ui/styles/global.css`
