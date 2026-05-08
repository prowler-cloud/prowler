---
name: tailwind-4
description: "Trigger: When styling with Tailwind CSS 4, especially in `className`, variant composition, `cn()`, or dynamic-value decisions. Enforces Tailwind-first styling rules and escape hatches."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, ui]
  auto_invoke: "Working with Tailwind classes"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill when UI styling decisions involve Tailwind class composition, semantic theme usage, or choosing between `className`, `cn()`, and inline styles.

## Hard Rules

- Prefer Tailwind utility classes directly in `className` for static styling.
- Do not put `var(...)` expressions inside `className`; use semantic Tailwind tokens or inline styles where needed.
- Do not use hex colors in class strings; use theme or Tailwind palette classes.
- Use `cn()` only when conditional or merge behavior is real.
- Use inline `style` only for truly dynamic values or third-party APIs that cannot consume class names.

## Decision Gates

| Question | Action |
|---|---|
| Static styling only? | Use plain `className="..."`. |
| Conditional or override-prone classes? | Use `cn(...)`. |
| Dynamic numeric or percentage values? | Use the `style` prop. |
| Third-party library prop cannot accept classes? | Pass CSS custom property values or inline style constants. |
| Need a one-off dimension not in the design system? | Use an arbitrary value sparingly, but never for colors. |

## Execution Steps

1. Classify the styling need as static, conditional, dynamic, or third-party-only.
2. Prefer semantic Tailwind utilities and theme tokens first.
3. Introduce `cn()` only if merge logic or conditions justify it.
4. Move dynamic measurements or library-only values into `style` constants.
5. Replace color escape hatches with palette or theme classes.
6. Review the final markup and remove unnecessary wrappers or styling indirection.

## Output Contract

- State which styling path was chosen: plain `className`, `cn()`, or inline `style`.
- Call out any removed anti-pattern such as `var(...)` in `className` or hex colors.
- Mention any remaining escape hatch and why it was necessary.

## References

- [Prowler UI skill](../prowler-ui/SKILL.md)
- [React 19 skill](../react-19/SKILL.md)
- [Repository agent rules](../../AGENTS.md)
