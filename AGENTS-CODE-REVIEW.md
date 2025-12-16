# Code Review Rules

## References

- UI details: `ui/AGENTS.md`
- SDK details: `prowler/AGENTS.md`
- MCP details: `mcp_server/AGENTS.md`

---

## ALL FILES

REJECT if:

- Hardcoded secrets/credentials
- `any` type (TypeScript) or missing type hints (Python)
- Code duplication (violates DRY)
- Silent error handling (no logging)

---

## TypeScript/React (ui/)

REJECT if:

- `import React` or `import * as React` → use `import { useState }`
- Union types `type X = "a" | "b"` → use `const X = {...} as const`
- `var()` or hex colors in className → use Tailwind classes
- `useMemo` or `useCallback` without justification (React 19 Compiler)
- `z.string().email()` → use `z.email()` (Zod v4)
- `z.string().nonempty()` → use `z.string().min(1)` (Zod v4)
- Missing `"use client"` in client components
- Missing `"use server"` in server actions
- Images without `alt` attribute
- Interactive elements without `aria` labels
- Non-semantic HTML when semantic exists

PREFER:

- `components/shadcn/` over custom components
- `cn()` for conditional/merged classes
- Local files if used 1 place, `components/shared/` if 2+
- Responsive classes: `sm:`, `md:`, `lg:`, `xl:`

EXCEPTION:

- `var()` allowed in chart/graph component props (not className)

---

## Python (prowler/, mcp_server/)

REJECT if:

- Missing type hints on public functions
- Missing docstrings on classes/public methods
- Bare `except:` without specific exception
- `print()` instead of `logger`

REQUIRE for SDK checks:

- Inherit from `Check`
- `execute()` returns `list[CheckReport]`
- `report.status` = `"PASS"` | `"FAIL"`
- `.metadata.json` file exists

REQUIRE for MCP tools:

- Extend `BaseTool` (auto-registration)
- `MinimalSerializerMixin` for responses
- `from_api_response()` for API transforms

---

## Response Format

FIRST LINE must be exactly:

```
STATUS: PASSED
```

or

```
STATUS: FAILED
```

If FAILED, list: `file:line - rule - issue`
