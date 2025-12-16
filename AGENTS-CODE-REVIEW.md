# Prowler Code Review Rules

**AI-powered code review rules for the Prowler monorepo.**

## Component-Specific Guidelines

For detailed rules, refer to each component's AGENTS.md:

- **UI (TypeScript/React)**: `ui/AGENTS.md`
- **SDK (Python)**: `prowler/AGENTS.md`
- **MCP Server (Python)**: `mcp_server/AGENTS.md`
- **General Guidelines**: `AGENTS.md`

---

## Critical Rules - All Components

### General

- **NO hardcoded secrets**: Use environment variables or secure credential management
- **NO `any` types**: Always use proper typing (TypeScript) or type hints (Python)
- **Conventional commits**: Follow `<type>[scope]: <description>` format
- **DRY principle**: No code duplication - extract to shared utilities
- **Error handling**: Never let errors crash silently; log and handle gracefully

---

## TypeScript/React Rules (ui/)

### Imports

- ✅ `import { useState, useEffect } from "react"`
- ❌ `import React` or `import * as React`

### Types

- ✅ `const STATUS = { ACTIVE: "active" } as const; type Status = typeof STATUS[keyof typeof STATUS]`
- ❌ `type Status = "active" | "inactive"` (union types)

### Styling

- ✅ `className="bg-slate-800 text-white"` (Tailwind classes)
- ✅ `className={cn(baseStyles, isActive && "opacity-100")}` (conditional with cn())
- ❌ `var()` in className strings
- ❌ Hex colors like `#fff` (use Tailwind semantic classes)
- Exception: `var()` is allowed for chart/graph components that require CSS color strings

### React 19 Patterns

- ❌ `useMemo`, `useCallback` - React Compiler handles optimization
- ✅ Server components by default, `"use client"` only when needed
- ✅ `"use server"` for server actions

### Zod v4

- ✅ `z.email()` not `z.string().email()`
- ✅ `z.uuid()` not `z.string().uuid()`
- ✅ `z.string().min(1)` not `z.string().nonempty()`

### File Organization

- Used in 1 place → keep local in feature directory
- Used in 2+ places → move to `components/shared/`, `lib/`, `types/`, or `hooks/`

### Components

- Use components from `components/shadcn/` when possible
- Implement DRY, KISS principles (reusable components, avoid repetition)

### Responsive Design

- Layout must work for all responsive breakpoints (mobile, tablet, desktop)
- Use Tailwind responsive prefixes: `sm:`, `md:`, `lg:`, `xl:`

### Accessibility

- All images must have `alt` text
- Interactive elements need `aria` labels
- Use semantic HTML elements

---

## Python Rules (prowler/, mcp_server/)

### Style

- **PEP 8 compliance**: Enforced by black and flake8
- **Type hints**: Required for all public functions
- **Docstrings**: Required for all classes and public methods
- **Import order**: standard library → third party → local (use isort)

### Type Hints

```python
# ✅ Correct
def process(data: dict) -> list[str] | None:
    pass

# ❌ Incorrect - missing type hints
def process(data):
    pass
```

### Error Handling

```python
# ✅ Correct - specific exception handling with logging
from prowler.lib.logger import logger

try:
    result = api_call()
except SpecificException as e:
    logger.error(f"API error: {e}")
    # Graceful handling
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    # Never let checks crash the entire scan
```

### Prowler SDK Checks

All security checks must:

1. Inherit from `Check` base class
2. Implement `execute()` method returning `list[CheckReport]`
3. Set `report.status` to `"PASS"` or `"FAIL"`
4. Provide descriptive `status_extended` message
5. Have corresponding `.metadata.json` file

### MCP Server Tools

- Extend `BaseTool` for Prowler App tools (auto-registration)
- Use `@mcp.tool()` decorator for Hub/Docs tools
- Use `MinimalSerializerMixin` for LLM-optimized responses
- Implement `from_api_response()` for API transformations

---

## Response Format

**Your response MUST start with exactly one of:**

```
STATUS: PASSED
```

or

```
STATUS: FAILED
```

**If FAILED**, list each violation with:

- File path
- Line number (if applicable)
- Rule violated
- Brief explanation

**If PASSED**, confirm all files comply with the coding standards.
