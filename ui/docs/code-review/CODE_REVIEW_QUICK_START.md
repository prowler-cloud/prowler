# Code Review - Quick Start

## 3 Steps to Enable

### 1. Open `.env`
```bash
nano ui/.env
# or your favorite editor
```

### 2. Find this line
```bash
CODE_REVIEW_ENABLED=false
```

### 3. Change it to
```bash
CODE_REVIEW_ENABLED=true
```

**Done! ✅**

---

## What Happens Now

Every time you `git commit`:

```
✅ If your code complies with AGENTS.md standards:
   → Commit executes normally

❌ If there are standard violations:
   → Commit is BLOCKED
   → You see the errors in the terminal
   → Fix the code
   → Commit again
```

---

## Example

```bash
$ git commit -m "feat: add new component"

🏁 Prowler UI - Pre-Commit Hook

ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

📋 Files to validate:
  - components/my-feature.tsx

📤 Sending to Claude Code for validation...

STATUS: FAILED
- File: components/my-feature.tsx:45
  Rule: React Imports
  Issue: Using 'import * as React'
  Expected: import { useState } from "react"

❌ VALIDATION FAILED
Fix violations before committing

# Fix the file and commit again
$ git commit -m "feat: add new component"

🏁 Prowler UI - Pre-Commit Hook

ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

✅ VALIDATION PASSED

# Commit successful ✅
```

---

## Disable Temporarily

If you need to commit without validation:

```bash
# Option 1: Change in .env
CODE_REVIEW_ENABLED=false

# Option 2: Bypass (use with caution!)
git commit --no-verify
```

---

## What Gets Validated

- ✅ Correct React imports
- ✅ TypeScript patterns (const-based types)
- ✅ Tailwind CSS (no var() or hex in className)
- ✅ cn() utility (only for conditionals)
- ✅ No useMemo/useCallback without reason
- ✅ Zod v4 syntax
- ✅ File organization
- ✅ Directives "use client"/"use server"

---

## More Info

Read `CODE_REVIEW_SETUP.md` for:
- Troubleshooting
- Complete details
- Advanced configuration
