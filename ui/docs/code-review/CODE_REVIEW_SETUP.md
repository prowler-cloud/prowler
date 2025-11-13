# Code Review Setup - Prowler UI

Guide to set up automatic code validation with Claude Code in the pre-commit hook.

## Overview

The code review system works like this:

1. **When you enable `CODE_REVIEW_ENABLED=true` in `.env`**
   - When you `git commit`, the pre-commit hook runs
   - Only validates TypeScript/JavaScript files you're committing
   - Uses Claude Code to check if they comply with AGENTS.md
   - If there are violations → **BLOCKS the commit**
   - If everything is fine → Continues normally

2. **When `CODE_REVIEW_ENABLED=false` (default)**
   - The pre-commit hook does not run validation
   - No standards validation
   - Developers can commit without restrictions

## Installation

### 1. Ensure Claude Code is in your PATH

```bash
# Verify that claude is available in terminal
which claude

# If it doesn't appear, check your Claude Code CLI installation
```

### 2. Enable validation in `.env`

In `/ui/.env`, find the "Code Review Configuration" section:

```bash
#### Code Review Configuration ####
# Enable Claude Code standards validation on pre-commit hook
# Set to 'true' to validate changes against AGENTS.md standards via Claude Code
# Set to 'false' to skip validation
CODE_REVIEW_ENABLED=false  # ← Change this to 'true'
```

**Options:**
- `CODE_REVIEW_ENABLED=true` → Enables validation
- `CODE_REVIEW_ENABLED=false` → Disables validation (default)

### 3. The hook is ready

The `.husky/pre-commit` file already contains the logic. You don't need to install anything else.

## How It Works

### Normal Flow (with validation enabled)

```bash
$ git commit -m "feat: add new component"

# Pre-commit hook executes automatically
🚀 Prowler UI - Pre-Commit Hook
 ℹ️  Code Review Status: true

📋 Files to validate:
  - components/new-feature.tsx
  - types/new-feature.ts

📤 Sending to Claude Code for validation...

# Claude analyzes the files...

=== VALIDATION REPORT ===
STATUS: PASSED
All files comply with AGENTS.md standards.

✅ VALIDATION PASSED
# Commit continues ✅
```

### If There Are Violations

```bash
$ git commit -m "feat: add new component"

# Claude detects issues...

=== VALIDATION REPORT ===
STATUS: FAILED

- File: components/new-feature.tsx:15
  Rule: React Imports
  Issue: Using 'import * as React' instead of named imports
  Expected: import { useState } from "react"

❌ VALIDATION FAILED

Please fix the violations before committing:
  1. Review the violations listed above
  2. Fix the code according to AGENTS.md standards
  3. Commit your changes
  4. Try again

# Commit is BLOCKED ❌
```

## What Gets Validated

The system verifies that files comply with:

### 1. React Imports
```typescript
// ❌ WRONG
import * as React from "react"
import React, { useState } from "react"

// ✅ CORRECT
import { useState } from "react"
```

### 2. TypeScript Type Patterns
```typescript
// ❌ WRONG
type SortOption = "high-low" | "low-high"

// ✅ CORRECT
const SORT_OPTIONS = {
  HIGH_LOW: "high-low",
  LOW_HIGH: "low-high",
} as const
type SortOption = typeof SORT_OPTIONS[keyof typeof SORT_OPTIONS]
```

### 3. Tailwind CSS
```typescript
// ❌ WRONG
className="bg-[var(--color)]"
className="text-[#ffffff]"

// ✅ CORRECT
className="bg-card-bg text-white"
```

### 4. cn() Utility
```typescript
// ❌ WRONG
className={cn("flex items-center")}

// ✅ CORRECT
className={cn("h-3 w-3", isCircle ? "rounded-full" : "rounded-sm")}
```

### 5. React 19 Hooks
```typescript
// ❌ WRONG
const memoized = useMemo(() => value, [])

// ✅ CORRECT
// Don't use useMemo (React Compiler handles it)
const value = expensiveCalculation()
```

### 6. Zod v4 Syntax
```typescript
// ❌ WRONG
z.string().email()
z.string().nonempty()

// ✅ CORRECT
z.email()
z.string().min(1)
```

### 7. File Organization
```
// ❌ WRONG
Code used by 2+ features in feature-specific folder

// ✅ CORRECT
Code used by 1 feature → local in that feature
Code used by 2+ features → in shared/global
```

### 8. Use Directives
```typescript
// ❌ WRONG
export async function updateUser() { } // Missing "use server"

// ✅ CORRECT
"use server"
export async function updateUser() { }
```

## Disable Temporarily

If you need to commit without validation temporarily:

```bash
# Option 1: Change in .env
CODE_REVIEW_ENABLED=false
git commit

# Option 2: Use git hook bypass
git commit --no-verify

# Option 3: Disable the hook
chmod -x .husky/pre-commit
git commit
chmod +x .husky/pre-commit
```

**⚠️ Note:** `--no-verify` skips ALL hooks.

## Troubleshooting

### "Claude Code CLI not found"

```
⚠️ Claude Code CLI not found in PATH
To enable: ensure Claude Code is in PATH and CODE_REVIEW_ENABLED=true
```

**Solution:**
```bash
# Check where claude-code is installed
which claude-code

# If not found, add to your ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"  # or where it's installed

# Reload the terminal
source ~/.zshrc
```

### "Validation inconclusive"

If Claude Code cannot determine the status:

```
⚠️ Could not determine validation status
Allowing commit (validation inconclusive)
```

The commit is allowed automatically. If you want to be stricter, you can:

1. Manually review files against AGENTS.md
2. Report the analysis problem to Claude

### Build fails after validation

```
❌ Build failed
```

If validation passes but build fails:

1. Check the build error
2. Fix it locally
3. Commit and try again

## View the Full Report

Reports are saved in temporary files that are deleted afterward. To see the detailed report in real-time, watch the hook output:

```bash
git commit 2>&1 | tee commit-report.txt
```

This will save everything to `commit-report.txt`.

## For the Team

### Enable on your machine

```bash
cd ui
# Edit .env locally and set:
CODE_REVIEW_ENABLED=true
```

### Recommended Flow

1. **During development**: `CODE_REVIEW_ENABLED=false`
   - Iterate faster
   - Build check still runs

2. **Before final commit**: `CODE_REVIEW_ENABLED=true`
   - Verify you meet standards
   - Prevent PRs rejected for violations

3. **In CI/CD**: You could add additional validation
   - (future) Server-side validation in GitHub Actions

## Questions?

If you have questions about the standards being validated, check:
- `AGENTS.md` - Complete architecture guide
- `CLAUDE.md` - Project-specific instructions
