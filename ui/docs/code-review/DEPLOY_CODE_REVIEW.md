# Deploy Code Review System

Instructions for setting up the Code Review system in Prowler UI.

## Summary

An automatic validation system has been implemented that:

- ✅ Validates code against AGENTS.md standards before committing
- ✅ Uses Claude Code (already in your PATH)
- ✅ Only validates files being committed
- ✅ Can be easily enabled/disabled with an environment variable
- ✅ Blocks commits if there are violations (exit code 1)

## Changes Made

### 1. File: `ui/.env`

Added configuration block:

```bash
#### Code Review Configuration ####
# Enable Claude Code standards validation on pre-commit hook
# Set to 'true' to validate changes against AGENTS.md standards via Claude Code
# Set to 'false' to skip validation
CODE_REVIEW_ENABLED=false
```

**Why `false` by default:**
- Doesn't interrupt current workflow
- Developers can enable when they want
- Avoids unexpected blocks

### 2. File: `ui/.husky/pre-commit`

Completely rewritten with validation logic:

```bash
#!/bin/bash
# Reads .env
# If CODE_REVIEW_ENABLED=true:
#   - Gets files being committed
#   - Builds prompt with file contents
#   - Sends to `claude-code` CLI
#   - Parses response for "STATUS: PASSED" or "STATUS: FAILED"
#   - If FAILED → exit 1 (blocks commit)
#   - If PASSED → continues
```

### 3. Documentation: `CODE_REVIEW_QUICK_START.md`

Quick guide for developers:
- 3 steps to enable
- Usage examples
- How to disable if needed

### 4. Documentation: `CODE_REVIEW_SETUP.md`

Complete guide:
- Detailed installation
- How the flow works
- What exactly gets validated
- Troubleshooting
- Advanced configuration

### 5. Documentation: `CODE_REVIEW_TESTING.md`

Testing guide:
- How to test each component
- Real test cases
- Troubleshooting

## Installation

### For Developers

1. **Open `ui/.env`**

2. **Find this line** (around line 174):
   ```bash
   CODE_REVIEW_ENABLED=false
   ```

3. **Change to:**
   ```bash
   CODE_REVIEW_ENABLED=true
   ```

4. **Save the file**

5. **Next commit will validate automatically:**
   ```bash
   git commit -m "feat: new feature"

   # If CODE_REVIEW_ENABLED=true, you'll see:
   🔍 Running Claude Code standards validation...
   ```

### For Leads/Maintainers

**No additional setup is needed.** The system is ready to use.

Just verify:
```bash
# The hook must be executable
ls -la .husky/pre-commit
# Should show: -rwxr-xr-x

# If not, run:
chmod +x .husky/pre-commit
```

## How It Works

### Standard Flow (Disabled - Default)

```
git commit
  ↓
Pre-commit hook runs
  ↓
CODE_REVIEW_ENABLED=false
  ↓
Skip validation
  ↓
Commit ✅
```

### Flow with Validation (Enabled)

```
git commit
  ↓
Pre-commit hook runs
  ↓
CODE_REVIEW_ENABLED=true
  ↓
Get files being committed
  ↓
Build prompt with code
  ↓
claude-code < prompt.txt
  ↓
Claude analyzes code
  ↓
Returns: STATUS: PASSED or STATUS: FAILED
  ↓
If PASSED:
  Commit ✅

If FAILED:
  Show violations
  exit 1
  Commit BLOCKED ❌
```

## What Gets Validated

The system is configured to detect violations of:

1. **React Imports**
   - ❌ `import * as React`
   - ✅ `import { useState }`

2. **TypeScript Type Patterns**
   - ❌ `type Status = "a" | "b"`
   - ✅ `const STATUS = {...} as const`

3. **Tailwind CSS**
   - ❌ `className="bg-[var(...)]"`
   - ✅ `className="bg-card-bg"`

4. **cn() Utility**
   - ❌ `className={cn("static")}`
   - ✅ `className={cn("h-3", isActive && "bg-blue")}`

5. **React 19 Hooks**
   - ❌ `useMemo()` without reason
   - ✅ No useMemo (React Compiler handles it)

6. **Zod v4 Syntax**
   - ❌ `z.string().email()`
   - ✅ `z.email()`

7. **File Organization**
   - ❌ Shared code in feature-specific folder
   - ✅ Following The Scope Rule

8. **Directives**
   - ❌ Server Action without `"use server"`
   - ✅ Proper directives

## Exit Codes (For CI/CD)

The pre-commit script returns:

```bash
exit 0  # ✅ Commit allowed (validation passed or disabled)
exit 1  # ❌ Commit blocked (validation failed)
```

This allows it to be used in:
- GitHub Actions
- GitLab CI
- Other CI/CD systems

## Disable Temporarily

```bash
# Option 1: Change in .env
CODE_REVIEW_ENABLED=false

# Option 2: Bypass (skips all hooks)
git commit --no-verify

# Option 3: Disable the hook temporarily
chmod -x .husky/pre-commit
git commit
chmod +x .husky/pre-commit
```

## Troubleshooting

### "claude-code: command not found"

```bash
# Check where Claude Code is installed
which claude-code

# If not found, add to ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"

# Reload:
source ~/.zshrc
```

### Hook doesn't run

```bash
# Verify it's executable
ls -la .husky/pre-commit

# Should show: -rwxr-xr-x
# If not, run:
chmod +x .husky/pre-commit
```

### Validation inconclusive

If Claude's analysis doesn't return clear status:
- Commit is allowed automatically
- Warning shown in terminal
- Developer can review manually

## For The Team

**Recommendation:**

1. **During development:** `CODE_REVIEW_ENABLED=false`
   - Iterate faster
   - Build check still runs

2. **Before final commit:** `CODE_REVIEW_ENABLED=true`
   - Verify you meet standards
   - Prevent PRs rejected for violations

3. **In CI/CD (future):** Add server-side validation
   ```bash
   # GitHub Actions could run:
   npm run code-review:ci
   ```

## Available Documentation

After this implementation, there are 5 documents:

1. **CODE_REVIEW_QUICK_START.md** ← Read first
2. **CODE_REVIEW_SETUP.md** ← For details
3. **CODE_REVIEW_TESTING.md** ← For testing
4. **DEPLOY_CODE_REVIEW.md** ← This document
5. **IMPLEMENTATION_SUMMARY.md** ← For a quick summary

## Next Steps

### Short Term
- [ ] Review generated files
- [ ] Test with `CODE_REVIEW_ENABLED=true`
- [ ] Share documentation with team

### Medium Term
- [ ] Gather feedback from developers
- [ ] Adjust validation rules if needed
- [ ] Consider making it standard before commits

### Long Term
- [ ] Add validation in CI/CD
- [ ] Integrate with GitHub/GitLab for auto-comments
- [ ] Expand validation suite

## Technical Summary

```
┌─────────────────────────────────────────┐
│  .env                                   │
│  CODE_REVIEW_ENABLED=true/false         │
└────────────────┬────────────────────────┘
                 │
                 ↓
    ┌──────────────────────────────┐
    │  .husky/pre-commit           │
    │  (bash script)               │
    │                              │
    │  1. Read CODE_REVIEW_ENABLED │
    │  2. If true:                 │
    │     - git diff --cached      │
    │     - cat files              │
    │     - claude-code < prompt   │
    │     - grep STATUS            │
    │     - exit 0/1               │
    │  3. exit                     │
    └──────────────────────────────┘
                 │
                 ↓
        ┌────────────────────┐
        │  Shell Exit Code   │
        │  0 = OK ✅         │
        │  1 = BLOCKED ❌    │
        └────────────────────┘
```

## Support

If you have questions:
1. Read CODE_REVIEW_QUICK_START.md (start here)
2. Read CODE_REVIEW_SETUP.md (technical details)
3. Read CODE_REVIEW_TESTING.md (testing)
4. Check AGENTS.md (standards being validated)

---

**Status:** ✅ Complete implementation and ready to use.

Enable when the team is ready.
