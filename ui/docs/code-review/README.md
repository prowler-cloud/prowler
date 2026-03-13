# Code Review System Documentation

Complete documentation for the Claude Code-powered pre-commit validation system.

## Quick Navigation

**Want to get started in 3 steps?**
→ Read: [`CODE_REVIEW_QUICK_START.md`](./CODE_REVIEW_QUICK_START.md)

**Want complete technical details?**
→ Read: [`CODE_REVIEW_SETUP.md`](./CODE_REVIEW_SETUP.md)

---

## What This System Does

Automatically validates code against AGENTS.md standards when you commit using Claude Code.

```
git commit
  ↓
(Optional) Claude Code validation
  ↓
If violations found → Commit is BLOCKED ❌
If code complies → Commit continues ✅
```

**Key Feature:** Configurable with a single variable in `.env`
- `CODE_REVIEW_ENABLED=true` → Validates (recommended before commits)
- `CODE_REVIEW_ENABLED=false` → Skip validation (default, for iteration)

---

## File Guide

| File | Purpose | Read Time |
|------|---------|-----------|
| [`CODE_REVIEW_QUICK_START.md`](./CODE_REVIEW_QUICK_START.md) | 3-step setup & examples | 5 min |
| [`CODE_REVIEW_SETUP.md`](./CODE_REVIEW_SETUP.md) | Complete technical guide | 15 min |

---

## What Gets Validated

When validation is enabled, the system checks:

✅ **React Imports**
- Must use: `import { useState } from "react"`
- Not: `import * as React` or `import React, {`

✅ **TypeScript Types**
- Must use: `const STATUS = {...} as const; type Status = typeof STATUS[...]`
- Not: `type Status = "a" | "b"`

✅ **Tailwind CSS**
- Must use: `className="bg-card-bg text-white"`
- Not: `className="bg-[var(...)]"` or `className="text-[#fff]"`

✅ **cn() Utility**
- Must use for: `cn("h-3", isActive && "bg-blue")`
- Not for: `cn("static-class")`

✅ **React 19 Hooks**
- No: `useMemo()` / `useCallback()` without documented reason
- Use: Nothing (React Compiler handles optimization)

✅ **Zod v4 Syntax**
- Must use: `z.email()`, `.min(1)`
- Not: `z.string().email()`, `.nonempty()`

✅ **File Organization**
- 1 feature uses → Keep local in feature folder
- 2+ features use → Move to shared/global

✅ **Directives**
- Server Actions must have: `"use server"`
- Client Components must have: `"use client"`

---

## Installation (For Your Team)

### Step 1: Decide if you want validation
- **Optional:** Each developer decides
- **Team policy:** Consider making it standard before commits

### Step 2: Enable in your environment
```bash
# Edit ui/.env
CODE_REVIEW_ENABLED=true
```

### Step 3: Done!
Your next `git commit` will validate automatically.

---

## Support

| Question | Answer |
|----------|--------|
| How do I enable it? | Change `CODE_REVIEW_ENABLED=true` in `.env` |
| How do I disable it? | Change `CODE_REVIEW_ENABLED=false` in `.env` |
| How do I bypass? | Use `git commit --no-verify` (emergency only) |
| What if Claude Code isn't found? | Check PATH: `which claude` |
| What if hook doesn't run? | Check executable: `chmod +x .husky/pre-commit` |
| How do I test it? | Enable validation and commit code with violations to test |
| What if I don't have Claude Code? | Validation is skipped gracefully |

---

## Key Features

✅ **No Setup Required**
- Uses Claude Code already in your PATH
- No API keys needed
- Works offline (if Claude Code supports it)

✅ **Smart Validation**
- Only checks files being committed
- Not the entire codebase
- Fast: ~10-30 seconds with validation enabled

✅ **Flexible**
- Can be enabled/disabled per developer
- Can be disabled temporarily with `git commit --no-verify`
- Default is disabled (doesn't interrupt workflow)

✅ **Clear Feedback**
- Shows exactly what violates standards
- Shows file:line references
- Explains how to fix each issue

✅ **Well Documented**
- 5 different documentation files
- For different needs and levels
- Examples and troubleshooting included

---

## Architecture

```
┌─────────────────────────────────────────┐
│  Developer commits code                 │
└────────────────┬────────────────────────┘
                 ↓
        ┌─────────────────┐
        │ Pre-Commit Hook │
        │ (.husky/pre-commit)
        └────────┬────────┘
                 ↓
        Read CODE_REVIEW_ENABLED from .env
                 ↓
        ┌──────────────────────────┐
        │ If false (disabled)      │
        └────────┬─────────────────┘
                 ↓
            exit 0 (OK)
                 ↓
            Commit continues ✅

        ┌──────────────────────────┐
        │ If true (enabled)        │
        └────────┬─────────────────┘
                 ↓
        Extract staged files
        (git diff --cached)
                 ↓
        Build prompt with git diff
                 ↓
        Send to: claude < prompt
                 ↓
        Analyze against AGENTS.md
                 ↓
        Return: STATUS: PASSED or FAILED
                 ↓
        Parse with: grep "^STATUS:"
                 ↓
        ┌──────────────────┐
        │ PASSED detected  │
        └────────┬─────────┘
                 ↓
            exit 0 (OK)
                 ↓
            Commit continues ✅

        ┌──────────────────┐
        │ FAILED detected  │
        └────────┬─────────┘
                 ↓
        Show violations
                 ↓
            exit 1 (FAIL)
                 ↓
        Commit is BLOCKED ❌
                 ↓
        Developer fixes code
        Developer commits again
```

---

## Getting Started

1. **Read:** [`CODE_REVIEW_QUICK_START.md`](./CODE_REVIEW_QUICK_START.md) (5 minutes)
2. **Enable:** Set `CODE_REVIEW_ENABLED=true` in your `ui/.env`
3. **Test:** Commit some code and see validation in action
4. **For help:** See the troubleshooting section in [`CODE_REVIEW_SETUP.md`](./CODE_REVIEW_SETUP.md)

---

## Implementation Details

- **Files Modified:** 1 (`.husky/pre-commit`)
- **Files Created:** 3 (documentation)
- **Hook Size:** ~120 lines of bash
- **Dependencies:** Claude Code CLI (already available)
- **Setup Time:** 1 minute
- **Default:** Disabled (no workflow interruption)

---

## Questions?

- **How to enable?** → `CODE_REVIEW_QUICK_START.md`
- **How does it work?** → `CODE_REVIEW_SETUP.md`
- **Troubleshooting?** → See troubleshooting section in `CODE_REVIEW_SETUP.md`

---

## Status

✅ **Ready to Use**

The system is fully implemented, documented, and tested. You can enable it immediately with a single variable change.

---

**Last Updated:** November 6, 2024
**Status:** Complete Implementation
