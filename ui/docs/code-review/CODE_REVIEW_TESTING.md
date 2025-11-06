# Code Review - Testing Guide

Guide to test that validation works correctly.

## Test 1: Validation Disabled (Default)

### Configuration
```bash
# In .env
CODE_REVIEW_ENABLED=false
```

### Expected Result
```bash
$ git commit -m "test: something"

🚀 Prowler UI - Pre-Commit Hook
ℹ️  Code Review Status: false

⏭️  Code review disabled (CODE_REVIEW_ENABLED=false)

# Commit continues ✅
```

**✅ Test passed:** Validation is skipped when disabled.

---

## Test 2: Enable Validation

### Configuration
```bash
# In .env
CODE_REVIEW_ENABLED=true
```

### Create test file with violation

```bash
# Create a temporary file with an error
cat > /tmp/test-violation.tsx << 'EOF'
import * as React from "react";  // ❌ Violation: Incorrect React import
import { useState } from "react";

export function MyComponent() {
  const [count, setCount] = useState(0);
  return <div>{count}</div>;
}
EOF

# Copy to project
cp /tmp/test-violation.tsx ui/components/test-violation.tsx
git add ui/components/test-violation.tsx
git commit -m "test: violation for testing"
```

### Expected Result
```bash
🚀 Prowler UI - Pre-Commit Hook
ℹ️  Code Review Status: true

🔍 Running Claude Code standards validation...

📋 Files to validate:
  - components/test-violation.tsx

📤 Sending to Claude Code...

=== VALIDATION REPORT ===
STATUS: FAILED

- File: components/test-violation.tsx:1
  Rule: React Imports
  Issue: Using 'import * as React from "react"' - should use named imports only
  Expected: import { useState } from "react"

❌ VALIDATION FAILED

Fix violations before committing
```

**✅ Test passed:** Validation detects violations and blocks the commit.

---

## Test 3: Fix Violation

### Fix the file
```bash
# Edit the file
cat > ui/components/test-violation.tsx << 'EOF'
import { useState } from "react";  // ✅ Correct

export function MyComponent() {
  const [count, setCount] = useState(0);
  return <div>{count}</div>;
}
EOF

git add ui/components/test-violation.tsx
git commit -m "fix: correct React imports"
```

### Expected Result
```bash
🔍 Running Claude Code standards validation...

📋 Files to validate:
  - components/test-violation.tsx

📤 Sending to Claude Code...

=== VALIDATION REPORT ===
STATUS: PASSED
All files comply with AGENTS.md standards.

✅ VALIDATION PASSED

# Commit successful ✅
```

**✅ Test passed:** After fixing, the commit executes normally.

---

## Test 4: Clean Up

```bash
# Remove the test file
git rm ui/components/test-violation.tsx
git commit -m "test: remove test-violation file"
```

---

## Test 5: Validation with Bypass (Optional)

To verify that the bypass works:

```bash
# Force commit without validation
git commit --no-verify

# ⚠️ WARNING: This skips ALL hooks
```

**✅ Test passed:** The `--no-verify` flag allows skipping hooks when necessary.

---

## Real-World Test Cases

### Case 1: Tailwind CSS Violation

```bash
# ❌ Wrong
className="bg-[var(--color-bg)]"

# ✅ Correct
className="bg-card-bg"
```

### Case 2: Type Pattern Violation

```bash
# ❌ Wrong
type Status = "active" | "inactive" | "pending"

# ✅ Correct
const STATUS = {
  ACTIVE: "active",
  INACTIVE: "inactive",
  PENDING: "pending",
} as const
type Status = typeof STATUS[keyof typeof STATUS]
```

### Case 3: cn() Misuse

```bash
# ❌ Wrong
className={cn("flex items-center")}

# ✅ Correct
className={cn("h-3 w-3", isActive ? "bg-blue" : "bg-gray")}
```

### Case 4: React Hook Violation

```bash
// ❌ Wrong
const memoized = useMemo(() => heavyComputation(), [])

// ✅ Correct
const result = heavyComputation()  // React 19 Compiler optimizes automatically
```

---

## Testing Checklist

- [ ] Test 1: Validation disabled → commit normal ✅
- [ ] Test 2: Validation active with error → commit blocked ✅
- [ ] Test 3: Fix error → commit successful ✅
- [ ] Test 4: Clean up test files ✅
- [ ] Test 5: Bypass with --no-verify works ✅
- [ ] Claude Code available in PATH ✅
- [ ] Hook is executable (chmod +x) ✅

---

## Troubleshooting

### Error: "claude-code: command not found"

```bash
# Check installation
which claude-code

# If not found, add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Error: Hook doesn't run

```bash
# Verify it's executable
ls -la .husky/pre-commit
# Should show: -rwxr-xr-x

# If not, make it executable
chmod +x .husky/pre-commit
```

### Error: Build fails after validation

```bash
# Validation passed but build failed
# Fix the build errors:
npm run build

# Then try committing again
git commit
```

---

## For CI/CD (Future)

This system is for local validation. In the future you could add:

```bash
# In GitHub Actions
- Run: npm run code-review:ci
# Validates all files in the PR against standards
```
