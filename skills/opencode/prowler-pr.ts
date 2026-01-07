
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-pr
description: Creates Pull Requests for Prowler following the project template and conventions. Use when creating PRs, submitting changes, or opening pull requests.
license: Apache 2.0
---

## When to use this skill

Use this skill when you need to create a Pull Request for Prowler. It ensures the PR follows the project template and includes all required sections.

## PR Template

The PR must follow the template at \`.github/pull_request_template.md\`:

### Required Sections

1. **Context**: Why this change? Link issues with \`Fix #XXXX\`
2. **Description**: Summary of changes and dependencies
3. **Steps to review**: How to test/verify
4. **Checklist**: Component-specific items
5. **License**: Apache 2.0 confirmation

### Component Checklists

**SDK Changes:**
- New checks? → Update permissions?
- Tests covering code
- Docstrings following Google style
- Backport needed?
- CHANGELOG: \`prowler/CHANGELOG.md\`

**UI Changes:**
- Screenshots: Mobile (<640px), Tablet (640-1024px), Desktop (>1024px)
- CHANGELOG: \`ui/CHANGELOG.md\`

**API Changes:**
- API specs regeneration
- Version updates
- CHANGELOG: \`api/CHANGELOG.md\`

## Title Convention

Use conventional commits: \`feat:\`, \`fix:\`, \`docs:\`, \`chore:\`, \`refactor:\`, \`test:\`

## Commands

\`\`\`bash
# Analyze changes
git diff main...HEAD
git log main..HEAD --oneline

# Create PR
gh pr create --title "type: description" --body "..."

# Create draft
gh pr create --draft
\`\`\`

## Keywords
prowler pr, pull request, gh, github, contribution
`;

export default tool({
  description: SKILL,
  args: {
    component: tool.schema.string().describe("Affected component(s): sdk, api, ui, mcp, docs, or 'all'"),
    type: tool.schema.string().describe("PR type: feat, fix, docs, chore, refactor, test"),
    title: tool.schema.string().describe("Short description for PR title"),
    issue: tool.schema.string().optional().describe("Issue number to link (without #)"),
  },
  async execute(args) {
    const components = args.component.toLowerCase().split(',').map(c => c.trim());

    const sdkChecklist = components.includes('sdk') || components.includes('all') ? `
- Are there new checks included in this PR? Yes / No
    - If so, do we need to update permissions for the provider?
- [ ] Review if the code is being covered by tests.
- [ ] Review if code is documented (Google style)
- [ ] Review if backport is needed.
- [ ] Review if Readme.md needs changes
- [ ] CHANGELOG: prowler/CHANGELOG.md updated` : '';

    const uiChecklist = components.includes('ui') || components.includes('all') ? `

#### UI
- [ ] All requirements work as expected
- [ ] Screenshots - Mobile (X < 640px)
- [ ] Screenshots - Tablet (640px > X < 1024px)
- [ ] Screenshots - Desktop (X > 1024px)
- [ ] CHANGELOG: ui/CHANGELOG.md updated` : '';

    const apiChecklist = components.includes('api') || components.includes('all') ? `

#### API
- [ ] API specs regenerated (if needed)
- [ ] Version updates checked
- [ ] CHANGELOG: api/CHANGELOG.md updated` : '';

    const issueRef = args.issue ? `Fix #${args.issue}` : '{Link issue with Fix #XXXX}';

    return `
PR Template for: ${args.type}: ${args.title}

## Commands to create this PR:

\`\`\`bash
# First, check your changes
git status
git diff main...HEAD

# Create PR
gh pr create --title "${args.type}: ${args.title}" --body "$(cat <<'EOF'
### Context

${issueRef}

{Add motivation and context}

### Description

{Summary of changes}

### Steps to review

1. {Step 1}
2. {Step 2}

### Checklist
${sdkChecklist}${uiChecklist}${apiChecklist}

### License

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.
EOF
)"
\`\`\`

## Pre-PR Checklist:
- [ ] Tests pass locally
- [ ] Linting passes
- [ ] CHANGELOG(s) updated
- [ ] Branch up to date with main
    `.trim();
  },
})
