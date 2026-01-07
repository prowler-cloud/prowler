
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler
description: Main entry point for Prowler development. Quick reference for all components, commands, and patterns across the monorepo.
license: Apache 2.0
---

## When to use this skill

Use this skill as your starting point for any Prowler development task. It provides quick access to all component patterns and commands.

## Project Overview

Prowler is an open-source cloud security assessment tool. The monorepo contains:

| Component | Tech Stack | Location |
|-----------|------------|----------|
| SDK | Python 3.9+, Poetry 2+ | \`prowler/\` |
| API | Django 5.1.x, DRF 3.15.x, Celery 5.4.x | \`api/\` |
| UI | Next.js 15, React 19, Tailwind 4 | \`ui/\` |
| MCP Server | FastMCP 2.13.1, Python 3.12+ | \`mcp_server/\` |
| Docs | MDX, Mintlify | \`docs/\` |
| Dashboard | Dash, Plotly | \`dashboard/\` |

## Specialized Skills

Use these skills for component-specific guidance:
- \`prowler-sdk-check\`: Create security checks
- \`prowler-api\`: Django/DRF patterns (RLS, serializers, views)
- \`prowler-ui\`: Next.js 15 + React 19 patterns
- \`prowler-mcp\`: MCP server tools and models
- \`prowler-compliance\`: Compliance frameworks
- \`prowler-provider\`: Cloud provider architecture
- \`prowler-test\`: Testing patterns for all components
- \`prowler-docs\`: Documentation style guide

## Quick Commands

### SDK
\`\`\`bash
poetry install --with dev && poetry run pre-commit install
poetry run python prowler-cli.py aws --check iam_user_mfa_enabled
poetry run pytest -n auto -vvv tests/
\`\`\`

### API
\`\`\`bash
cd api && poetry install --with dev
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run celery -A config.celery worker -l INFO
cd api && poetry run pytest
\`\`\`

### UI
\`\`\`bash
cd ui && pnpm install && pnpm run dev
cd ui && pnpm run typecheck && pnpm run lint:fix
cd ui && pnpm run test:e2e
\`\`\`

### MCP Server
\`\`\`bash
cd mcp_server && uv run prowler-mcp
cd mcp_server && uv run prowler-mcp --transport http --port 8000
\`\`\`

### Docker (Full Stack)
\`\`\`bash
docker-compose up -d        # Production
docker-compose -f docker-compose-dev.yml up -d  # Development
\`\`\`

## Commit Conventions

Follow conventional-commit style:
- \`feat:\` New feature
- \`fix:\` Bug fix
- \`docs:\` Documentation only
- \`chore:\` Build/auxiliary tools
- \`perf:\` Performance improvement
- \`refactor:\` Code change (no fix/feature)
- \`test:\` Adding/correcting tests

## Key Patterns

### SDK: Check Implementation
\`\`\`python
class check_name(Check):
    def execute(self) -> list[CheckReportProvider]:
        findings = []
        for resource in service_client.resources:
            report = CheckReportProvider(metadata=self.metadata(), resource=resource)
            report.status = "PASS" if compliant else "FAIL"
            findings.append(report)
        return findings
\`\`\`

### API: RLS Pattern
\`\`\`python
with rls_transaction(tenant_id):
    resources = Resource.objects.filter(provider=provider)
\`\`\`

### UI: Server Action
\`\`\`typescript
"use server";
export async function action(formData: FormData) {
  const validated = schema.parse(Object.fromEntries(formData));
  await db.update(validated);
  revalidatePath("/path");
}
\`\`\`

### MCP: BaseTool
\`\`\`python
class FeatureTools(BaseTool):
    async def list_items(self) -> dict:
        response = await self.api_client.get("/api/v1/items")
        return SimplifiedItem.from_api_response(response).model_dump()
\`\`\`

## Supported Cloud Providers

AWS, Azure, GCP, Kubernetes, GitHub, M365, OCI, AlibabaCloud, MongoDB Atlas, IaC

## Keywords
prowler, cloud security, aws, azure, gcp, kubernetes, compliance, security scanning
`;

export default tool({
  description: SKILL,
  args: {
    component: tool.schema.string().optional().describe("Component: sdk, api, ui, mcp, docs (optional - shows all if not specified)"),
    action: tool.schema.string().optional().describe("Action: commands, patterns, structure (optional)"),
  },
  async execute(args) {
    const componentInfo = {
      sdk: {
        path: "prowler/",
        stack: "Python 3.9+, Poetry 2+, pytest",
        commands: [
          "poetry install --with dev",
          "poetry run python prowler-cli.py {provider}",
          "poetry run pytest tests/",
        ],
      },
      api: {
        path: "api/",
        stack: "Django 5.1.x, DRF, Celery 5.4.x, PostgreSQL",
        commands: [
          "cd api && poetry install --with dev",
          "cd api && poetry run python src/backend/manage.py runserver",
          "cd api && poetry run pytest",
        ],
      },
      ui: {
        path: "ui/",
        stack: "Next.js 15, React 19, Tailwind 4, Playwright",
        commands: [
          "cd ui && pnpm install && pnpm run dev",
          "cd ui && pnpm run healthcheck",
          "cd ui && pnpm run test:e2e",
        ],
      },
      mcp: {
        path: "mcp_server/",
        stack: "FastMCP 2.13.1, Python 3.12+, httpx",
        commands: [
          "cd mcp_server && uv run prowler-mcp",
          "cd mcp_server && uv run prowler-mcp --transport http",
        ],
      },
      docs: {
        path: "docs/",
        stack: "MDX, Mintlify",
        commands: [
          "mintlify dev",
        ],
      },
    };

    if (args.component && componentInfo[args.component as keyof typeof componentInfo]) {
      const info = componentInfo[args.component as keyof typeof componentInfo];
      return `
Prowler ${args.component.toUpperCase()} Component

Path: ${info.path}
Stack: ${info.stack}

Commands:
${info.commands.map(c => `  ${c}`).join('\n')}

For detailed patterns, use: prowler-${args.component}
      `.trim();
    }

    return `
Prowler Monorepo Quick Reference

Components:
- SDK (prowler/): Python security scanning engine
- API (api/): Django REST backend
- UI (ui/): Next.js frontend
- MCP (mcp_server/): AI agent tools
- Docs (docs/): Documentation

Use specialized skills for detailed guidance:
- prowler-sdk-check: Security check implementation
- prowler-api: Django/DRF patterns
- prowler-ui: React/Next.js patterns
- prowler-mcp: MCP server tools
- prowler-compliance: Framework mapping
- prowler-provider: Provider architecture
- prowler-test: Testing patterns
- prowler-docs: Documentation style

Quick start:
  poetry install --with dev  # SDK
  cd api && poetry install   # API
  cd ui && pnpm install      # UI
  docker-compose up -d       # Full stack
    `.trim();
  },
})
