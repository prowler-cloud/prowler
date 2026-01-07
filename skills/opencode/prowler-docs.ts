
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-docs
description: Prowler documentation style guide and writing standards. Covers brand voice, SEO optimization, technical writing patterns, and MDX components.
license: Apache 2.0
---

## When to use this skill

Use this skill when writing Prowler documentation for:
- Feature documentation
- API/SDK references
- Tutorials and guides
- Release notes

## Brand Voice

### Unbiased Communication
- Avoid gendered pronouns (use "you/your" or "they/them")
- Use inclusive alternatives: businessman -> businessperson, mankind -> humanity
- No generalizations about gender, race, nationality, culture
- Avoid militaristic language: fight -> address, kill chain -> cyberattack chain

### Technical Terminology
- Define key terms and acronyms on first use: "Identity and Access Management (IAM)"
- Prefer verbal over nominal constructions: "The report was created" not "The creation of the report"
- Use clear, accessible language; minimize jargon

## Formatting Standards

### Title Case Capitalization
Use Title Case for all headers:
- Good: "How to Configure Security Scanning"
- Bad: "How to configure security scanning"

### Hyphenation
- Prenominal position: "world-leading company"
- Postnominal position: "features built in"

### Bullet Points
Use when information can be logically divided:
\`\`\`markdown
Prowler CLI includes:
* **Industry standards:** CIS, NIST 800, NIST CSF
* **Regulatory compliance:** RBI, FedRAMP, PCI-DSS
* **Privacy frameworks:** GDPR, HIPAA, FFIEC
\`\`\`

### Interaction Verbs
- Desktop: Click, Double-click, Right-click, Drag, Scroll
- Touch: Tap, Double-tap, Press and hold, Swipe, Pinch

## SEO Optimization

### Sentence Structure
Place keywords at the beginning:
- Good: "To create a custom role, open a terminal..."
- Bad: "Open a terminal to create a custom role..."

### Headers
- H1: Primary (unique, descriptive)
- H2-H6: Subheadings (logical hierarchy)
- Include keywords naturally

## MDX Components

### Version Badge
\`\`\`mdx
import { VersionBadge } from "/snippets/version-badge.mdx"

## New Feature Name

<VersionBadge version="4.5.0" />

Description of the feature...
\`\`\`

### Warnings and Danger Calls
\`\`\`mdx
<Warning>
Disabling encryption may expose sensitive data to unauthorized access.
</Warning>

<Danger>
Running this command will **permanently delete all data**.
</Danger>
\`\`\`

## Prowler Features (Proper Nouns)

Reference without articles:
- Prowler App, Prowler CLI, Prowler SDK
- Prowler Cloud, Prowler Studio, Prowler Registry
- Built-in Compliance Checks
- Multi-cloud Security Scanning
- Autonomous Cloud Security Analyst (AI)

## Documentation Structure

\`\`\`
docs/
├── getting-started/
├── tutorials/
├── providers/
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── ...
├── api/
├── sdk/
├── compliance/
└── developer-guide/
\`\`\`

## Keywords
prowler docs, documentation, technical writing, seo, mdx, style guide
`;

export default tool({
  description: SKILL,
  args: {
    doc_type: tool.schema.string().describe("Documentation type: feature, tutorial, api-reference, guide"),
    topic: tool.schema.string().describe("Topic being documented"),
  },
  async execute(args) {
    return `
Prowler Documentation Pattern for: ${args.doc_type} - ${args.topic}

File location: docs/{category}/${args.topic}.mdx

Structure for "${args.doc_type}":

${args.doc_type === 'feature' ? `
## ${args.topic}

<VersionBadge version="X.X.X" />

Brief description of what this feature does.

### Prerequisites
- Bullet point prerequisites

### Configuration
Step-by-step configuration instructions.

### Usage
\`\`\`bash
# Example command
prowler aws --feature-flag
\`\`\`

### Examples
Practical examples with expected output.

### Related
- Link to related documentation
` : args.doc_type === 'tutorial' ? `
## How to ${args.topic}

Learn how to accomplish X in Y minutes.

### What You'll Learn
- Learning objective 1
- Learning objective 2

### Prerequisites
- Required knowledge/tools

### Steps

#### Step 1: Description
Detailed instructions...

#### Step 2: Description
Detailed instructions...

### Verification
How to confirm success.

### Next Steps
Links to advanced topics.
` : args.doc_type === 'api-reference' ? `
## ${args.topic} API

### Endpoint
\`GET /api/v1/${args.topic}\`

### Authentication
Bearer token required.

### Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| param1    | string | Yes | Description |

### Response
\`\`\`json
{
  "data": {...}
}
\`\`\`

### Errors
| Code | Description |
|------|-------------|
| 400  | Bad request |
| 404  | Not found   |
` : `
## ${args.topic} Guide

### Overview
What this guide covers.

### Key Concepts
Explain fundamental concepts.

### Best Practices
Recommended approaches.

### Troubleshooting
Common issues and solutions.
`}

Remember:
- Title Case for headers
- Keywords at sentence beginnings
- Define acronyms on first use
- Use bullet points for lists
- Add Version Badge for new features
    `.trim()
  },
})
