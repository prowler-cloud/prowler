---
name: prowler-docs
description: >
  Prowler documentation style guide and writing standards.
  Trigger: When writing documentation for Prowler features, tutorials, or guides.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## When to Use

Use this skill when writing Prowler documentation for:
- Feature documentation
- API/SDK references
- Tutorials and guides
- Release notes

## Brand Voice

### Unbiased Communication
- Avoid gendered pronouns (use "you/your" or "they/them")
- Use inclusive alternatives: businessman → businessperson, mankind → humanity
- No generalizations about gender, race, nationality, culture
- Avoid militaristic language: fight → address, kill chain → cyberattack chain

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
```markdown
Prowler CLI includes:
* **Industry standards:** CIS, NIST 800, NIST CSF
* **Regulatory compliance:** RBI, FedRAMP, PCI-DSS
* **Privacy frameworks:** GDPR, HIPAA, FFIEC
```

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
```mdx
import { VersionBadge } from "/snippets/version-badge.mdx"

## New Feature Name

<VersionBadge version="4.5.0" />

Description of the feature...
```

### Warnings and Danger Calls
```mdx
<Warning>
Disabling encryption may expose sensitive data to unauthorized access.
</Warning>

<Danger>
Running this command will **permanently delete all data**.
</Danger>
```

## Prowler Features (Proper Nouns)

Reference without articles:
- Prowler App, Prowler CLI, Prowler SDK
- Prowler Cloud, Prowler Studio, Prowler Registry
- Built-in Compliance Checks
- Multi-cloud Security Scanning
- Autonomous Cloud Security Analyst (AI)

## Documentation Structure

```
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
```

## Keywords
prowler docs, documentation, technical writing, seo, mdx, style guide
