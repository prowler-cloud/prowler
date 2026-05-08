---
name: jsonapi
description: "Trigger: When creating or modifying API endpoints, reviewing API responses, or validating JSON:API behavior in Prowler. Enforces JSON:API v1.1 response, relationship, and media-type compliance."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0.0"
  scope: [root, api]
  auto_invoke:
    - "Creating API endpoints"
    - "Modifying API responses"
    - "Reviewing JSON:API compliance"
---

## Activation Contract

Use this skill when the task is about what the JSON:API contract MUST look like: document shape, media types, relationship linkage, sparse fields, includes, errors, and status-code semantics. Pair it with `django-drf` for implementation mechanics and `prowler-api` for Prowler tenant or provider rules.

## Hard Rules

- Never return `data` and `errors` in the same document.
- Always return JSON:API media types and document members consistent with the spec.
- Always model resource identifiers with string `id` values and kebab-case `type` values.
- Always represent relationships with JSON:API linkage objects, not raw foreign keys.
- Always emit error objects as an array and keep `status` as a string.
- Never hide spec violations behind framework defaults; verify the final payload shape.

## Decision Gates

| Question | Action |
|---|---|
| Are you designing endpoint structure or reviewing payload correctness? | Use this skill as the compliance authority. |
| Are you implementing DRF serializers/viewsets/filters too? | Load `django-drf` as a companion skill. |
| Does tenant visibility affect whether a resource should appear? | Load `prowler-api` too. |
| Is the change about relationship payloads or compound documents? | Validate linkage, `include`, and deduplication rules explicitly. |
| Is the response async or task-based? | Confirm status codes and response shape still satisfy JSON:API rules. |

## Execution Steps

1. Identify the document type involved: success, error, relationship update, compound document, or sparse fieldset response.
2. Check media type, top-level members, and status code semantics first.
3. Validate resource object shape: `type`, string `id`, `attributes`, and `relationships`.
4. Verify query parameter behavior for `include`, `fields`, `filter`, `sort`, and pagination.
5. Review error payloads for array shape, string status, and pointers when field-specific.
6. Hand implementation details back to `django-drf` once compliance constraints are clear.

## Output Contract

- State the JSON:API rule or family of rules that governs the task.
- Mention the endpoint or payload surface being validated.
- Name companion skills needed for implementation or tenant-aware behavior.
- Call out the concrete violation risk if the current shape is wrong.

## References

- [Repository agent rules](../../AGENTS.md)
- [API component guidance](../../api/AGENTS.md)
- [DRF implementation skill](../django-drf/SKILL.md)
- [Prowler API skill](../prowler-api/SKILL.md)
