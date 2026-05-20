---
name: framework-compliance-triage
description: Make a cloud account compliant with a security or industry framework using Prowler Cloud.
---

# Framework compliance

Iterative, interactive flow that takes a cloud account through setup, reporting, and remediation until it complies with the chosen security or industry framework.

## 1. Initial Prowler Cloud setup

Ask the user which provider and framework to target, then confirm both are supported by the Prowler Hub MCP:

- Enumerate supported providers with `prowler_hub_list_providers`.
- Enumerate frameworks for the chosen provider with `prowler_hub_list_compliances`, passing the provider `id` as the only element of the `provider` input list.

If the framework is not supported, tell the user, suggest they request it or contribute it themselves, and end the flow. Otherwise continue.

### 1.1 Connect to Prowler Cloud

Verify the Prowler MCP connection by calling `prowler_app_search_providers` — a successful response returns the list of providers. If the call fails, walk the user through troubleshooting: internet connectivity, Prowler Cloud credentials, and permissions on the Prowler Cloud account.
For getting accurate information about configurations use `prowler_docs_search` to pull relevant instructions from the Prowler documentation.

### 1.2 Verify the provider is configured (or configure it)

Call `prowler_app_search_providers` to check whether the target provider (AWS account, Azure Subscription, GitHub Account...) exists in the user's Prowler Cloud account. Handle the result based on what's found:

- **Provider not present.** Guide the user through adding and configuring it. Retrieve the relevant connection, credential, and permission instructions with `prowler_docs_search`.
- **Provider present but misconfigured** (missing credentials, insufficient permissions, etc.). Walk the user through fixing the configuration, pulling the relevant guidance with `prowler_docs_search`.
- **Provider present and configured.** If multiple accounts are configured for the same provider, list them with helpful detail (account name, ID, last scan date) and ask which to use. If only one is configured, use it without prompting.

### 1.3 Review compliance report for the provider account

The flow needs at least one completed scan with a compliance report available.

Look for a completed scan first: call `prowler_app_list_scans` with the selected `provider_id` and `state: ["completed"]`, then call `prowler_app_get_compliance_overview` with each `scan_id` to find one whose compliance report is available. If one is found, continue to the next section.

If no completed scan has a report, call `prowler_app_list_scans` again with `state: ["available", "executing"]` to detect a scan in progress. If one exists, tell the user and ask whether to wait or start a new one.

Otherwise, trigger a new scan with `prowler_app_trigger_scan` and the `provider_id`. Warn the user it may take time. When the scan completes, restart this section to re-check the results.

If the scan is in progress or just started, stop the flow and ask the user to return when it's completed. Optionally, provide a link to the Prowler Cloud console where they can monitor the scan's progress. The link looks like `https://cloud.prowler.com/scans?filter%5Bprovider_uid__in%5D={provider_id}`.

## 2. Compliance report

Every iteration of the remediation loop reads and writes a single markdown file per provider account and framework, stored at `${CLAUDE_PROJECT_DIR}/.prowler/compliance-<compliance_id>-<provider_uid>.md`. Sanitize `<provider_uid>` to `[a-zA-Z0-9_-]` by replacing anything else with `-`. Create `.prowler/` if missing.

Across iterations, edit only: status tags on failed requirements and their findings, the per-requirement `Fix plan` / `Fix applied` sub-bullets added during sections 3.2–3.3, the **Global remediation approach** block, and the **Activity log** (append-only, newest on top). Requirement descriptions, finding IDs, and the entire **Manual review requirements** section are read-only after first render.

Status taxonomy for failed requirements and their findings:

- `[FAIL]` — failing in the latest scan.
- `[IN PROGRESS]` — picked up by section 3.2.
- `[FIXED-UNVERIFIED]` — remediation applied; not yet confirmed.
- `[PASS]` — passing in the latest scan (set when a rescan in section 3.4 confirms the fix).
- `[SKIPPED]` — user explicitly deferred.

### Report template

A fresh report is rendered like this (substituting values from the `prowler_app_get_compliance_framework_state_details` Prowler MCP tool response):

````markdown
# Compliance report: <compliance_id>

**Provider account**: <display name + uid>
**Scan ID**: <scan_id>
**Generated**: <ISO timestamp>
**Last update**: <ISO timestamp>
**Status**: <passed>/<total> passing (<pct>%) · <failed> failing · <manual_review> manual review

## Global remediation approach
<!-- Filled by section 3.1. -->
- **Primary tool**: _Terraform | Azure CLI | AWS CLI | web console | mixed_
- **Mode**: _Claude autonomous | Claude-assisted_
- **Notes**:

## Activity log
- <ISO timestamp> — Report initialized from scan `<scan_id>`.

## Failed requirements

### <code> — [FAIL]
**Description**: <text>
**Findings** (<n>):
- [FAIL] `<finding_id>`

## Manual review requirements
- **<code>** — [PENDING]: <description>
````

### 2.1 Generate or refresh the report

Resolve the report path for the current `compliance_id` and provider account.

If the file does not exist, call `prowler_app_get_compliance_framework_state_details` for the target scan, render the template above, and write the file with one initialization entry in the activity log.

If the file exists, read it and compare its `Scan ID` to the target scan from section 1.3. When the scan matches, reuse the file and summarize remaining `[FAIL]` and `[IN PROGRESS]` items in chat. When the scan differs, ask the user whether to refresh — on confirmation, regenerate the failed-requirements section from the new tool response, carry forward the **Global remediation approach** block and the full activity log, and append an activity-log entry noting the scan change.

Once the file is current, surface the top failing requirements in chat: sort by finding count descending, show the top 5 with their codes and counts, and point to the file path for the full list.

## 3. Remediation loop

### 3.1 Define the global remediation approach

Ask the user which tool to use for fixes (Terraform, Azure CLI, AWS CLI, web console, mixed...) and whether Claude should remediate autonomously or step by step alongside them. Write the answers into the **Global remediation approach** block of the report file. If the block is already populated from a previous session, confirm with the user before overwriting.

### 3.2 Pick the first FAIL requirement and inspect its findings

Pick the first `[FAIL]` requirement at the top of the failed-requirements section. Move its status and every finding under it to `[IN PROGRESS]`, and add a `**Fix plan**:` sub-bullet describing what will be done.

Call `prowler_app_get_finding_details` for each `finding_id` to retrieve the failing resource and the Prowler Hub's remediation guidance for that check using the tool `prowler_hub_get_check_details` with the `check_id` from the finding details. Summarize the guidance in chat, and append it to the `**Fix plan**` note for each finding.

### 3.3 Diagnose and fix

Read the remediation guidance returned in 3.2, identify the root cause, and apply the fix using the tool defined in the `**Global remediation approach**` section. Append a `**Fix applied**: <tool, summary, refs>` sub-bullet to the requirement, move each fixed finding to `[FIXED-UNVERIFIED]`, and add one activity-log entry describing the change.

### 3.4 Loop

Move to the next `[FAIL]` requirement and repeat from section 3.2. When no `[FAIL]` requirements remain (all are `[FIXED-UNVERIFIED]` or `[SKIPPED]`), trigger a fresh scan with `prowler_app_trigger_scan` to verify the fixes end-to-end. When the new scan completes, restart section 2.1 with the carry-forward path — requirements no longer in the new FAIL list move to `[PASS]`, anything still failing reverts to `[FAIL]` with the previous fix attempt visible in the activity log.
