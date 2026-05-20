---
name: framework-compliance-triage
description: Make a cloud account compliant with a security or industry framework using Prowler Cloud.
---

# Framework compliance

Iterative, interactive flow that takes a cloud account through setup, reporting, and remediation until it complies with the chosen security or industry framework.

## Checkpoints

This skill uses **checkpoints** to mark moments where you must stop, post a clear question or summary to the user, and wait for the reply before continuing. Each checkpoint is rendered like this:

> **Checkpoint — <name>**
>
> What to present, and what to wait for.

Treat every checkpoint as a hard stop:

- Do not skip a checkpoint because the user previously said "go ahead", "just do it", or similar. Confirmations are scoped to a single checkpoint and do not transfer to later ones.
- Do not bundle two checkpoints into one message. Post one, wait for the reply, then continue.
- Do not infer the user's answer from context or proceed on silence. Ask explicitly and wait.
- If a checkpoint is conditional (e.g. only fires when multiple accounts exist), evaluate the condition first; if it does not apply, continue without prompting.
- If the user's initial message already answers the question a checkpoint asks (e.g. "make my AWS subscription compliant with CIS using Terraform autonomously"), treat the checkpoint as satisfied for the parts they covered, and only ask for what is still missing.

## 1. Initial Prowler Cloud setup

> **Checkpoint — Provider and framework selection**
>
> If the user has not already specified both the provider and the framework, ask explicitly and wait for the answer. If they have specified them in their opening message, skip this checkpoint.

Confirm both are supported by the Prowler Hub MCP:

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
- **Provider present and configured.** Continue.

> **Checkpoint — Account selection** *(conditional: more than one account of the chosen provider is configured)*
>
> List the accounts with helpful detail (account name, uid, last scan date) and ask which one to use. Wait for the answer. If only one account exists, skip this checkpoint and use it.

### 1.3 Review compliance report for the provider account

The flow needs at least one completed scan with a compliance report available.

Look for a completed scan first: call `prowler_app_list_scans` with the selected `provider_id` and `state: ["completed"]`, then call `prowler_app_get_compliance_overview` with each `scan_id` to find one whose compliance report is available. If one is found, continue to the next section.

If no completed scan has a report, call `prowler_app_list_scans` again with `state: ["available", "executing"]` to detect a scan in progress.

> **Checkpoint — Scan-in-progress decision** *(conditional: an in-progress scan was detected)*
>
> Tell the user a scan is already running and ask whether to wait for it to complete or start a fresh one. Wait for the answer.

If no scan is running (or the user chose to start a fresh one), trigger a new scan with `prowler_app_trigger_scan` and the `provider_id`. The link `https://cloud.prowler.com/scans?filter%5Bprovider_uid__in%5D={provider_id}` lets the user monitor progress.

When a scan is in progress (either pre-existing and elected to wait, or just triggered), stop the flow and ask the user to return when it's completed — restart this section to re-check the results.

## 2. Compliance report

Every iteration of the remediation loop reads and writes a single markdown file per provider account and framework, stored at `${CLAUDE_PROJECT_DIR}/.prowler/compliance-<compliance_id>-<provider_uid>.md`. Sanitize `<provider_uid>` to `[a-zA-Z0-9_-]` by replacing anything else with `-`. Create `.prowler/` if missing.

Across iterations, edit only: status tags on failed requirements and their findings, the per-requirement `Fix plan` / `Fix applied` sub-bullets added during sections 3.3–3.4, the **Global remediation approach** block, and the **Activity log** (append-only, newest on top). Requirement descriptions, finding IDs, and the entire **Manual review requirements** section are read-only after first render.

Status taxonomy for failed requirements and their findings:

- `[FAIL]` — failing in the latest scan.
- `[IN PROGRESS]` — picked up by section 3.3.
- `[FIXED-UNVERIFIED]` — remediation applied; not yet confirmed.
- `[PASS]` — passing in the latest scan (set when a rescan in section 3.5 confirms the fix).
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

If the file exists, read it and compare its `Scan ID` to the target scan from section 1.3. When the scan matches, reuse the file and summarize remaining `[FAIL]` and `[IN PROGRESS]` items in chat.

> **Checkpoint — Report refresh** *(conditional: the file's `Scan ID` differs from the current target scan)*
>
> Tell the user the report on disk was generated from a different scan and ask whether to refresh it from the new scan. Wait for the answer.

On confirmation, regenerate the failed-requirements section from the new `prowler_app_get_compliance_framework_state_details` response, carry forward the **Global remediation approach** block and the full activity log, and append an activity-log entry noting the scan change.

Once the file is current, surface the top failing requirements in chat: sort by finding count descending, show the top 5 with their codes and counts, and point to the file path for the full list.

## 3. Remediation loop

### 3.1 Define the global remediation approach

Two modes are available:

- **Claude-assisted** (default when the user has not specified): per-requirement confirmation. For each requirement Claude shows the target resource, exact commands, side effects, and reversibility, then waits for explicit go-ahead before applying.
- **Claude autonomous**: no per-requirement gate, but Claude still presents one batch-level fix plan up front (§3.2) and waits for a single confirmation, and pauses if a finding looks not applicable, requires a paid feature, or has wide blast radius (breaks dev workflow, forces collaborator changes, is hard to reverse).

If the user phrases their request as "just do it" or similar, treat that as autonomous **with** the batch-plan confirmation still required — the confirmation is a property of the skill, not the user's verbosity preference.

> **Checkpoint — Global remediation approach**
>
> Ask the user which tool to use for fixes (Terraform, gh / az / aws CLI, web console, mixed...) and which mode to operate in. Wait for the answer before continuing. This checkpoint is non-negotiable: never assume a default tool, and never assume autonomous mode.

Once answered, write the values into the **Global remediation approach** block of the report file.

> **Checkpoint — Overwriting an existing approach** *(conditional: the block is already populated from a previous session)*
>
> Show the previous values and the new ones, and ask the user to confirm before overwriting. Wait for the answer.

### 3.2 Present the batch fix plan *(autonomous mode only)*

In **assisted** mode, skip this section — the per-requirement gate in §3.3 confirms each fix as it comes up. Only run §3.2 in **autonomous** mode, where the loop will otherwise apply fixes without further input.

Before touching anything, post a single chat summary covering every `[FAIL]` requirement:

- Group findings that share a fix (e.g. ten branch-protection requirements satisfied by one PUT call → present as one group).
- For each group: target resource, exact tool calls, side effects, reversibility.
- Call out findings that look **not applicable** to this target (e.g. an Organization-only check evaluated against a User account, a feature gated by a paid plan, a resource type the user doesn't have) and propose `[SKIPPED]` with the reason.
- Call out findings that require manual user action Claude cannot perform.

> **Checkpoint — Batch fix plan approval** *(conditional: autonomous mode)*
>
> Post the grouped plan and wait for explicit confirmation. Do not start any fix before the user replies.

Once approved, the loop proceeds through the batch without further prompts unless something deviates from the approved plan.

### 3.3 Pick the first FAIL requirement and inspect its findings

Pick the first `[FAIL]` requirement at the top of the failed-requirements section. Move its status and every finding under it to `[IN PROGRESS]`, and add a `**Fix plan**:` sub-bullet describing what will be done.

Call `prowler_app_get_finding_details` for each `finding_id` to retrieve the failing resource and the Prowler Hub's remediation guidance for that check using the tool `prowler_hub_get_check_details` with the `check_id` from the finding details. Summarize the guidance in chat, and append it to the `**Fix plan**` note for each finding.

If a finding does not apply to the target resource (Organization-only check on a User account, paid-tier feature, missing resource type, etc.), set the requirement status to `[SKIPPED]` with the reason, log it in the activity log, and move on without attempting the fix — even if it was missed during §3.2.

> **Checkpoint — Per-requirement approval** *(conditional: assisted mode)*
>
> Post the per-requirement plan in chat — resource, command, side effects, reversibility — and wait for confirmation before moving to §3.4. In **autonomous** mode, post the plan for transparency but proceed unless it deviates from the batch plan agreed in §3.2.

### 3.4 Diagnose, fix, verify

Read the remediation guidance returned in §3.3, identify the root cause, and apply the fix using the tool defined in the **Global remediation approach** block. After applying, verify via the same tool that applied the fix or via a provider API call when applicable. If the re-read shows the change did not land, leave the status at `[IN PROGRESS]`, surface the error to the user, and stop the loop for this requirement.

When the change is in place, append a `**Fix applied**: <tool, summary, refs>` sub-bullet to the requirement, move each fixed finding to `[FIXED-UNVERIFIED]`, and add one activity-log entry describing the change. If no programmatic verification was possible (e.g. web console action), note in the activity log that confirmation depends on the rescan in §3.5.

### 3.5 Loop

Move to the next `[FAIL]` requirement and repeat from section 3.3.

> **Checkpoint — Rescan trigger** *(conditional: no `[FAIL]` requirements remain; all are `[FIXED-UNVERIFIED]` or `[SKIPPED]`)*
>
> Summarize what was applied, list any `[SKIPPED]` items with reasons, and ask whether to trigger a fresh scan with `prowler_app_trigger_scan` to verify the fixes end-to-end. Wait for the answer.

On confirmation, trigger the rescan. When it completes, restart section 2.1 with the carry-forward path — requirements no longer in the new FAIL list move to `[PASS]`, anything still failing reverts to `[FAIL]` with the previous fix attempt visible in the activity log.
