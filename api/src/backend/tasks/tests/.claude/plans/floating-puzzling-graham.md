# Plan: fix changelog PR number + cover the real name-refresh path

## Context

PR #11476 (`fix/api-store-resource-name-PROWLER-1937`) fixes resources keeping an empty
`name` on re-scans. Two surviving review findings need fixing:

1. **Changelog points to the wrong PR.** The entry links to `#11937`, but this PR is
   `#11476` (the Jira ticket number PROWLER-1937 leaked into the PR number).
2. **The real fix has no test.** A live scan only runs `_process_finding_micro_batch`;
   `_store_resources` is dead (only tests call it). The PR's new tests exercise
   `_store_resources`, while the name-refresh branch in the micro-batch path
   (`scan.py:721-726`) is never run by any test. Codecov confirms 2 uncovered patch lines,
   matching exactly those two lines.

Out of scope (left as the open question on the PR): deleting `_store_resources`. Not touched here.

## Changes

### 1. `api/CHANGELOG.md` (line 21)
Replace both the number and the URL: `#11937` → `#11476`,
`/pull/11937` → `/pull/11476`.

### 2. `api/src/backend/tasks/tests/test_scan.py`
Add one focused test to `TestProcessFindingMicroBatch` (after the
`test_process_finding_micro_batch_manual_mute_and_dirty_resources` test, ~line 1699),
modeled on it but minimal:

`test_process_finding_micro_batch_refreshes_empty_resource_name`
- Create an existing `Resource` with `name=""` (the actual bug: an old resource with an
  empty name), put it in `resource_cache`.
- Build a `FakeFinding` (PASS, simpler) whose `resource_name` is a real non-empty value
  and whose `resource_uid` matches the existing resource.
- Call `_process_finding_micro_batch` with the same cache args / `noop_rls_transaction`
  patches used by the neighbouring tests.
- Assert, after `existing_resource.refresh_from_db()`, that
  `existing_resource.name == finding.resource_name`.

This drives the `if finding.resource_name and resource_instance.name != ...` branch
(empty → real name differs) and proves the new `"name"` entry in `bulk_update` persists it.

## Verification

Per the user's instruction, do NOT run linters or tests and do NOT commit. Manual check only:
the new test follows the exact call signature and patching of the existing micro-batch tests,
and asserts the field the PR is meant to fix.

(For reference, the test would normally be run with:
`poetry run pytest src/backend/tasks/tests/test_scan.py -k refreshes_empty_resource_name` from `api/`.)
