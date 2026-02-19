# AWS Organizations Bulk Account Connection - Implementation Plan

## Context

Prowler SaaS users currently add AWS accounts one at a time. This feature adds a modal-based wizard to bulk discover and connect all accounts in an AWS Organization. In OSS mode, the option appears disabled with a "Get Prowler Cloud" CTA. The backend API (PR #2826) is already merged.

**Spec:** `ui/docs/aws-organizations-bulk-connect.md`
**Figma:** OSS disabled `10248:3258` | Validate Connection `10160:2965` | Launch Scan `10004:102323`

---

## 1. Architecture: Modal-Based Wizard

The entire Organizations flow lives in a **modal dialog** (not separate pages). This is a self-contained wizard opened from the existing connect-account page.

**User journey:**
1. `/providers/connect-account` → Select AWS → See method selector (inline in existing form)
2. Click "Add Multiple Accounts With AWS Organizations" → **Opens `OrgWizardModal`**
3. Modal handles all remaining steps internally, closes on completion

**Modal internal steps** (4-step stepper):

| Step | Name | Content |
|------|------|---------|
| 1 ✓ | Link a Cloud Provider | Pre-completed (AWS + Organizations chosen on the page) |
| 2 | Authenticate Credentials | Org name, AWS Org ID, Role ARN, External ID form |
| 3 | Validate Connection | Discovery polling → Account selection → Apply → Connection testing |
| 4 | Launch Scan | Success summary, scan schedule dropdown, Launch Scan button |

**Step 3 sub-phases:**
- **Phase A — Discovery**: Polls `getDiscovery()` every 3s. Shows spinner + "Discovering your AWS Organization..."
- **Phase B — Account Selection**: TreeView with checkboxes + "Name (optional)" input fields. User selects accounts, enters aliases, clicks "Next"
- **Phase C — Apply + Test**: Calls `applyDiscovery()`, then `checkConnectionProvider()` for each created provider. TreeView updates with status icons (✓/✗). Buttons: "Back", "Skip Connection Validation", "Test Connections"

**Step 4 behavior:**
- Shows org name + UID badge
- "Accounts Connected!" with green check
- Scan schedule dropdown ("Scan Daily every 24 hours")
- "Done" → close modal, navigate to `/providers`
- "Launch Scan" → schedule scans for all providers → close modal → navigate to `/providers` → toast notification

---

## 2. File Structure

### New Files

```
ui/
├── types/organizations.ts                                  # Types + const enums
├── actions/organizations/
│   ├── organizations.ts                                    # Server actions (5 API calls)
│   └── organizations.adapter.ts                            # buildOrgTreeData(), helpers
├── store/organizations/
│   └── store.ts                                            # Zustand store (multi-step state)
├── components/providers/organizations/
│   ├── org-wizard-modal.tsx                                # Modal shell + stepper + step router
│   ├── org-wizard-stepper.tsx                              # 4-step vertical stepper (shadcn-based)
│   ├── aws-method-selector.tsx                             # "Single Account" vs "Organizations" radio
│   ├── org-setup-form.tsx                                  # Step 2: Org details form
│   ├── org-discovery-loader.tsx                            # Step 3 Phase A: Discovery polling spinner
│   ├── org-account-selection.tsx                           # Step 3 Phase B: Tree + checkboxes + names
│   ├── org-connection-test.tsx                             # Step 3 Phase C: Tree + status icons + test
│   ├── org-launch-scan.tsx                                 # Step 4: Success + scan schedule
│   └── org-account-tree-item.tsx                           # Custom renderItem for TreeView
```

### Modified Files

```
ui/
├── components/providers/workflow/forms/connect-account-form.tsx   # Add method selector for AWS
├── store/index.ts                                                 # Export org store
├── types/index.ts                                                 # Export org types
```

---

## 3. Types (`ui/types/organizations.ts`)

### Const enums (following `as const` pattern)

```typescript
export const DISCOVERY_STATUS = { PENDING: "pending", RUNNING: "running", SUCCEEDED: "succeeded", FAILED: "failed" } as const;
export const APPLY_STATUS = { READY: "ready", BLOCKED: "blocked" } as const;
export const ORG_RELATION = { ALREADY_LINKED: "already_linked", LINK_REQUIRED: "link_required", LINKED_TO_OTHER: "linked_to_other_organization" } as const;
export const SECRET_STATE = { ALREADY_EXISTS: "already_exists", WILL_CREATE: "will_create", MANUAL_REQUIRED: "manual_required" } as const;

export const ORG_WIZARD_STEP = { SETUP: 0, VALIDATE: 1, LAUNCH: 2 } as const;
// Note: Step 0 in modal = Step 2 in stepper (Step 1 is pre-completed)
```

### Key interfaces (flat, one-level depth)

- `AccountRegistration` — `{ provider_exists, provider_id, organization_relation, apply_status, blocked_reasons[] }`
- `DiscoveredAccount` — `{ id, name, email, status, parent_id, registration }`
- `DiscoveredOu` — `{ id, name, arn, parent_id }`
- `DiscoveredRoot` — `{ id, arn, name, policy_types }`
- `DiscoveryResult` — `{ roots[], organizational_units[], accounts[] }`
- `OrganizationResource` — JSON:API `{ id, type: "organizations", attributes }`
- `DiscoveryResource` — JSON:API `{ id, type: "organization-discoveries", attributes }`
- `ApplyResultResource` — JSON:API with counts + relationships (provider IDs)

---

## 4. Server Actions (`ui/actions/organizations/organizations.ts`)

All follow existing pattern: `"use server"`, `getAuthHeaders()`, `handleApiResponse()`.

| Action | Method | Endpoint | Notes |
|--------|--------|----------|-------|
| `createOrganization(formData)` | POST | `/organizations` | Returns org ID |
| `createOrganizationSecret(formData)` | POST | `/organization-secrets` | Includes org relationship |
| `triggerDiscovery(orgId)` | POST | `/organizations/{id}/discover` | No body, returns discovery ID |
| `getDiscovery(orgId, discoveryId)` | GET | `/organizations/{id}/discoveries/{did}` | Poll status |
| `applyDiscovery(formData)` | POST | `/organizations/{id}/discoveries/{did}/apply` | Returns provider IDs + counts |

**Reuse existing utilities:**
- `getAuthHeaders()` — `ui/lib/helper.ts`
- `handleApiResponse()` — `ui/lib/server-actions-helper.ts`
- `handleApiError()` — `ui/lib/server-actions-helper.ts`
- `checkConnectionProvider()` — `ui/actions/providers/providers.ts` (for testing each created provider)
- `checkTaskStatus()` — `ui/lib/helper.ts` (polling pattern for connection test tasks)
- `scheduleDaily()` / `scanOnDemand()` — `ui/actions/scans/scans.ts` (for Launch Scan step)

---

## 5. Adapter (`ui/actions/organizations/organizations.adapter.ts`)

### `buildOrgTreeData(result: DiscoveryResult): TreeDataItem[]`

Transforms flat API arrays into hierarchical `TreeDataItem[]` for the TreeView component:
1. Create root-level nodes from `result.roots[]`
2. Build OU nodes, nest under parent root/OU via `parent_id`
3. Build account leaf nodes, nest under parent OU/root via `parent_id`
4. Set `disabled: true` on accounts where `apply_status === "blocked"`

### `getSelectableAccountIds(result: DiscoveryResult): string[]`

Returns IDs of accounts with `apply_status === "ready"` (pre-selects all selectable accounts).

### `buildAccountLookup(result: DiscoveryResult): Map<string, DiscoveredAccount>`

Lookup map for `org-account-tree-item.tsx` to access registration data by account ID.

### `getOuIdsForSelectedAccounts(result: DiscoveryResult, selectedAccountIds: string[]): string[]`

Given selected account IDs, returns the set of OU IDs needed (ancestor OUs for selected accounts).

---

## 6. Zustand Store (`ui/store/organizations/store.ts`)

```typescript
interface OrgSetupState {
  // Identity
  organizationId: string | null;
  organizationName: string | null;
  organizationExternalId: string | null;
  discoveryId: string | null;

  // Discovery
  discoveryResult: DiscoveryResult | null;

  // Selection + aliases
  selectedAccountIds: string[];
  accountAliases: Record<string, string>;  // accountId -> alias

  // Apply result
  createdProviderIds: string[];

  // Connection test results
  connectionResults: Record<string, "pending" | "success" | "error">;  // providerId -> status

  // Actions
  setOrganization: (id: string, name: string, externalId: string) => void;
  setDiscovery: (id: string, result: DiscoveryResult) => void;
  setSelectedAccountIds: (ids: string[]) => void;
  setAccountAlias: (accountId: string, alias: string) => void;
  setCreatedProviderIds: (ids: string[]) => void;
  setConnectionResult: (providerId: string, status: "pending" | "success" | "error") => void;
  reset: () => void;
}
```

Uses `persist` middleware with `sessionStorage`. Pattern matches `ui/store/ui/store.ts`.

---

## 7. Component Details

### 7.1 `org-wizard-modal.tsx` — Modal Shell

A large Dialog (shadcn `Dialog` from `@/components/shadcn/dialog`) containing:
- Header: "Adding A Cloud Provider" + info link + X close button
- Two-column layout: Left = `OrgWizardStepper`, Right = step content
- Footer: Back/Next/action buttons (vary by step)
- Internal state: `currentStep` (0=Setup, 1=Validate, 2=Launch)
- On close (X or "Done"): calls `orgStore.reset()`, closes dialog

Props: `open: boolean`, `onOpenChange: (open: boolean) => void`

### 7.2 `org-wizard-stepper.tsx` — 4-Step Stepper

Custom vertical stepper (shadcn-based, NOT HeroUI) with 4 steps:
1. "Link a Cloud Provider" — always completed (green check)
2. "Authenticate Credentials" — active/completed based on `currentStep`
3. "Validate Connection" — active/completed/error based on state
4. "Launch Scan" — active when reached

Icons: folder-git-2, key-round, rocket, Prowler logo (matching Figma)
Step 3 shows error icon when connection tests have failures.

### 7.3 `aws-method-selector.tsx` — Method Selection

Renders inside `connect-account-form.tsx` when `providerType === "aws"`.

Two radio-style cards:
1. **"Add A Single AWS Cloud Account"** — `Box` icon, always enabled
2. **"Add Multiple Accounts With AWS Organizations"** — `Building2` icon
   - SaaS (`NEXT_PUBLIC_IS_CLOUD_ENV === "true"`): enabled
   - OSS: disabled + gradient "Get Prowler Cloud" CTA badge

### 7.4 `connect-account-form.tsx` — Modification

Add AWS method selection as conditional within `prevStep === 2`:

```
prevStep === 1: RadioGroupProvider — unchanged
prevStep === 2 && providerType === "aws" && !awsMethod: AwsMethodSelector + OrgWizardModal
prevStep === 2 && providerType !== "aws": UID/Alias input — unchanged
prevStep === 2 && awsMethod === "single": UID/Alias input (existing)
```

New local state: `awsMethod: "single" | null`, `isOrgModalOpen: boolean`

When "Organizations" is selected → `setIsOrgModalOpen(true)` (opens the wizard modal)
When "Single Account" is selected → `setAwsMethod("single")` (shows UID input)

### 7.5 `org-setup-form.tsx` — Step 2: Organization Details

React Hook Form + Zod schema:
- `organizationName`: `z.string().min(3)`
- `awsOrgId`: `z.string().regex(/^o-[a-z0-9]{10,32}$/)`
- `roleArn`: `z.string().regex(/^arn:aws:iam::\d{12}:role\//)`
- `externalId`: `z.string().min(1)`

**Submit flow (sequential chain):**
1. `createOrganization()` → get `orgId`
2. `createOrganizationSecret()` with `orgId` → get `secretId`
3. `triggerDiscovery(orgId)` → get `discoveryId`
4. Store all in Zustand: `setOrganization(orgId, name, externalId)`, discoveryId
5. Advance to step 3 (Validate Connection)

Shows loading state during 3-call chain. If any fails, shows error on the relevant field.

### 7.6 `org-discovery-loader.tsx` — Step 3 Phase A: Discovery Polling

On mount, polls `getDiscovery(orgId, discoveryId)` every 3s, max 60 retries (3 min).
- Shows spinner + "Discovering your AWS Organization..."
- On `succeeded`: stores result in Zustand, transitions to Phase B
- On `failed`: shows error message + "Retry" button

### 7.7 `org-account-selection.tsx` — Step 3 Phase B: Selection

Renders:
- Org info header (AWS badge + org name + UID badge)
- `TreeView` from `@/components/shadcn/tree-view` with:
  - `showCheckboxes={true}`, `enableSelectChildren={true}`, `expandAll={true}`
  - Custom `renderItem` → shows account ID + "Name (optional)" input field
- Pre-selects all `ready` accounts
- Blocked accounts shown as disabled with reason tooltip

Buttons: "Back" (go to step 2), "Next" (advance to Phase C / Apply)

### 7.8 `org-connection-test.tsx` — Step 3 Phase C: Apply + Test Connections

**On mount:**
1. Calls `applyDiscovery()` with selected account IDs + aliases from Zustand
2. Stores returned `createdProviderIds` in Zustand
3. Automatically tests all connections: for each provider ID, calls `checkConnectionProvider()` then polls `checkTaskStatus()`
4. Updates TreeView status icons in real-time via `connectionResults` in store

**TreeView display** (from Figma):
- Table headers: "Account ID" | "Name (optional)"
- Each node: expand arrow + status icon (✓ green / ✗ red / spinner) + folder/shield icon + ID + name field
- Uses `TreeDataItem.status` and `TreeDataItem.isLoading` for built-in spinner/icon support

**Error state** (from Figma `10160:2965`):
- Red error banner: "There was a problem connecting to some accounts. Ensure the Prowler StackSet has successfully deployed then retry testing connections."
- "Test Connections" button retries all failed connections
- "Skip Connection Validation" link advances to step 4 anyway

**Success:** All connections pass → automatically advance to step 4

Buttons: "Back", "Skip Connection Validation" (text link), "Test Connections" (primary)

### 7.9 `org-launch-scan.tsx` — Step 4: Launch Scan

From Figma (`10004:102323`):
- Org info header (AWS badge + org name + UID badge)
- Green check + "Accounts Connected!"
- "Your accounts are connected to Prowler and ready to Scan!"
- "Select a Prowler scan schedule for these accounts."
- Dropdown: "Scan Daily (every 24 hours)" (default selected)

**"Done" button:**
- Close modal, navigate to `/providers`, revalidate
- No scan triggered

**"Launch Scan" button:**
- For each provider ID in `createdProviderIds`:
  - Call `scheduleDaily()` (from `ui/actions/scans/scans.ts`)
- Close modal, navigate to `/providers`
- Show toast: "Scan launched for N accounts"
- Revalidate `/providers` and `/scans`

### 7.10 `org-account-tree-item.tsx` — Custom Tree Renderer

Used in both Phase B (selection) and Phase C (testing) via `renderItem` prop.

**Phase B (selection mode):**
- Shows: account ID text + "Name (optional)" input field
- Checkboxes handled by TreeView's built-in checkbox support

**Phase C (testing mode):**
- Shows: status icon (✓/✗/spinner) + account ID + "Name (optional)" input (read-only or editable)
- OUs show aggregate status (all children pass = ✓, any fail = ✗)
- Uses `item.status` ("success"/"error") and `item.isLoading` from TreeDataItem

Account data lookup via closure over `Map<string, DiscoveredAccount>` from adapter.

---

## 8. SaaS/OSS Gating

Single check in `AwsMethodSelector`:
```typescript
const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
```
- OSS: Organizations option disabled with gradient "Get Prowler Cloud" CTA
- SaaS: Organizations option fully functional
- No server-side gating needed

---

## 9. Implementation Order

| # | Task | Depends On |
|---|------|-----------|
| 1 | Types (`types/organizations.ts`) | — |
| 2 | Server actions (`actions/organizations/organizations.ts`) | Types |
| 3 | Adapter (`actions/organizations/organizations.adapter.ts`) | Types |
| 4 | Zustand store (`store/organizations/store.ts`) | Types |
| 5 | `AwsMethodSelector` component | — |
| 6 | `OrgWizardStepper` component | — |
| 7 | `OrgSetupForm` component | Actions, Store |
| 8 | `OrgDiscoveryLoader` component | Actions, Store |
| 9 | `OrgAccountTreeItem` component | Adapter, Types |
| 10 | `OrgAccountSelection` component | TreeView, TreeItem, Store |
| 11 | `OrgConnectionTest` component | Actions, Store, TreeView |
| 12 | `OrgLaunchScan` component | Scan actions, Store |
| 13 | `OrgWizardModal` (shell + step router) | All above components |
| 14 | Modify `connect-account-form.tsx` | AwsMethodSelector, OrgWizardModal |
| 15 | Wire exports (`store/index.ts`, `types/index.ts`) | All |

---

## 10. Verification

### Local testing (UI states — no real API)

1. `pnpm run dev` → verify no errors
2. `pnpm run typecheck` → all types compile
3. `pnpm run lint:fix` → no lint errors
4. `/providers/connect-account`:
   - Select AWS → method selector appears
   - OSS mode: Organizations option disabled + "Get Prowler Cloud" badge
   - Click "Single Account" → existing UID form (unchanged)
   - Click "Organizations" (SaaS) → modal opens
   - Non-AWS providers → go straight to UID form (no method selector)
5. Modal stepper: verify 4 steps render, step transitions work
6. Org setup form: validation works (Zod errors on invalid inputs)
7. Mock discovery states: pending spinner, succeeded tree, failed error
8. TreeView: checkboxes toggle, blocked accounts disabled, names editable
9. Close modal (X or Done) → state resets

### Cloud DEV E2E testing (required before merge)

1. Happy path: create org → secret → discover → select → apply → test connections → launch scan
2. Partial failure: some connections fail → error banner → "Test Connections" retry → "Skip" works
3. All pass: auto-advance to Launch Scan
4. Discovery failure: shows error + "Retry" button
5. Blocked accounts: cannot be selected in tree
6. Launch Scan: modal closes → `/providers` → toast → providers visible in table
7. OSS gate: method selector shows disabled option with CTA

### Key utilities to reuse

| Utility | Path | Used For |
|---------|------|----------|
| `getAuthHeaders()` | `ui/lib/helper.ts` | All API calls |
| `handleApiResponse()` | `ui/lib/server-actions-helper.ts` | Response parsing |
| `checkConnectionProvider()` | `ui/actions/providers/providers.ts` | Testing each provider |
| `checkTaskStatus()` | `ui/lib/helper.ts:257` | Polling connection test tasks |
| `scheduleDaily()` | `ui/actions/scans/scans.ts:141` | Launch Scan step |
| `useFormServerErrors` | `ui/hooks/use-form-server-errors.ts` | Map API errors to form fields |
| `TreeView` | `ui/components/shadcn/tree-view/` | Account hierarchy + selection |
| `Dialog` | `ui/components/shadcn/dialog` | Modal container |
| `useUIStore` pattern | `ui/store/ui/store.ts` | Zustand + persist reference |
| `addProvider` pattern | `ui/actions/providers/providers.ts` | JSON:API server action reference |
