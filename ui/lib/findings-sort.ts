/**
 * Sort presets for findings-shaped endpoints.
 *
 * The Prowler API exposes two families of findings endpoints with INVERTED
 * sort semantics for the same human intent. Reading them wrong inverts the
 * triage order silently — a bug that has shipped more than once.
 *
 * ─── Family A: plain findings ─────────────────────────────────────────────
 *   `/findings`, `/findings/latest`
 *   `FindingViewSet.ordering_fields` (api/v1/views.py) maps `status` and
 *   `severity` straight to the Postgres ENUM columns. Postgres sorts ENUMs
 *   by DECLARATION order:
 *     severity:  critical, high, medium, low, informational  → ASC = critical first
 *     status:    FAIL, PASS, MANUAL                          → ASC = FAIL first
 *   Use the bare token. NO minus prefix on `status` or `severity`.
 *   `delta` is NOT in `ordering_fields` — sorting by delta is unsupported.
 *
 * ─── Family B: finding-groups ─────────────────────────────────────────────
 *   `/finding-groups`, `/finding-groups/latest`, `/finding-groups/{id}/resources`
 *   `_FINDING_GROUP_SORT_MAP` and `_RESOURCE_SORT_MAP` (api/v1/views.py)
 *   REMAP the public sort keys to computed integer columns:
 *     severity  → severity_order   (5=critical … 1=informational)
 *     status    → status_order     (3=FAIL, 2=PASS, 1=MANUAL)
 *     delta     → delta_order      (2=new, 1=changed, 0=otherwise)
 *   Higher integer = more important. PREFIX with `-` to put FAIL/critical/new first.
 *
 * The two families look identical from the outside (`sort=...`) but require
 * opposite tokens. Always import from this file. Never hard-code.
 */

// ---------------------------------------------------------------------------
// Family A: plain findings (Postgres ENUM — no minus on status/severity)
// ---------------------------------------------------------------------------

export const FINDINGS_FAIL_FIRST = "status";
export const FINDINGS_SEVERITY_HIGH_FIRST = "severity";
export const FINDINGS_RECENT_INSERT = "-inserted_at";
export const FINDINGS_RECENT_UPDATE = "-updated_at";

// ---------------------------------------------------------------------------
// Family B: finding-groups (computed integer — minus on status/severity/delta)
// ---------------------------------------------------------------------------

export const FG_FAIL_FIRST = "-status";
export const FG_SEVERITY_HIGH_FIRST = "-severity";
export const FG_DELTA_NEW_FIRST = "-delta";
export const FG_RECENT_LAST_SEEN = "-last_seen_at";

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

export const composeSort = (...tokens: string[]): string => tokens.join(",");

// ---------------------------------------------------------------------------
// Presets — Family A
// ---------------------------------------------------------------------------

/**
 * Default for plain-findings tables WITHOUT a server-side `filter[status]`.
 * FAIL rows first, then critical→informational, then most recent.
 * Delta is intentionally omitted — `/findings` does not accept `delta` as a
 * sort field (see FindingViewSet.ordering_fields).
 */
export const FINDINGS_DEFAULT_SORT = composeSort(
  FINDINGS_FAIL_FIRST,
  FINDINGS_SEVERITY_HIGH_FIRST,
  FINDINGS_RECENT_INSERT,
);

/**
 * Default for plain-findings tables that ALREADY apply `filter[status]=FAIL`
 * (or equivalent) server-side. Status sort would be redundant.
 */
export const FINDINGS_FILTERED_SORT = composeSort(
  FINDINGS_SEVERITY_HIGH_FIRST,
  FINDINGS_RECENT_INSERT,
);

/**
 * Resource-detail drawer "other findings" tab. Pairs with a server-side
 * `filter[status]=FAIL`, so status is omitted. Uses `-updated_at` because
 * `/findings/latest` exposes `updated_at`, not `inserted_at`.
 */
export const RESOURCE_DRAWER_OTHER_FINDINGS_SORT = composeSort(
  FINDINGS_SEVERITY_HIGH_FIRST,
  FINDINGS_RECENT_UPDATE,
);

// ---------------------------------------------------------------------------
// Presets — Family B
// ---------------------------------------------------------------------------

/**
 * Default for finding-groups list endpoints. FAIL groups first, then by
 * severity, then by `new` deltas (deltas matter on group endpoints since
 * `delta_order` is a real ordering column).
 */
export const FINDING_GROUPS_DEFAULT_SORT = composeSort(
  FG_FAIL_FIRST,
  FG_SEVERITY_HIGH_FIRST,
  FG_DELTA_NEW_FIRST,
  FG_RECENT_LAST_SEEN,
);

/**
 * Default for the per-group resources sub-endpoint
 * (`/finding-groups/{id}/resources`). Same shape as the groups list because
 * `_RESOURCE_SORT_MAP` exposes the same computed columns.
 */
export const FINDING_GROUP_RESOURCES_DEFAULT_SORT = composeSort(
  FG_FAIL_FIRST,
  FG_SEVERITY_HIGH_FIRST,
  FG_DELTA_NEW_FIRST,
  FG_RECENT_LAST_SEEN,
);

/**
 * Default for the `/findings` PAGE (which renders finding-groups, NOT plain
 * findings) when the URL already constrains `filter[status__in]` and/or
 * `filter[delta__in]`. Status and delta sort would be redundant.
 *
 * IMPORTANT: do NOT pass `inserted_at` here — `_FINDING_GROUP_SORT_MAP`
 * does not expose it; valid recency keys are `last_seen_at`, `first_seen_at`,
 * and `failing_since`.
 */
export const FINDING_GROUPS_FILTERED_SORT = composeSort(
  FG_SEVERITY_HIGH_FIRST,
  FG_RECENT_LAST_SEEN,
);
