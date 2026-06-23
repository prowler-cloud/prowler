import { describe, expect, it } from "vitest";

import {
  type MetaDataProps,
  type ProviderProps,
  SCAN_JOBS_TAB,
  type ScanAttributes,
  type ScanProps,
  type ScanTrigger,
  type ScheduleProps,
} from "@/types";

import {
  appendPendingScheduleRowsToPage,
  buildPendingScheduleRows,
  buildScheduledTabRows,
  formatScanDuration,
  getScanAlias,
  getScanFindingsSummary,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanJobsUserFilters,
  getScanScheduleLabel,
  getScanStatusLabel,
  getScanTriggerFilterOptions,
  mapScheduleToScanRow,
} from "./scans.utils";

const makeScan = (
  name: string | null,
  trigger: ScanTrigger = "manual",
): ScanProps => ({
  type: "scans",
  id: "scan-1",
  attributes: {
    name: name ?? "",
    trigger,
    state: "completed",
    unique_resource_count: 0,
    progress: 100,
    scanner_args: null,
    duration: 0,
    started_at: "",
    inserted_at: "",
    completed_at: "",
    scheduled_at: "",
    next_scan_at: "",
  },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    task: { data: { type: "tasks", id: "task-1" } },
  },
});

describe("scans.utils", () => {
  it("falls back to completed tab for unknown tab values", () => {
    expect(getScanJobsTab("unknown")).toBe(SCAN_JOBS_TAB.COMPLETED);
    expect(getScanJobsTab(SCAN_JOBS_TAB.COMPLETED)).toBe(
      SCAN_JOBS_TAB.COMPLETED,
    );
  });

  it("maps scan job tabs to the state filters expected by the API", () => {
    expect(getScanJobsTabFilters(SCAN_JOBS_TAB.ACTIVE)).toEqual({
      "filter[state__in]": "available,executing",
    });
    expect(getScanJobsTabFilters(SCAN_JOBS_TAB.COMPLETED)).toEqual({
      "filter[state__in]": "completed,failed,cancelled",
    });
    expect(getScanJobsTabFilters(SCAN_JOBS_TAB.SCHEDULED)).toEqual({
      "filter[state__in]": "scheduled",
    });
  });

  it("narrows tab state filters when a matching status is selected", () => {
    expect(getScanJobsTabFilters(SCAN_JOBS_TAB.COMPLETED, "failed")).toEqual({
      "filter[state__in]": "failed",
    });
    expect(
      getScanJobsTabFilters(SCAN_JOBS_TAB.COMPLETED, "failed,cancelled"),
    ).toEqual({
      "filter[state__in]": "failed,cancelled",
    });
    expect(getScanJobsTabFilters(SCAN_JOBS_TAB.ACTIVE, "failed")).toEqual({
      "filter[state__in]": "available,executing",
    });
  });

  it("keeps user filters while excluding scan state filters", () => {
    expect(
      getScanJobsUserFilters({
        tab: "completed",
        page: "2",
        "filter[provider_uid]": "123456789012",
        "filter[state__in]": "failed,cancelled",
        "filter[search]": "production",
      }),
    ).toEqual({
      "filter[provider_uid]": "123456789012",
      "filter[search]": "production",
    });
  });

  it("excludes trigger filters from scheduled scans", () => {
    expect(
      getScanJobsUserFilters({
        tab: "scheduled",
        "filter[trigger]": "manual",
        "filter[provider_uid]": "123456789012",
      }),
    ).toEqual({
      "filter[provider_uid]": "123456789012",
    });
  });

  it("formats scan labels and durations for table display", () => {
    expect(getScanAlias(makeScan(""))).toBe("-");
    expect(getScanAlias(makeScan("Daily scheduled scan", "scheduled"))).toBe(
      "Scheduled Scan",
    );
    expect(getScanAlias(makeScan("", "scheduled"))).toBe("Scheduled Scan");
    expect(getScanAlias(makeScan("Production scan"))).toBe("Production scan");
    expect(formatScanDuration(73)).toBe("1 min 13 sec");
    expect(formatScanDuration(null)).toBe("-");
  });

  it("maps trigger and state values to product labels", () => {
    expect(getScanScheduleLabel("manual")).toBe("Manual");
    expect(getScanScheduleLabel("scheduled")).toBe("Scheduled");
    expect(getScanScheduleLabel("imported")).toBe("Imported");
    expect(getScanStatusLabel("available")).toBe("Queued");
    expect(getScanStatusLabel("completed")).toBe("Completed");
  });

  it("includes imported in the trigger filter only for Cloud", () => {
    expect(getScanTriggerFilterOptions(false)).toEqual([
      { value: "all", label: "All Types" },
      { value: "manual", label: "Manual" },
      { value: "scheduled", label: "Scheduled" },
    ]);
    expect(getScanTriggerFilterOptions(true)).toEqual([
      { value: "all", label: "All Types" },
      { value: "manual", label: "Manual" },
      { value: "scheduled", label: "Scheduled" },
      { value: "imported", label: "Imported" },
    ]);
  });

  it("reads findings summary from root or nested API fields", () => {
    expect(
      getScanFindingsSummary({
        fail: 2,
        pass: 3,
        fail_new: 1,
      } as unknown as ScanAttributes),
    ).toEqual({ fail: 2, pass: 3, failNew: 1 });

    expect(
      getScanFindingsSummary({
        findings: {
          failed_findings: 4,
          passed_findings: 8,
          new_passed_findings: 2,
        },
      } as unknown as ScanAttributes),
    ).toEqual({ fail: 4, pass: 8, passNew: 2 });

    expect(getScanFindingsSummary(makeScan("x").attributes)).toBeNull();
  });
});

describe("buildPendingScheduleRows", () => {
  const now = new Date("2026-06-10T10:30:00Z");

  const makeProvider = (id: string): ProviderProps => ({
    id,
    type: "providers",
    attributes: {
      provider: "aws",
      uid: `uid-${id}`,
      alias: `alias-${id}`,
      status: "completed",
      resources: 0,
      connection: {
        connected: true,
        last_checked_at: "2026-06-10T10:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-06-10T10:00:00Z",
      updated_at: "2026-06-10T10:00:00Z",
      created_by: {
        object: "users",
        id: "user-1",
      },
    },
    relationships: {
      secret: { data: null },
      provider_groups: { meta: { count: 0 }, data: [] },
    },
  });

  const makeScheduledScan = (id: string, providerId: string): ScanProps => ({
    ...makeScan("Scheduled Scan", "scheduled"),
    id,
    relationships: {
      provider: { data: { type: "providers", id: providerId } },
      task: { data: { type: "tasks", id: `task-${id}` } },
    },
  });

  const makeMeta = ({
    page,
    pages,
    count,
  }: {
    page: number;
    pages: number;
    count: number;
  }): MetaDataProps => ({
    pagination: {
      page,
      pages,
      count,
      itemsPerPage: [1, 2, 10],
    },
    version: "v1",
  });

  const weeklySchedule = {
    scan_enabled: true,
    scan_frequency: "WEEKLY",
    scan_hour: 9,
    scan_timezone: "Europe/Madrid",
    scan_interval_hours: null,
    scan_day_of_week: 1,
    scan_day_of_month: null,
  } as const;

  it("synthesizes a pending row for a configured schedule without scan rows", () => {
    const rows = buildPendingScheduleRows({
      providers: [makeProvider("p1")],
      schedulesByProviderId: { p1: weeklySchedule },
      coveredProviderIds: new Set(),
      now,
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe("pending-schedule-p1");
    expect(rows[0].attributes.state).toBe("scheduled");
    expect(rows[0].attributes.trigger).toBe("scheduled");
    expect(rows[0].pendingSchedule?.summary).toBe(
      "Weekly on Monday @ 9:00am (Europe/Madrid)",
    );
    expect(rows[0].pendingSchedule?.cadence).toBe("Weekly on Monday");
    expect(rows[0].providerInfo?.uid).toBe("uid-p1");
  });

  it("uses global covered providers when appending pending rows", () => {
    // Given - p1 has a real scheduled scan on a previous page, p2 only has a configured schedule.
    const result = appendPendingScheduleRowsToPage({
      scans: [],
      meta: makeMeta({ page: 2, pages: 1, count: 1 }),
      page: 2,
      pageSize: 1,
      providers: [makeProvider("p1"), makeProvider("p2")],
      schedulesByProviderId: {
        p1: weeklySchedule,
        p2: weeklySchedule,
      },
      coveredProviderIds: new Set(["p1"]),
      now,
    });

    // Then - p1 is not duplicated as a synthetic pending row.
    expect(result.data.map((scan) => scan.id)).toEqual(["pending-schedule-p2"]);
    expect(result.meta?.pagination.count).toBe(2);
    expect(result.meta?.pagination.pages).toBe(2);
  });

  it("keeps the last real page within page size and carries pending rows to the next page", () => {
    // Given - three real scheduled scans and two pending schedules at page size 2.
    const providers = ["p1", "p2", "p3", "p4", "p5"].map(makeProvider);
    const schedulesByProviderId = Object.fromEntries(
      providers.map((provider) => [provider.id, weeklySchedule]),
    );

    const lastRealPage = appendPendingScheduleRowsToPage({
      scans: [makeScheduledScan("scan-3", "p3")],
      meta: makeMeta({ page: 2, pages: 2, count: 3 }),
      page: 2,
      pageSize: 2,
      providers,
      schedulesByProviderId,
      coveredProviderIds: new Set(["p1", "p2", "p3"]),
      now,
    });

    const firstPendingOnlyPage = appendPendingScheduleRowsToPage({
      scans: [],
      meta: makeMeta({ page: 3, pages: 2, count: 3 }),
      page: 3,
      pageSize: 2,
      providers,
      schedulesByProviderId,
      coveredProviderIds: new Set(["p1", "p2", "p3"]),
      now,
    });

    // Then - page 2 gets one pending row, page 3 gets the remaining pending row.
    expect(lastRealPage.data.map((scan) => scan.id)).toEqual([
      "scan-3",
      "pending-schedule-p4",
    ]);
    expect(lastRealPage.meta?.pagination.count).toBe(5);
    expect(lastRealPage.meta?.pagination.pages).toBe(3);
    expect(firstPendingOnlyPage.data.map((scan) => scan.id)).toEqual([
      "pending-schedule-p5",
    ]);
  });

  it("shows pending rows on an otherwise empty scheduled tab with coherent metadata", () => {
    // Given
    const result = appendPendingScheduleRowsToPage({
      scans: [],
      meta: makeMeta({ page: 1, pages: 0, count: 0 }),
      page: 1,
      pageSize: 10,
      providers: [makeProvider("p1")],
      schedulesByProviderId: { p1: weeklySchedule },
      coveredProviderIds: new Set(),
      now,
    });

    // Then
    expect(result.data.map((scan) => scan.id)).toEqual(["pending-schedule-p1"]);
    expect(result.meta?.pagination.count).toBe(1);
    expect(result.meta?.pagination.pages).toBe(1);
    expect(result.meta?.pagination.page).toBe(1);
  });

  it("prefers the server-computed next_scan_at and carries last_scan_at", () => {
    const rows = buildPendingScheduleRows({
      providers: [makeProvider("p1")],
      schedulesByProviderId: {
        p1: {
          ...weeklySchedule,
          next_scan_at: "2026-06-15T00:00:00Z",
          last_scan_at: "2026-06-01T10:00:00Z",
        },
      },
      coveredProviderIds: new Set(),
      now,
    });

    expect(rows[0].attributes.scheduled_at).toBe("2026-06-15T00:00:00Z");
    expect(rows[0].pendingSchedule?.nextScanAt).toBe("2026-06-15T00:00:00Z");
    expect(rows[0].pendingSchedule?.lastScanAt).toBe("2026-06-01T10:00:00Z");
  });

  it("falls back to a client estimate when next_scan_at is absent", () => {
    const rows = buildPendingScheduleRows({
      providers: [makeProvider("p1")],
      schedulesByProviderId: { p1: weeklySchedule },
      coveredProviderIds: new Set(),
      now,
    });

    expect(rows[0].attributes.scheduled_at).not.toBeNull();
    expect(rows[0].pendingSchedule?.lastScanAt).toBeNull();
  });

  it("skips providers already covered by a real scheduled scan row", () => {
    const rows = buildPendingScheduleRows({
      providers: [makeProvider("p1")],
      schedulesByProviderId: { p1: weeklySchedule },
      coveredProviderIds: new Set(["p1"]),
      now,
    });

    expect(rows).toHaveLength(0);
  });

  it("skips unconfigured and disabled schedules", () => {
    const rows = buildPendingScheduleRows({
      providers: [makeProvider("p1"), makeProvider("p2"), makeProvider("p3")],
      schedulesByProviderId: {
        p1: { ...weeklySchedule, scan_hour: null },
        p2: { ...weeklySchedule, scan_enabled: false },
      },
      coveredProviderIds: new Set(),
      now,
    });

    expect(rows).toHaveLength(0);
  });

  describe("mapScheduleToScanRow", () => {
    const makeSchedule = (
      attributes: Partial<ScheduleProps["attributes"]> = {},
    ): ScheduleProps => ({
      type: "schedules",
      id: "p1",
      attributes: {
        ...weeklySchedule,
        next_scan_at: "2026-06-15T00:00:00Z",
        last_scan_at: "2026-06-01T10:00:00Z",
        ...attributes,
      },
      relationships: {
        provider: { data: { type: "providers", id: "p1" } },
      },
    });

    it("maps a configured schedule to a Scheduled-tab row", () => {
      const row = mapScheduleToScanRow(makeSchedule(), makeProvider("p1"), now);

      expect(row.id).toBe("schedule-p1");
      expect(row.attributes.trigger).toBe("scheduled");
      expect(row.attributes.state).toBe("scheduled");
      expect(row.attributes.scheduled_at).toBe("2026-06-15T00:00:00Z");
      expect(row.pendingSchedule?.summary).toBe(
        "Weekly on Monday @ 9:00am (Europe/Madrid)",
      );
      expect(row.pendingSchedule?.cadence).toBe("Weekly on Monday");
      expect(row.pendingSchedule?.lastScanAt).toBe("2026-06-01T10:00:00Z");
      expect(row.providerInfo?.uid).toBe("uid-p1");
      // The schedule id IS the provider id.
      expect(row.relationships.provider.data?.id).toBe("p1");
    });

    it("leaves providerInfo undefined when the provider is missing from included", () => {
      const row = mapScheduleToScanRow(makeSchedule(), undefined, now);

      expect(row.providerInfo).toBeUndefined();
    });

    it("shows no next run for a paused schedule", () => {
      const row = mapScheduleToScanRow(
        makeSchedule({ scan_enabled: false, next_scan_at: null }),
        makeProvider("p1"),
        now,
      );

      expect(row.attributes.scheduled_at).toBeNull();
      expect(row.pendingSchedule?.nextScanAt).toBeNull();
    });
  });

  describe("buildScheduledTabRows", () => {
    const schedule: ScheduleProps = {
      type: "schedules",
      id: "p1",
      attributes: {
        ...weeklySchedule,
        next_scan_at: "2026-06-15T00:00:00Z",
        last_scan_at: null,
      },
      relationships: { provider: { data: { type: "providers", id: "p1" } } },
    };

    it("maps schedule data and passes meta through verbatim", () => {
      const meta = makeMeta({ page: 1, pages: 3, count: 25 });

      const result = buildScheduledTabRows(
        { data: [schedule], included: [makeProvider("p1")], meta },
        now,
      );

      expect(result.data.map((row) => row.id)).toEqual(["schedule-p1"]);
      expect(result.data[0].providerInfo?.uid).toBe("uid-p1");
      expect(result.meta).toBe(meta);
    });

    it("returns an empty result on error or missing data", () => {
      expect(buildScheduledTabRows({ error: "boom" }, now)).toEqual({
        data: [],
      });
      expect(buildScheduledTabRows(null, now)).toEqual({ data: [] });
    });

    it("drops unconfigured schedules even if the backend returns them", () => {
      const unconfigured: ScheduleProps = {
        ...schedule,
        id: "p2",
        attributes: { ...schedule.attributes, scan_hour: null },
        relationships: { provider: { data: { type: "providers", id: "p2" } } },
      };

      const result = buildScheduledTabRows(
        { data: [schedule, unconfigured], included: [], meta: undefined },
        now,
      );

      expect(result.data.map((row) => row.id)).toEqual(["schedule-p1"]);
    });
  });
});
