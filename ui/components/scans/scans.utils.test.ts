import { describe, expect, it } from "vitest";

import {
  SCAN_JOBS_TAB,
  type ScanAttributes,
  type ScanProps,
  type ScanTrigger,
} from "@/types";

import {
  formatScanDuration,
  getScanAlias,
  getScanFindingsSummary,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanJobsUserFilters,
  getScanScheduleLabel,
  getScanStatusLabel,
  getScanTriggerFilterOptions,
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
      "scheduled scan",
    );
    expect(getScanAlias(makeScan("", "scheduled"))).toBe("scheduled scan");
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
