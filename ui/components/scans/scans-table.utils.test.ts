import { describe, expect, it } from "vitest";

import type { ScanAttributes, ScanProps } from "@/types";

import {
  formatScanDuration,
  getScanAlias,
  getScanFindingsSummary,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanScheduleLabel,
  getScanStatusLabel,
  getScanTriggerFilterOptions,
  SCAN_JOBS_TAB,
} from "./scans-table.utils";

const makeScan = (name: string | null): ScanProps => ({
  type: "scans",
  id: "scan-1",
  attributes: {
    name: name ?? "",
    trigger: "manual",
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

describe("scans-table.utils", () => {
  it("falls back to active tab for unknown tab values", () => {
    expect(getScanJobsTab("unknown")).toBe(SCAN_JOBS_TAB.ACTIVE);
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

  it("formats scan labels and durations for table display", () => {
    expect(getScanAlias(makeScan(""))).toBe("-");
    expect(getScanAlias(makeScan("Daily scheduled scan"))).toBe(
      "scheduled scan",
    );
    expect(getScanAlias(makeScan("Production scan"))).toBe("Production scan");
    expect(formatScanDuration(73)).toBe("1 min 13 sec");
    expect(formatScanDuration(null)).toBe("-");
  });

  it("maps trigger and state values to product labels", () => {
    expect(getScanScheduleLabel("manual")).toBe("Single");
    expect(getScanScheduleLabel("scheduled")).toBe("Scheduled");
    expect(getScanScheduleLabel("imported")).toBe("Imported");
    expect(getScanStatusLabel("available")).toBe("Queued");
    expect(getScanStatusLabel("completed")).toBe("Completed");
  });

  it("includes imported in the trigger filter only for Cloud", () => {
    expect(getScanTriggerFilterOptions(false)).toEqual([
      { value: "all", label: "All Types" },
      { value: "manual", label: "Single" },
      { value: "scheduled", label: "Scheduled" },
    ]);
    expect(getScanTriggerFilterOptions(true)).toEqual([
      { value: "all", label: "All Types" },
      { value: "manual", label: "Single" },
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
