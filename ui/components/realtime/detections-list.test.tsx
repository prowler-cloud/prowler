import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/actions/realtime", () => ({}));

import type { RealtimeDetection } from "@/types/realtime";

import { DetectionsTable } from "./detections-list";

const detection = (
  overrides: Partial<RealtimeDetection>,
): RealtimeDetection => ({
  id: "d1",
  provider_id: "p",
  event_id: "e",
  event_time: "2026-10-23T10:00:00Z",
  region: "eu-west-1",
  rule_id: "s3_public_acl",
  title: "Bucket made public",
  severity: "high",
  actor: "",
  resource: "bucket-1",
  check_ids: [],
  requirements: [],
  status: "violation",
  note: "",
  verified_at: null,
  ...overrides,
});

describe("DetectionsTable", () => {
  it("marks drift found by the reconciler as compliance drift", () => {
    render(
      <DetectionsTable
        detections={[
          detection({
            id: "d2",
            rule_id: "framework_drift",
            title: "Public bucket (compliance drift)",
          }),
          detection({}),
        ]}
      />,
    );

    expect(screen.getAllByText("Compliance drift")).toHaveLength(1);
    expect(screen.getByText("Public bucket (compliance drift)")).toBeVisible();
  });
});
