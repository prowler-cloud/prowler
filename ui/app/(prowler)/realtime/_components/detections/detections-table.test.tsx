import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RealtimeDetection } from "@/app/(prowler)/realtime/_types";

import { DetectionsTable } from "./detections-table";

const router = vi.hoisted(() => ({ push: vi.fn(), search: "" }));

// The table's shared helpers import the server auth module; no user here.
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/realtime",
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(router.search),
}));

const detection: RealtimeDetection = {
  id: "8d0f6c2a-1b3e-4f5a-9c7d-2e4f6a8b0c1d",
  provider_id: "provider-1",
  event_id: "evt-1",
  event_time: "2026-11-04T10:42:18Z",
  region: "eu-west-1",
  rule_id: "sg_open_all",
  title: "Security group open to the internet on all ports",
  severity: "critical",
  actor: "arn:aws:sts::123456789012:assumed-role/ci-deployer/gh",
  resource: "sg-0a41c9e2",
  check_ids: ["ec2_securitygroup_allow_ingress_from_internet_to_all_ports"],
  requirements: ["CC6.6"],
  status: "violation",
  note: "Security group sg-0a41c9e2 allows 0.0.0.0/0 on all ports.",
  verified_at: "2026-11-04T10:42:31Z",
};

const metadata = { pagination: { page: 1, pages: 1, count: 1 }, version: "1" };

describe("DetectionsTable", () => {
  beforeEach(() => {
    // jsdom has no scrollIntoView; the filter dropdowns call it.
    Element.prototype.scrollIntoView = vi.fn();
    router.push.mockReset();
    router.search = "tab=detections&filter%5Bstatus__in%5D=violation";
  });

  it("opens the clicked detection through the URL, keeping the filters", async () => {
    const user = userEvent.setup();
    render(
      <DetectionsTable
        providerId="provider-1"
        detections={[detection]}
        metadata={metadata}
        selected={null}
        selectedActions={[]}
        filtered
      />,
    );

    await user.click(screen.getByText(detection.title));
    expect(router.push).toHaveBeenCalledWith(
      `/realtime?tab=detections&filter%5Bstatus__in%5D=violation&detection=${detection.id}`,
      { scroll: false },
    );
  });

  it("explains an empty result under filters", () => {
    render(
      <DetectionsTable
        providerId="provider-1"
        detections={[]}
        metadata={{ ...metadata, pagination: { page: 1, pages: 1, count: 0 } }}
        selected={null}
        selectedActions={[]}
        filtered
      />,
    );
    expect(screen.getByText("No detections match")).toBeInTheDocument();
  });
});
