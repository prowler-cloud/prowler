import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";
import type {
  RealtimeDetection,
  RealtimeEvent,
} from "@/app/(prowler)/realtime/_types";

import { DetectionsTable } from "./detections/detections-table";
import { StreamView } from "./stream/stream-view";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/realtime",
  useSearchParams: () => new URLSearchParams(),
}));
// The table's shared helpers import the server auth module; no user here.
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

const ACCOUNT = "123456789012";
const SSO_ACTOR = `arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/ana@example.com`;
const SERVICE_ACTOR = `arn:aws:sts::${ACCOUNT}:assumed-role/example-app-NetworkStack-ABCDEFGHIJ-FlowLogRole-AbCdEfGhIjKl/vpc-flow-logging+${ACCOUNT}`;

const detection: RealtimeDetection = {
  id: "8d0f6c2a-1b3e-4f5a-9c7d-2e4f6a8b0c1d",
  provider_id: "provider-1",
  event_id: "evt-1",
  event_time: "2026-11-05T13:41:54Z",
  region: "us-east-1",
  rule_id: "console_login_without_mfa",
  title: "Console login without MFA",
  severity: "medium",
  actor: SSO_ACTOR,
  resource: SSO_ACTOR,
  check_ids: [],
  requirements: [],
  status: "compliant",
  note: "",
  verified_at: null,
};

const event = (overrides: Partial<RealtimeEvent>): RealtimeEvent => ({
  id: "event-1",
  event_time: "2026-11-05T23:49:32Z",
  region: "us-east-1",
  event_source: "metering-marketplace.amazonaws.com",
  event_name: "MeterUsage",
  user_type: "AssumedRole",
  user_arn: SSO_ACTOR,
  source_ip: "vpc-flow-logs.amazonaws.com",
  error_code: "CustomerNotEntitledException",
  read_only: false,
  provider_id: "provider-1",
  detection_status: "compliant",
  rule_id: "console_login_without_mfa",
  ...overrides,
});

// Main's width on a 1100px window with the sidebar open.
function InMain({ children }: { children: ReactNode }) {
  return (
    <div
      data-responsive-container
      className="@container"
      style={{ width: 760 }}
    >
      {children}
    </div>
  );
}

const scrollOverflow = (container: Element) => {
  const table = container.querySelector("table");
  if (!table?.parentElement) throw new Error("No table rendered");
  return table.parentElement.scrollWidth - table.parentElement.clientWidth;
};

describe("Realtime tables", () => {
  it("fit the detections in the page width and keep who acted readable", async () => {
    const screen = await render(
      <InMain>
        <DetectionsTable
          providerId="provider-1"
          detections={[detection]}
          metadata={{
            pagination: { page: 1, pages: 1, count: 1 },
            version: "1",
          }}
          selected={null}
          selectedActions={[]}
          filtered={false}
        />
      </InMain>,
    );

    await expect.element(screen.getByText(detection.title)).toBeVisible();
    expect(scrollOverflow(screen.container)).toBeLessThanOrEqual(0);
    const actor = screen.getByText("ana@example.com", { exact: true });
    await expect.element(actor).toBeVisible();
    expect(actor.element().closest("[title]")?.getAttribute("title")).toBe(
      SSO_ACTOR,
    );
  });

  it("fit the event stream in the page width", async () => {
    const screen = await render(
      <InMain>
        <StreamView
          providerId="provider-1"
          showAll
          events={[
            event({ id: "event-1" }),
            event({
              id: "event-2",
              event_name: "CreateLogStream",
              event_source: "logs.amazonaws.com",
              user_arn: SERVICE_ACTOR,
              error_code: "",
              detection_status: null,
              rule_id: null,
            }),
          ]}
        />
      </InMain>,
    );

    await expect.element(screen.getByText("CreateLogStream")).toBeVisible();
    expect(scrollOverflow(screen.container)).toBeLessThanOrEqual(0);
    await expect
      .element(screen.getByText("ana@example.com", { exact: true }))
      .toBeVisible();
  });
});
