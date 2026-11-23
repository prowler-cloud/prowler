import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RealtimeEvent } from "@/app/(prowler)/realtime/_types";

import { followView, StreamView } from "./stream-view";

const router = vi.hoisted(() => ({ push: vi.fn(), search: "" }));

// The table's shared helpers import the server auth module; no user here.
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/realtime",
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(router.search),
}));

const event = (id: string, name: string): RealtimeEvent => ({
  id,
  event_time: "2026-11-04T10:42:18Z",
  region: "eu-west-1",
  event_source: "ec2.amazonaws.com",
  event_name: name,
  user_type: "AssumedRole",
  user_arn: "arn:aws:sts::123456789012:assumed-role/ci-deployer/gh",
  source_ip: "20.42.7.115",
  error_code: "",
  read_only: false,
  provider_id: "provider-1",
  detection_status: null,
  rule_id: null,
});

describe("followView", () => {
  it("shows everything while following", () => {
    const events = [event("a", "One"), event("b", "Two")];
    expect(followView(events, null)).toEqual({ visible: events, newCount: 0 });
  });

  it("keeps the snapshot rows and counts the rest as new", () => {
    const events = [event("c", "Three"), event("a", "One")];
    const view = followView(events, ["a"]);
    expect(view.visible.map((item) => item.id)).toEqual(["a"]);
    expect(view.newCount).toBe(1);
  });
});

describe("StreamView", () => {
  beforeEach(() => {
    router.push.mockReset();
    router.search = "tab=stream";
  });

  it("freezes the rows when follow live is off and catches up on demand", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <StreamView
        providerId="provider-1"
        events={[event("a", "PutObject")]}
        showAll={false}
      />,
    );

    await user.click(screen.getByRole("switch", { name: "Follow live" }));
    rerender(
      <StreamView
        providerId="provider-1"
        events={[event("b", "CreateAccessKey"), event("a", "PutObject")]}
        showAll={false}
      />,
    );

    expect(screen.queryByText("CreateAccessKey")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "1 new event" }));
    expect(screen.getByText("CreateAccessKey")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /new event/ }),
    ).not.toBeInTheDocument();
  });

  it("asks for read-only calls through the URL", async () => {
    const user = userEvent.setup();
    render(
      <StreamView
        providerId="provider-1"
        events={[event("a", "PutObject")]}
        showAll={false}
      />,
    );

    await user.click(screen.getByRole("switch", { name: "Changes only" }));
    expect(router.push).toHaveBeenCalledWith(
      "/realtime?tab=stream&allEvents=1",
      {
        scroll: false,
      },
    );
  });
});
