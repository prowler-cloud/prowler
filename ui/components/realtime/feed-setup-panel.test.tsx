import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getFeed, saveFeed } = vi.hoisted(() => ({
  getFeed: vi.fn(),
  saveFeed: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({
  getRealtimeFeed: getFeed,
  saveRealtimeFeed: saveFeed,
  pollRealtimeFeed: vi.fn(),
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));
vi.mock("@/components/realtime/template-guide", () => ({
  TemplateGuide: () => <div>template guide</div>,
}));

import { FeedSetupPanel } from "./feed-setup-panel";

const feed = {
  id: "f1",
  provider_id: "p1",
  queue_url: "",
  region: "us-east-1",
  status: "connected",
  last_polled_at: null,
  last_event_at: null,
  last_error: "",
};

describe("FeedSetupPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getFeed.mockResolvedValue({ ok: true, data: null });
    saveFeed.mockResolvedValue({ ok: true, data: feed });
  });

  it("tells its parent when CloudTrail lookup was started", async () => {
    const user = userEvent.setup();
    const onFeedChanged = vi.fn();
    render(
      <FeedSetupPanel
        providerId="p1"
        canManage
        onFeedChanged={onFeedChanged}
      />,
    );

    await user.click(
      await screen.findByRole("button", {
        name: "Start with CloudTrail lookup",
      }),
    );

    await waitFor(() => expect(onFeedChanged).toHaveBeenCalledWith(feed));
    expect(saveFeed).toHaveBeenCalledWith({
      providerId: "p1",
      feed: { queue_url: "", region: "us-east-1" },
    });
  });

  it("tells its parent when a queue URL was saved", async () => {
    const user = userEvent.setup();
    const onFeedChanged = vi.fn();
    getFeed.mockResolvedValue({ ok: true, data: feed });
    render(
      <FeedSetupPanel
        providerId="p1"
        canManage
        onFeedChanged={onFeedChanged}
      />,
    );

    await user.type(
      await screen.findByLabelText("SQS queue URL"),
      "https://sqs.us-east-1.amazonaws.com/123456789012/q",
    );
    await user.click(screen.getByRole("button", { name: "Save feed" }));

    await waitFor(() => expect(onFeedChanged).toHaveBeenCalled());
    expect(saveFeed).toHaveBeenCalledWith(
      expect.objectContaining({
        feed: expect.objectContaining({
          queue_url: "https://sqs.us-east-1.amazonaws.com/123456789012/q",
        }),
      }),
    );
  });
});
