import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EventsTimeline } from "./events-timeline";

const { getResourceEventsMock } = vi.hoisted(() => ({
  getResourceEventsMock: vi.fn(),
}));

vi.mock("@/actions/resources", () => ({
  getResourceEvents: getResourceEventsMock,
}));

const mockEvent = {
  type: "resource-events" as const,
  id: "event-1",
  attributes: {
    event_time: "2026-01-26T16:05:07Z",
    event_name: "CreateStack",
    event_source: "cloudformation.amazonaws.com",
    actor: "admin-role",
    actor_uid: "arn:aws:sts::123456:assumed-role/admin-role",
    actor_type: "AssumedRole",
    source_ip_address: "192.168.1.1",
    user_agent: "aws-cli/2.0",
    request_data: { stackName: "my-stack" },
    response_data: { stackId: "arn:aws:cloudformation:..." },
    error_code: null,
    error_message: null,
  },
};

const mockErrorEvent = {
  ...mockEvent,
  id: "event-2",
  attributes: {
    ...mockEvent.attributes,
    event_name: "DeleteStack",
    error_code: "AccessDenied",
    error_message: "User is not authorized",
  },
};

describe("EventsTimeline", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows non-AWS message for non-AWS providers", () => {
    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={false} />);

    // Then
    expect(
      screen.getByText("Events timeline is only available for AWS resources."),
    ).toBeInTheDocument();
    expect(getResourceEventsMock).not.toHaveBeenCalled();
  });

  it("shows loading state while fetching events", async () => {
    // Given
    getResourceEventsMock.mockReturnValue(new Promise(() => {})); // never resolves

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText("Fetching CloudTrail events..."),
      ).toBeInTheDocument();
    });
  });

  it("renders events after successful fetch", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue({
      data: [mockEvent],
    });

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(screen.getByText("CreateStack")).toBeInTheDocument();
    });
    expect(screen.getByText("1 event")).toBeInTheDocument();
    expect(screen.getByText("admin-role")).toBeInTheDocument();
  });

  it("shows empty state when no events are returned", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue({ data: [] });

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText("No events found in the last 90 days."),
      ).toBeInTheDocument();
    });
  });

  it("shows error message when API returns an error", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue({
      error: "Provider credentials are invalid or expired.",
      status: 502,
    });

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText(
          "Provider credentials are invalid or expired. Please reconnect your AWS provider.",
        ),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Try again")).toBeInTheDocument();
  });

  it("shows 503 error message for AWS unavailability", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue({
      error: "Service Unavailable",
      status: 503,
    });

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText(
          "AWS CloudTrail is temporarily unavailable. Please try again later.",
        ),
      ).toBeInTheDocument();
    });
  });

  it("shows raw error message for other error statuses", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue({
      error: "Invalid lookback_days parameter.",
      status: 400,
    });

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText("Invalid lookback_days parameter."),
      ).toBeInTheDocument();
    });
  });

  it("expands event to show detail card on click", async () => {
    // Given
    const user = userEvent.setup();
    getResourceEventsMock.mockResolvedValue({ data: [mockEvent] });

    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    await waitFor(() => {
      expect(screen.getByText("CreateStack")).toBeInTheDocument();
    });

    // When - click the event row to expand
    await user.click(screen.getByText("CreateStack"));

    // Then - detail card should show expanded info
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    expect(screen.getByText("AssumedRole")).toBeInTheDocument();
    expect(screen.getByText("Request")).toBeInTheDocument();
    expect(screen.getByText("Response")).toBeInTheDocument();
  });

  it("collapses event when clicked again", async () => {
    // Given
    const user = userEvent.setup();
    getResourceEventsMock.mockResolvedValue({ data: [mockEvent] });

    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    await waitFor(() => {
      expect(screen.getByText("CreateStack")).toBeInTheDocument();
    });

    // When - expand then collapse (use getAllByText since expanded card also shows event name)
    await user.click(screen.getByText("CreateStack"));
    expect(screen.getByText("Request")).toBeInTheDocument();

    await user.click(screen.getAllByText("CreateStack")[0]);

    // Then
    expect(screen.queryByText("Request")).not.toBeInTheDocument();
  });

  it("shows error banner for events with error codes", async () => {
    // Given
    const user = userEvent.setup();
    getResourceEventsMock.mockResolvedValue({
      data: [mockErrorEvent],
    });

    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    await waitFor(() => {
      expect(screen.getByText("DeleteStack")).toBeInTheDocument();
    });

    // When
    await user.click(screen.getByText("DeleteStack"));

    // Then
    expect(screen.getByText("AccessDenied")).toBeInTheDocument();
    expect(screen.getByText("User is not authorized")).toBeInTheDocument();
  });

  it("refetches events when include read events checkbox is toggled", async () => {
    // Given
    const user = userEvent.setup();
    getResourceEventsMock.mockResolvedValue({ data: [mockEvent] });

    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    await waitFor(() => {
      expect(screen.getByText("CreateStack")).toBeInTheDocument();
    });

    expect(getResourceEventsMock).toHaveBeenCalledWith("resource-1", {
      includeReadEvents: false,
    });

    // When
    await user.click(screen.getByRole("checkbox"));

    // Then
    await waitFor(() => {
      expect(getResourceEventsMock).toHaveBeenCalledWith("resource-1", {
        includeReadEvents: true,
      });
    });
  });

  it("retries fetch when retry button is clicked", async () => {
    // Given
    const user = userEvent.setup();
    getResourceEventsMock
      .mockResolvedValueOnce({ error: "Something went wrong", status: 500 })
      .mockResolvedValueOnce({ data: [mockEvent] });

    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    await waitFor(() => {
      expect(screen.getByText("Try again")).toBeInTheDocument();
    });

    // When
    await user.click(screen.getByText("Try again"));

    // Then
    await waitFor(() => {
      expect(screen.getByText("CreateStack")).toBeInTheDocument();
    });
    expect(getResourceEventsMock).toHaveBeenCalledTimes(2);
  });

  it("handles null response gracefully", async () => {
    // Given
    getResourceEventsMock.mockResolvedValue(null);

    // When
    render(<EventsTimeline resourceId="resource-1" isAwsProvider={true} />);

    // Then
    await waitFor(() => {
      expect(
        screen.getByText("Failed to fetch events. Please try again."),
      ).toBeInTheDocument();
    });
  });
});
