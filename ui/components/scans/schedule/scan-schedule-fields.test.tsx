import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { getScheduleFormDefaults } from "@/lib/schedules";
import type { ScheduleFormValues } from "@/types/schedules";

import { ScanScheduleFields } from "./scan-schedule-fields";

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "setPointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

function ScheduleFieldsHarness({
  canUseAdvancedSchedule = true,
  showCloudUpgradeBadge = false,
}: {
  canUseAdvancedSchedule?: boolean;
  showCloudUpgradeBadge?: boolean;
} = {}) {
  const form = useForm<ScheduleFormValues>({
    defaultValues: getScheduleFormDefaults(),
  });

  return (
    <ScanScheduleFields
      form={form}
      showNextScheduledCopy
      canUseAdvancedSchedule={canUseAdvancedSchedule}
      showCloudUpgradeBadge={showCloudUpgradeBadge}
    />
  );
}

function getHelperCopy(text: RegExp) {
  return screen.getByText((_, element) => {
    return (
      element?.tagName.toLowerCase() === "p" &&
      text.test(element.textContent ?? "")
    );
  });
}

describe("ScanScheduleFields", () => {
  it("updates the helper copy when the cadence changes to interval", async () => {
    // Given
    const user = userEvent.setup();
    render(<ScheduleFieldsHarness />);

    expect(getHelperCopy(/Daily/)).toBeInTheDocument();

    // When
    await user.click(screen.getByRole("combobox", { name: /repeats/i }));
    await user.click(screen.getByRole("option", { name: /every 48 hours/i }));

    // Then
    expect(getHelperCopy(/Every 48 hours/)).toBeInTheDocument();
    expect(
      screen.queryByText((_, element) => {
        return (
          element?.tagName.toLowerCase() === "p" &&
          /Daily/.test(element.textContent ?? "")
        );
      }),
    ).not.toBeInTheDocument();
  });

  it("uses ordinal copy for monthly schedules", async () => {
    // Given
    const user = userEvent.setup();
    render(<ScheduleFieldsHarness />);

    // When
    await user.click(screen.getByRole("combobox", { name: /repeats/i }));
    await user.click(screen.getByRole("option", { name: /monthly/i }));

    // Then
    expect(getHelperCopy(/Monthly on the 1st/)).toBeInTheDocument();
    expect(getHelperCopy(/Monthly on the 1st/)).not.toHaveTextContent(
      /Monthly on day/,
    );
  });

  it("shows a single cloud badge beside the Scan Schedule title when advanced controls are locked", () => {
    // Given
    render(
      <ScheduleFieldsHarness
        canUseAdvancedSchedule={false}
        showCloudUpgradeBadge
      />,
    );

    // Then
    expect(screen.getAllByText("Available in Prowler Cloud")).toHaveLength(1);
    expect(screen.getByText("Scan Schedule").parentElement).toHaveTextContent(
      "Available in Prowler Cloud",
    );
    expect(screen.getByText("Scan Time").parentElement).not.toHaveTextContent(
      "Available in Prowler Cloud",
    );
    expect(screen.getByText("Repeats").parentElement).not.toHaveTextContent(
      "Available in Prowler Cloud",
    );
    expect(
      screen.getByText(
        "Prowler Open Source only supports daily scheduled scans. A daily scan will run automatically once the account is connected.",
      ),
    ).toBeVisible();
  });
});
