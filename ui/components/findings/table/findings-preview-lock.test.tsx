import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { FindingsPreviewLock } from "./findings-preview-lock";

describe("FindingsPreviewLock", () => {
  beforeEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("tells the user how much of the list is hidden and opens the paid plan upgrade", async () => {
    // Given
    const user = userEvent.setup();
    render(<FindingsPreviewLock totalCount={1234} />);

    // When
    await user.click(
      screen.getByRole("button", { name: "Unlock All Findings" }),
    );

    // Then
    expect(
      screen.getByText("Showing the 10 most critical of 1,234 finding groups"),
    ).toBeInTheDocument();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW,
    );
  });
});
