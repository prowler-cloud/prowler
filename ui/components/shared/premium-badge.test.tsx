import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { TooltipProvider } from "@/components/shadcn/tooltip";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
} from "@/types/cloud-upgrade";

import { PremiumBadge } from "./premium-badge";

describe("PremiumBadge", () => {
  afterEach(() => {
    cleanup();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("opens the upgrade modal for its feature and surface", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <TooltipProvider>
        <PremiumBadge
          feature={CLOUD_UPGRADE_FEATURE.REALTIME}
          surface={CLOUD_UPGRADE_SURFACE.PREVIEW_PAGE}
        />
      </TooltipProvider>,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Premium feature/ }));

    // Then
    const state = useCloudUpgradeStore.getState();
    expect(state.activeFeature).toBe(CLOUD_UPGRADE_FEATURE.REALTIME);
    expect(state.surface).toBe(CLOUD_UPGRADE_SURFACE.PREVIEW_PAGE);
  });
});
