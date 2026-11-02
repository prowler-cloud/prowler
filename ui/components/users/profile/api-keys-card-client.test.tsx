import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { ApiKeysCardClient } from "./api-keys-card-client";

const { isCloudMock } = vi.hoisted(() => ({
  isCloudMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/actions/api-keys/api-keys", () => ({
  createApiKey: vi.fn(),
  updateApiKey: vi.fn(),
  revokeApiKey: vi.fn(),
}));

vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

describe("ApiKeysCardClient", () => {
  beforeEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("offers Prowler Cloud instead of creating keys on Local Server", async () => {
    // Given
    isCloudMock.mockReturnValue(false);
    const user = userEvent.setup();
    render(<ApiKeysCardClient initialApiKeys={[]} />);

    // When
    await user.click(screen.getByRole("button", { name: /Create API Key/ }));

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.API_KEYS,
    );
    expect(screen.queryByLabelText(/Expires in/)).not.toBeInTheDocument();
  });

  it("opens the create form in Prowler Cloud", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const user = userEvent.setup();
    render(<ApiKeysCardClient initialApiKeys={[]} />);

    // When
    await user.click(screen.getByRole("button", { name: /Create API Key/ }));

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    expect(await screen.findByLabelText(/Expires in/)).toBeVisible();
  });
});
