import { describe, expect, it } from "vitest";

import { handleRegistryLogo } from "@/__tests__/msw/handlers/registry";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";

import { ProviderTypeIcon, RegistryLogosProvider } from "./provider-type-icon";

// Keep even speculative browser requests on loopback; MSW serves the image.
const LOGO_URL = "https://127.0.0.1/providers/vcf/logo.png";

describe("ProviderTypeIcon for a dynamic provider", () => {
  it("shows the generic glyph until the streamed logos arrive, then the registry logo", async () => {
    // Given
    worker.use(handleRegistryLogo(LOGO_URL));
    let resolveLogos!: (logos: Record<string, string>) => void;
    const logos = new Promise<Record<string, string>>((resolve) => {
      resolveLogos = resolve;
    });
    const screen = await render(
      <RegistryLogosProvider logos={logos}>
        <ProviderTypeIcon type="vcf" size={35} />
      </RegistryLogosProvider>,
    );
    const logoImage = () => screen.container.querySelector("img");

    // Then: the icon renders while the registry has not answered.
    expect(screen.container.querySelector("svg")).not.toBeNull();
    expect(logoImage()).toBeNull();

    // When
    resolveLogos({ vcf: LOGO_URL });

    // Then
    await expect.poll(() => logoImage()?.getAttribute("src")).toBe(LOGO_URL);
    await expect.poll(() => logoImage()?.naturalWidth).toBe(1);
  });
});
