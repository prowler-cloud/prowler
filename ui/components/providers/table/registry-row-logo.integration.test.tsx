import { describe, expect, it } from "vitest";

import { handleRegistryLogo } from "@/__tests__/msw/handlers/registry";
import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";

import { RegistryLogosContext, RegistryRowLogo } from "./registry-row-logo";

const LOGO_URL = "https://media.registry.example.com/providers/vcf/logo.png";

describe("registry row logo", () => {
  it("shows the generic glyph until the streamed logos arrive, then the registry logo", async () => {
    // Given
    worker.use(handleRegistryLogo(LOGO_URL));
    let resolveLogos!: (logos: Record<string, string>) => void;
    const logos = new Promise<Record<string, string>>((resolve) => {
      resolveLogos = resolve;
    });
    const screen = await render(
      <RegistryLogosContext value={logos}>
        <RegistryRowLogo type="vcf" />
      </RegistryLogosContext>,
    );
    const logoImage = () => screen.container.querySelector("img");

    // Then: the row renders while the registry has not answered.
    expect(screen.container.querySelector("svg")).not.toBeNull();
    expect(logoImage()).toBeNull();

    // When
    resolveLogos({ vcf: LOGO_URL });

    // Then
    await expect.poll(() => logoImage()?.getAttribute("src")).toBe(LOGO_URL);
  });
});
