import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LighthouseIcon } from "./Icons";

describe("LighthouseIcon", () => {
  it("keeps gradient ids unique across instances", () => {
    // Given: the icon rendered several times on one page (sidebar, navbar,
    // overview banner) — with duplicate ids, browsers resolve url(#...)
    // against the first instance, which may sit in a display:none subtree
    // (the desktop sidebar on mobile) and leave the others unpainted.
    const { container } = render(
      <>
        <LighthouseIcon />
        <LighthouseIcon />
        <LighthouseIcon animatedAura />
      </>,
    );

    // Then: every gradient id is unique document-wide
    const ids = Array.from(
      container.querySelectorAll("linearGradient, radialGradient"),
    ).map((gradient) => gradient.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("paints every path from its own instance's defs", () => {
    // Given
    const { container } = render(<LighthouseIcon />);
    const svg = container.querySelector("svg") as SVGElement;
    const localIds = new Set(
      Array.from(svg.querySelectorAll("linearGradient, radialGradient")).map(
        (gradient) => gradient.id,
      ),
    );

    // Then: every fill/stroke reference resolves inside this same svg
    const references = Array.from(svg.querySelectorAll("path"))
      .flatMap((path) => [
        path.getAttribute("fill"),
        path.getAttribute("stroke"),
      ])
      .filter((paint): paint is string => paint?.startsWith("url(#") ?? false);
    expect(references.length).toBeGreaterThan(0);
    for (const reference of references) {
      const id = reference.slice("url(#".length, -1);
      expect(localIds.has(id)).toBe(true);
    }
  });
});
