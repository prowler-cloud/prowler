import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import { SkillMessageCard } from "./skill-message-card";

describe("SkillMessageCard", () => {
  it("names the provider and wizard step a connection guide was asked for", () => {
    // Given
    const context: LighthouseContextEnvelope = {
      schemaVersion: 1,
      transport: "inline",
      items: [
        {
          kind: "provider",
          id: "provider-wizard",
          source: "focused",
          scopeKey: "providers:wizard",
          label: "Amazon Web Services · Link a Provider",
          providerType: "aws",
        },
      ],
    };

    // When
    render(
      <SkillMessageCard
        skillRef={{
          skillId: "provider-connection-guide",
          name: "Connection Guide",
          version: 1,
        }}
        context={context}
      />,
    );

    // Then
    expect(screen.getByText("Connection Guide")).toBeInTheDocument();
    expect(
      screen.getByText("Amazon Web Services · Link a Provider"),
    ).toBeInTheDocument();
  });
});
