import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Requirement } from "@/types/compliance";

import type { CrossProviderRequirementExtras } from "../_types";
import { CrossProviderRequirementContent } from "./cross-provider-requirement-content";
import { RequirementProviderChips } from "./requirement-provider-chips";

const { clientAccordionContentMock } = vi.hoisted(() => ({
  clientAccordionContentMock: vi.fn(
    ({
      requirement,
      scanId,
    }: {
      requirement: Requirement;
      scanId: string;
      framework: string;
    }) => (
      <div data-testid="findings-content">
        {scanId}:{requirement.check_ids.join("|")}:{requirement.status}
      </div>
    ),
  ),
}));

// The real ClientAccordionContent drags the findings/server-action chain into
// jsdom; its behavior has its own tests. Here we assert the per-provider
// fan-out composition around it.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: clientAccordionContentMock }),
);

const mappedRequirement: Requirement = {
  name: "A&A-01 - Audit and Assurance Policy and Procedures",
  description: "Establish audit policies.",
  status: "FAIL",
  pass: 0,
  fail: 1,
  manual: 0,
  check_ids: ["aws_check", "azure_check"],
  scope_applicability: "IaaS",
};

const extras: CrossProviderRequirementExtras = {
  requirementId: "A&A-01",
  providers: { aws: "FAIL", azure: "PASS" },
  checkIdsByProvider: { aws: ["aws_check"], azure: ["azure_check"] },
  scanIdsByProvider: {
    aws: ["scan-aws-1", "scan-aws-2"],
    azure: ["scan-azure-1"],
  },
};

describe("RequirementProviderChips", () => {
  it("renders one status chip per provider", () => {
    render(<RequirementProviderChips providers={extras.providers} />);

    expect(screen.getByTestId("requirement-chip-aws")).toHaveTextContent(
      /fail/i,
    );
    expect(screen.getByTestId("requirement-chip-azure")).toHaveTextContent(
      /pass/i,
    );
  });
});

describe("CrossProviderRequirementContent", () => {
  it("renders one collapsed section per contributing provider scan", () => {
    render(
      <CrossProviderRequirementContent
        requirement={mappedRequirement}
        extras={extras}
        framework="CSA-CCM"
      />,
    );

    // aws has two accounts (two scans) + azure one → three sections.
    expect(screen.getByText("AWS — account 1 of 2")).toBeInTheDocument();
    expect(screen.getByText("AWS — account 2 of 2")).toBeInTheDocument();
    expect(screen.getByText("Azure")).toBeInTheDocument();
    // Lazy: findings content is not mounted until a section expands.
    expect(screen.queryByTestId("findings-content")).not.toBeInTheDocument();
  });

  it("expands a provider section into the per-scan findings scoped to that provider", async () => {
    const user = userEvent.setup();
    render(
      <CrossProviderRequirementContent
        requirement={mappedRequirement}
        extras={extras}
        framework="CSA-CCM"
      />,
    );

    await user.click(screen.getByText("Azure"));

    // The synthesized requirement narrows check_ids and status to azure's.
    expect(screen.getByTestId("findings-content")).toHaveTextContent(
      "scan-azure-1:azure_check:PASS",
    );
    const call = clientAccordionContentMock.mock.calls.at(-1)?.[0];
    expect(call?.requirement.scope_applicability).toBe("IaaS");
    expect(call?.framework).toBe("CSA-CCM");
  });
});
