import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { CheckProviderTypesMap, Requirement } from "@/types/compliance";

import type { CrossProviderRequirementExtras } from "../_types";
import { CrossProviderRequirementContent } from "./cross-provider-requirement-content";
import { RequirementProviderChips } from "./requirement-provider-chips";

const { clientAccordionContentMock } = vi.hoisted(() => ({
  clientAccordionContentMock: vi.fn(
    ({
      requirement,
      scanIds,
    }: {
      requirement: Requirement;
      scanIds: string[];
      framework: string;
      checkProviders: CheckProviderTypesMap;
      disableFindings?: boolean;
    }) => (
      <div data-testid="findings-content">
        {scanIds.join("|")}:{requirement.check_ids.join("|")}:
        {requirement.status}
      </div>
    ),
  ),
}));

// The real ClientAccordionContent drags the findings/server-action chain into
// jsdom; its behavior has its own tests. Here we assert the combined-view
// composition around it.
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
  check_ids: ["aws_check", "azure_check", "shared_check"],
  scope_applicability: "IaaS",
};

const extras: CrossProviderRequirementExtras = {
  requirementId: "A&A-01",
  providers: { aws: "FAIL", azure: "PASS" },
  checkIdsByProvider: {
    aws: ["aws_check", "shared_check"],
    azure: ["azure_check", "shared_check"],
  },
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
  it("renders the requirement once with all contributing scans combined", () => {
    clientAccordionContentMock.mockClear();
    render(
      <CrossProviderRequirementContent
        requirement={mappedRequirement}
        extras={extras}
        framework="CSA-CCM"
      />,
    );

    // One combined block — no per-provider sections repeating the detail.
    expect(clientAccordionContentMock).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/account 1 of/)).not.toBeInTheDocument();
    expect(screen.getByTestId("findings-content")).toHaveTextContent(
      "scan-aws-1|scan-aws-2|scan-azure-1:aws_check|azure_check|shared_check:FAIL",
    );

    // The mapped requirement passes through untouched (union checks,
    // roll-up status, detail fields for getDetailsComponent).
    const call = clientAccordionContentMock.mock.calls.at(-1)?.[0];
    expect(call?.requirement).toBe(mappedRequirement);
    expect(call?.framework).toBe("CSA-CCM");
    expect(call?.disableFindings).toBe(false);
  });

  it("labels each check with the provider types that declare it", () => {
    clientAccordionContentMock.mockClear();
    render(
      <CrossProviderRequirementContent
        requirement={mappedRequirement}
        extras={extras}
        framework="CSA-CCM"
      />,
    );

    const call = clientAccordionContentMock.mock.calls.at(-1)?.[0];
    expect(call?.checkProviders).toEqual({
      aws_check: ["aws"],
      azure_check: ["azure"],
      shared_check: ["aws", "azure"],
    });
  });

  it("disables findings when no provider contributed any check", () => {
    clientAccordionContentMock.mockClear();
    render(
      <CrossProviderRequirementContent
        requirement={{ ...mappedRequirement, check_ids: [], status: "MANUAL" }}
        extras={{
          ...extras,
          providers: { aws: "MANUAL", azure: "MANUAL" },
          checkIdsByProvider: {},
        }}
        framework="CSA-CCM"
      />,
    );

    const call = clientAccordionContentMock.mock.calls.at(-1)?.[0];
    expect(call?.disableFindings).toBe(true);
  });

  it("shows an empty state when no provider scan contributed", () => {
    clientAccordionContentMock.mockClear();
    render(
      <CrossProviderRequirementContent
        requirement={mappedRequirement}
        extras={{ ...extras, providers: {} }}
        framework="CSA-CCM"
      />,
    );

    expect(
      screen.getByText(/No provider scan contributed/),
    ).toBeInTheDocument();
    expect(clientAccordionContentMock).not.toHaveBeenCalled();
  });
});
