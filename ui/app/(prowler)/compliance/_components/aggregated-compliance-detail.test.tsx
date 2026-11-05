import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AggregatedComplianceDetail } from "./aggregated-compliance-detail";

vi.mock("@/components/compliance", () => ({
  ClientAccordionWrapper: () => <div />,
  RequirementsStatusCard: () => <div />,
  TopFailedSectionsCard: () => <div />,
}));

describe("AggregatedComplianceDetail", () => {
  it("stacks actions on mobile and keeps the link after the title on desktop", () => {
    // Given / When
    const { container } = render(
      <AggregatedComplianceDetail
        compliancetitle="CSA-CCM"
        logoPath="/csa.svg"
        title={<span>CSA Cloud Controls Matrix</span>}
        description={<p>5 of 5 compatible providers scanned</p>}
        headerLink={<a href="https://hub.prowler.com">View on Prowler Hub</a>}
        reportAction={<button type="button">Report</button>}
        filters={<div>Filters</div>}
        totals={{ pass: 1, fail: 2, manual: 3 }}
        coverage={<div>Coverage</div>}
        topFailed={{ sections: [], dataType: "sections" }}
        accordionItems={[]}
        initialExpandedKeys={[]}
      />,
    );

    // Then
    const logo = screen.getByAltText("CSA-CCM logo");
    const header = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-header"]',
    );
    const heading = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-heading"]',
    );
    const title = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-title"]',
    );
    const description = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-description"]',
    );
    const headerLink = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-header-link"]',
    );
    const reportAction = container.querySelector<HTMLElement>(
      '[data-slot="aggregated-compliance-report-action"]',
    );
    if (
      !header ||
      !heading ||
      !title ||
      !description ||
      !headerLink ||
      !reportAction
    ) {
      throw new Error("Expected every aggregated compliance header region");
    }

    expect(header).toHaveClass("sm:grid-cols-[auto_minmax(0,1fr)_auto]");
    expect(heading).toHaveClass(
      "contents",
      "sm:grid",
      "sm:grid-cols-[minmax(0,max-content)_auto]",
      "sm:items-center",
      "sm:justify-start",
      "sm:gap-x-4",
    );
    expect(heading).toContainElement(title);
    expect(heading).toContainElement(description);
    expect(heading).toContainElement(headerLink);
    expect(title).toHaveClass(
      "col-start-2",
      "row-start-1",
      "min-w-0",
      "truncate",
    );
    expect(description).toHaveClass("col-span-2", "row-start-2");
    expect(headerLink).toHaveClass("col-span-2", "row-start-3");
    expect(reportAction).toHaveClass(
      "col-span-2",
      "row-start-4",
      "sm:col-start-3",
    );

    const orderedElements = [
      logo,
      title,
      description,
      headerLink,
      reportAction,
    ];
    orderedElements.slice(0, -1).forEach((element, index) => {
      expect(
        element.compareDocumentPosition(orderedElements[index + 1]!) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    });
  });

  it("places the report directly after information when no header link exists", () => {
    // Given / When
    const { container } = render(
      <AggregatedComplianceDetail
        compliancetitle="Custom"
        title={<span>Custom Framework</span>}
        description={<p>2 accounts aggregated</p>}
        reportAction={<button type="button">Report</button>}
        filters={<div>Filters</div>}
        totals={{ pass: 1, fail: 2, manual: 3 }}
        coverage={<div>Coverage</div>}
        topFailed={{ sections: [], dataType: "sections" }}
        accordionItems={[]}
        initialExpandedKeys={[]}
      />,
    );

    // Then
    expect(
      container.querySelector('[data-slot="aggregated-compliance-title"]'),
    ).toHaveClass("col-start-1", "row-start-1");
    expect(
      container.querySelector(
        '[data-slot="aggregated-compliance-description"]',
      ),
    ).toHaveClass("col-start-1", "row-start-2");
    expect(
      container.querySelector(
        '[data-slot="aggregated-compliance-report-action"]',
      ),
    ).toHaveClass("col-start-1", "row-start-3");
    expect(
      container.querySelector(
        '[data-slot="aggregated-compliance-header-link"]',
      ),
    ).not.toBeInTheDocument();
  });
});
