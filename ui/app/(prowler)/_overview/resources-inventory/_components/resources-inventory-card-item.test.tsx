import { render, screen } from "@testing-library/react";
import { Shield } from "lucide-react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { ResourceInventoryItem } from "@/actions/overview";

import { ResourcesInventoryCardItem } from "./resources-inventory-card-item";

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

const baseItem: ResourceInventoryItem = {
  id: "security",
  label: "Security",
  icon: Shield,
  totalResources: 616,
  totalFindings: 319,
  failedFindings: 319,
  newFailedFindings: 64,
  severity: {
    critical: 12,
    high: 44,
    medium: 108,
    low: 155,
    informational: 0,
  },
};

describe("ResourcesInventoryCardItem", () => {
  describe("when the group has resources and failed findings", () => {
    it("builds a resources link that forwards current page filters", () => {
      render(
        <ResourcesInventoryCardItem
          item={baseItem}
          filters={{
            "filter[provider_id__in]": "aws-provider",
            "filter[account_id__in]": "account-1",
          }}
        />,
      );

      const link = screen.getByRole("link");

      expect(link).toHaveAttribute(
        "href",
        expect.stringContaining("/resources?"),
      );
      expect(link).toHaveAttribute(
        "href",
        expect.stringContaining("filter%5Bgroups__in%5D=security"),
      );
      expect(link).toHaveAttribute(
        "href",
        expect.stringContaining("filter%5Bprovider__in%5D=aws-provider"),
      );
      expect(link).toHaveAttribute(
        "href",
        expect.stringContaining("filter%5Baccount_id__in%5D=account-1"),
      );
    });

    it("renders a fail accent bar so the card is theme-agnostic", () => {
      render(<ResourcesInventoryCardItem item={baseItem} />);

      const card = screen.getByText("Security").closest("[data-slot='card']");
      const accent = card?.querySelector(
        "[data-slot='resource-stats-card-accent']",
      );

      expect(card).not.toBeNull();
      expect(accent).not.toBeNull();
    });
  });

  describe("when the group has resources but no failed findings", () => {
    it("renders a pass accent bar and the ShieldCheck badge", () => {
      render(
        <ResourcesInventoryCardItem
          item={{
            ...baseItem,
            totalFindings: 0,
            failedFindings: 0,
            newFailedFindings: 0,
          }}
        />,
      );

      const card = screen.getByText("Security").closest("[data-slot='card']");
      const accent = card?.querySelector(
        "[data-slot='resource-stats-card-accent']",
      );

      expect(accent).not.toBeNull();
      expect(screen.getByRole("link")).toBeInTheDocument();
    });
  });

  describe("when the group has no resources", () => {
    it("renders the empty state without a link", () => {
      render(
        <ResourcesInventoryCardItem
          item={{
            ...baseItem,
            totalResources: 0,
            totalFindings: 0,
            failedFindings: 0,
            newFailedFindings: 0,
          }}
        />,
      );

      expect(screen.queryByRole("link")).not.toBeInTheDocument();
      expect(screen.getByText("No Findings to display")).toBeInTheDocument();
    });
  });
});
