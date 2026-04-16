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
    it("should keep the resource link behavior while using a neutral card container", () => {
      // Given
      render(
        <ResourcesInventoryCardItem
          item={baseItem}
          filters={{
            "filter[provider_id__in]": "aws-provider",
            "filter[account_id__in]": "account-1",
          }}
        />,
      );

      // When
      const link = screen.getByRole("link");
      const card = screen.getByText("Security").closest("[data-slot='card']");

      // Then
      expect(card).not.toBeNull();
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
      expect(card).toHaveClass("border-border-neutral-secondary");
      expect(card).toHaveClass("bg-bg-neutral-secondary");
      expect(card!.className).toContain("before:bg-bg-fail-primary");
      expect(card!.className).not.toContain("bg-[rgba(67,34,50,0.2)]");
    });
  });

  describe("when the group has no resources", () => {
    it("should render the empty state without a resources link", () => {
      // Given
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

      // Then
      expect(screen.queryByRole("link")).not.toBeInTheDocument();
      expect(screen.getByText("No Findings to display")).toBeInTheDocument();
    });
  });
});
