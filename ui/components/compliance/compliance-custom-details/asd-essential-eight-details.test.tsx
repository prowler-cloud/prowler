import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

// `CustomLink` re-imports the `@/lib` barrel which transitively pulls in
// `next-auth` (server-only). Stub it with a plain anchor — we only need
// the `<a>` semantics here so the regex/extraction tests can assert on
// `href` and accessible name.
vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

import {
  type ASDEssentialEightRequirement,
  type Requirement,
  REQUIREMENT_STATUS,
} from "@/types/compliance";

import { ASDEssentialEightCustomDetails } from "./asd-essential-eight-details";

const fullRequirement: ASDEssentialEightRequirement = {
  name: "E8-PA-1",
  description: "Apply patches to internet-facing applications.",
  status: REQUIREMENT_STATUS.PASS,
  pass: 1,
  fail: 0,
  manual: 0,
  check_ids: ["check_one"],
  maturity_level: "ML1",
  assessment_status: "Automated",
  cloud_applicability: "full",
  mitigated_threats: ["T1190", "T1059"],
  implementation_notes: "Use SSM Patch Manager for AWS workloads.",
  rationale_statement: "Unpatched apps are commonly exploited.",
  impact_statement: "Increases blast radius of public-facing CVEs.",
  remediation_procedure: "Run **patch baseline** weekly.",
  audit_procedure: "Verify *baseline compliance*.",
  additional_information: "Refer to internal SOPs.",
  references: "https://example.com/a, https://example.com/b",
};

const emptyRequirement: Requirement = {
  name: "E8-EMPTY",
  description: "",
  status: REQUIREMENT_STATUS.MANUAL,
  pass: 0,
  fail: 0,
  manual: 1,
  check_ids: [],
};

describe("ASDEssentialEightCustomDetails", () => {
  describe("with a fully populated requirement", () => {
    it("renders every textual section", () => {
      render(<ASDEssentialEightCustomDetails requirement={fullRequirement} />);

      expect(screen.getByText("Description")).toBeInTheDocument();
      expect(
        screen.getByText("Apply patches to internet-facing applications."),
      ).toBeInTheDocument();

      expect(screen.getByText("Implementation Notes")).toBeInTheDocument();
      expect(
        screen.getByText("Use SSM Patch Manager for AWS workloads."),
      ).toBeInTheDocument();

      expect(screen.getByText("Rationale Statement")).toBeInTheDocument();
      expect(screen.getByText("Impact Statement")).toBeInTheDocument();
      expect(screen.getByText("Additional Information")).toBeInTheDocument();
      expect(screen.getByText("Refer to internal SOPs.")).toBeInTheDocument();
    });

    it("renders the three classification badges with their values", () => {
      render(<ASDEssentialEightCustomDetails requirement={fullRequirement} />);

      expect(screen.getByText("Maturity Level:")).toBeInTheDocument();
      expect(screen.getByText("ML1")).toBeInTheDocument();

      expect(screen.getByText("Assessment:")).toBeInTheDocument();
      expect(screen.getByText("Automated")).toBeInTheDocument();

      expect(screen.getByText("Cloud Applicability:")).toBeInTheDocument();
      expect(screen.getByText("full")).toBeInTheDocument();
    });

    it("does not render invalid ASD classification values", () => {
      render(
        <ASDEssentialEightCustomDetails
          requirement={{
            ...fullRequirement,
            maturity_level: "ML4",
            assessment_status: "Partially automated",
            cloud_applicability: "hybrid",
          }}
        />,
      );

      expect(screen.queryByText("Maturity Level:")).not.toBeInTheDocument();
      expect(screen.queryByText("Assessment:")).not.toBeInTheDocument();
      expect(
        screen.queryByText("Cloud Applicability:"),
      ).not.toBeInTheDocument();
    });

    it("renders mitigated threats as individual chips", () => {
      render(<ASDEssentialEightCustomDetails requirement={fullRequirement} />);

      expect(screen.getByText("Mitigated Threats")).toBeInTheDocument();
      expect(screen.getByText("T1190")).toBeInTheDocument();
      expect(screen.getByText("T1059")).toBeInTheDocument();
    });

    it("renders Remediation and Audit procedures as markdown", () => {
      render(<ASDEssentialEightCustomDetails requirement={fullRequirement} />);

      // The markdown renderer transforms `**patch baseline**` into a <strong>
      // and `*baseline compliance*` into an <em>. Asserting on the rendered
      // tags is what makes this a behavioral test rather than a string grep.
      expect(screen.getByText("Remediation Procedure")).toBeInTheDocument();
      expect(screen.getByText("patch baseline").tagName).toBe("STRONG");

      expect(screen.getByText("Audit Procedure")).toBeInTheDocument();
      expect(screen.getByText("baseline compliance").tagName).toBe("EM");
    });

    it("extracts every URL from the comma-separated References field", () => {
      render(<ASDEssentialEightCustomDetails requirement={fullRequirement} />);

      expect(screen.getByText("References")).toBeInTheDocument();
      const linkA = screen.getByRole("link", {
        name: "https://example.com/a",
      });
      const linkB = screen.getByRole("link", {
        name: "https://example.com/b",
      });
      expect(linkA).toHaveAttribute("href", "https://example.com/a");
      expect(linkB).toHaveAttribute("href", "https://example.com/b");
    });

    it("preserves http:// references (regex must not silently drop plain HTTP)", () => {
      render(
        <ASDEssentialEightCustomDetails
          requirement={{
            ...fullRequirement,
            references:
              "http://insecure.example.com/x https://secure.example.com/y",
          }}
        />,
      );

      expect(
        screen.getByRole("link", { name: "http://insecure.example.com/x" }),
      ).toHaveAttribute("href", "http://insecure.example.com/x");
      expect(
        screen.getByRole("link", { name: "https://secure.example.com/y" }),
      ).toHaveAttribute("href", "https://secure.example.com/y");
    });
  });

  describe("with an empty requirement", () => {
    it("renders nothing inside the container when every optional field is missing", () => {
      const { container } = render(
        <ASDEssentialEightCustomDetails requirement={emptyRequirement} />,
      );

      // No section headings should be rendered for an empty requirement.
      for (const heading of [
        "Description",
        "Implementation Notes",
        "Rationale Statement",
        "Impact Statement",
        "Remediation Procedure",
        "Audit Procedure",
        "Additional Information",
        "Mitigated Threats",
        "References",
      ]) {
        expect(screen.queryByText(heading)).not.toBeInTheDocument();
      }

      // No badges either.
      for (const label of [
        "Maturity Level:",
        "Assessment:",
        "Cloud Applicability:",
      ]) {
        expect(screen.queryByText(label)).not.toBeInTheDocument();
      }

      // The outer container still exists (an empty flex column) but it
      // shouldn't carry any rendered children.
      const outer = container.firstElementChild as HTMLElement | null;
      expect(outer).not.toBeNull();
      expect(outer?.children.length).toBe(1); // only the empty badge container
    });

    it("ignores a non-string References field (no broken link rendered)", () => {
      render(
        <ASDEssentialEightCustomDetails
          requirement={{
            ...emptyRequirement,
            references: undefined,
          }}
        />,
      );

      expect(screen.queryByText("References")).not.toBeInTheDocument();
      expect(screen.queryByRole("link")).not.toBeInTheDocument();
    });

    it("ignores a non-string-array `mitigated_threats` field", () => {
      render(
        <ASDEssentialEightCustomDetails
          requirement={{
            ...emptyRequirement,
            mitigated_threats: [{ not: "a string" }],
          }}
        />,
      );

      expect(screen.queryByText("Mitigated Threats")).not.toBeInTheDocument();
    });
  });
});
