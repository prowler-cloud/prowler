import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// Same stubs as the sibling accordion tests: the mappers' own
// toAccordionItems (unused here) drag the findings/server-action chain into
// jsdom through these imports.
vi.mock(
  "@/components/compliance/compliance-accordion/client-accordion-content",
  () => ({ ClientAccordionContent: () => null }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-title",
  () => ({
    ComplianceAccordionTitle: ({ label }: { label: string }) => (
      <span>{label}</span>
    ),
  }),
);
vi.mock(
  "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title",
  () => ({
    // Render the row name so parity assertions can compare the per-scan
    // accordion's visible titles against the cross-account builder's.
    ComplianceAccordionRequirementTitle: ({
      name,
      type,
    }: {
      name: string;
      type: string;
    }) => (
      <>
        {type && <span>{type}</span>}
        <span>{name}</span>
      </>
    ),
  }),
);

import { mapComplianceData as mapCis } from "@/lib/compliance/cis";
import { mapComplianceData as mapEns } from "@/lib/compliance/ens";
import {
  mapComplianceData as mapGeneric,
  toAccordionItems as perScanGenericItems,
} from "@/lib/compliance/generic";

import type { CrossAccountOverviewAttributes } from "../../_types";
import { toCrossAccountAccordionItems } from "../cross-account-accordion";
import { crossAccountToMapperInput } from "../cross-account-adapter";

const ACC = "11111111-1111-4111-8111-111111111111";
const accountMeta = [{ id: ACC, uid: "123456789012", alias: "prod" }];

/** End-to-end parity harness: API payload → adapter → REAL mapper → builder.
 *  Verifies the cross-account accordion renders the same titles/hierarchy
 *  the mapper's own per-scan view derives from the same data. */
const buildAttrs = (
  requirements: CrossAccountOverviewAttributes["requirements"],
  framework: string,
): CrossAccountOverviewAttributes => ({
  compliance_id: "test",
  provider_type: "aws",
  framework,
  name: framework,
  version: "1.0",
  description: "framework description",
  accounts: accountMeta,
  scan_ids: ["scan-1"],
  scan_ids_by_account: { [ACC]: ["scan-1"] },
  requirements_passed: 0,
  requirements_failed: 0,
  requirements_manual: 0,
  total_requirements: requirements.length,
  requirements,
});

describe("cross-account pipeline parity with real mappers", () => {
  it("CIS: rows show the mapper's rich 'id - description' title", () => {
    // Shaped like the backend template for a CIS framework: bare id as
    // name, the title in description, CIS metadata fields in attributes.
    const attrs = buildAttrs(
      [
        {
          id: "2.1.1",
          name: "2.1.1",
          description: "Ensure centralized root access in AWS Organizations",
          attributes: [
            {
              Section: "2 Identity and Access Management",
              Profile: "Level 1",
              Description:
                "Ensure centralized root access in AWS Organizations",
              AssessmentStatus: "Automated",
            },
          ],
          status: "PASS",
          accounts: { [ACC]: "PASS" },
          check_ids: ["check_a"],
        },
      ],
      "CIS",
    );

    const { attributesData, requirementsData } =
      crossAccountToMapperInput(attrs);
    const data = mapCis(attributesData, requirementsData);
    const items = toCrossAccountAccordionItems(
      data,
      new Map(),
      "CIS",
      accountMeta,
    );

    // Per-scan CIS: category "2. Identity and Access Management", row title
    // = control label "2.1.1 - Ensure…".
    expect(items[0].key).toContain("2. Identity and Access Management");
    const { unmount } = render(<>{items[0].items?.[0].title}</>);
    expect(
      screen.getByText(
        "2.1.1 - Ensure centralized root access in AWS Organizations",
      ),
    ).toBeInTheDocument();
    unmount();
  });

  it("ENS: marcos on top, labeled control groups nested, type chip on rows", () => {
    const ensRequirement = (
      id: string,
      marco: string,
      grupo: string,
      tipo: string,
    ) => ({
      id,
      name: id,
      description: "Proveedor de identidad centralizado",
      attributes: [
        {
          Marco: marco,
          Categoria: "Control de acceso",
          IdGrupoControl: grupo,
          Tipo: tipo,
          Nivel: "alto",
          Dimensiones: ["trazabilidad"],
          ModoEjecucion: "automático",
          DescripcionControl: "Descripción del control",
        },
      ],
      status: "PASS" as const,
      accounts: { [ACC]: "PASS" as const },
      check_ids: ["check_a"],
    });

    const attrs = buildAttrs(
      [
        ensRequirement(
          "op.acc.1.aws.iam.2",
          "operacional",
          "op.acc.1",
          "requisito",
        ),
        ensRequirement(
          "op.acc.1.aws.iam.3",
          "operacional",
          "op.acc.1",
          "recomendacion",
        ),
        ensRequirement("org.1.aws.iam.1", "organizativo", "org.1", "requisito"),
      ],
      "ENS",
    );

    const { attributesData, requirementsData } =
      crossAccountToMapperInput(attrs);
    const data = mapEns(attributesData, requirementsData);
    const items = toCrossAccountAccordionItems(
      data,
      new Map(),
      "ENS",
      accountMeta,
    );

    // Per-scan ENS: marcos (frameworks) at the top…
    expect(items.map((item) => item.key)).toEqual([
      "operacional",
      "organizativo",
    ]);
    // …categories under the marco, control group as its own nested level.
    const category = items[0].items?.[0];
    expect(category?.key).toBe("operacional-Control de acceso");
    expect(category?.items).toHaveLength(1);
    const group = category?.items?.[0];
    expect(group?.items).toHaveLength(2);

    // Requirement rows carry the ENS type chip like per-scan.
    const { unmount } = render(<>{group?.items?.[0].title}</>);
    expect(screen.getByText("requisito")).toBeInTheDocument();
    expect(screen.getByText("op.acc.1.aws.iam.2")).toBeInTheDocument();
    unmount();
  });

  it("generic flat structure (GDPR-style): requirements render as top-level rows", () => {
    // GDPR metadata has no distinct Section, so the generic mapper stores
    // requirements directly on the framework with EMPTY categories — the
    // accordion must not come out empty (regression: blank GDPR accordion).
    const attrs = buildAttrs(
      [
        {
          id: "article_25",
          name: "Article 25: Data protection by design and by default",
          description: "Data protection by design and by default",
          attributes: [
            {
              Section: "Article 25: Data protection by design and by default",
            },
          ],
          status: "FAIL",
          accounts: { [ACC]: "FAIL" },
          check_ids: ["check_a"],
        },
        {
          id: "article_32",
          name: "Article 32: Security of processing",
          description: "Security of processing",
          attributes: [{ Section: "Article 32: Security of processing" }],
          status: "FAIL",
          accounts: { [ACC]: "FAIL" },
          check_ids: ["check_b"],
        },
      ],
      "GDPR",
    );

    const { attributesData, requirementsData } =
      crossAccountToMapperInput(attrs);
    const data = mapGeneric(attributesData, requirementsData);
    const items = toCrossAccountAccordionItems(
      data,
      new Map(),
      "GDPR",
      accountMeta,
    );

    expect(items).toHaveLength(2);
    const { unmount } = render(<>{items[0].title}</>);
    expect(
      screen.getByText("Article 25: Data protection by design and by default"),
    ).toBeInTheDocument();
    unmount();
  });

  it("PCI 3-level shape: same leaf rows as the per-scan generic accordion", () => {
    // Real pci_3.2.1_aws metadata shape: every item has SubSection; the
    // top-level requirements (2.1, 2.2) carry SubSection === Section, the
    // children carry their parent's titled SubSection. The mapper hard-codes
    // bare-id names for PCI, so bare rows are per-scan behavior, not a
    // cross-account regression.
    const pciItem = (id: string, subSection: string) => ({
      id,
      name: id,
      description: `Description for ${id}`,
      attributes: [
        {
          Section: "Requirement 2: Do not use vendor-supplied defaults",
          SubSection: subSection,
        },
      ],
      status: "FAIL" as const,
      accounts: { [ACC]: "FAIL" as const },
      check_ids: ["check_a"],
    });
    const SECTION = "Requirement 2: Do not use vendor-supplied defaults";

    const attrs = buildAttrs(
      [
        pciItem("2.1", SECTION),
        pciItem("2.2", SECTION),
        pciItem("2.1.a", "2.1 Always change vendor-supplied defaults"),
        pciItem("2.2.1", "2.2 Develop configuration standards"),
        pciItem("2.2.2", "2.2 Develop configuration standards"),
      ],
      "PCI",
    );

    const { attributesData, requirementsData } =
      crossAccountToMapperInput(attrs);
    const data = mapGeneric(attributesData, requirementsData);

    const collectLeafTitles = (items: ReturnType<typeof perScanGenericItems>) =>
      items.flatMap(function walk(item): string[] {
        const children = item.items ?? [];
        if (children.length > 0) {
          return children.flatMap(walk);
        }
        const { unmount, container } = render(<>{item.title}</>);
        const text = container.textContent ?? "";
        unmount();
        return [text];
      });

    const crossAccountLeaves = collectLeafTitles(
      toCrossAccountAccordionItems(data, new Map(), "PCI", accountMeta),
    );
    const perScanLeaves = collectLeafTitles(perScanGenericItems(data, "scan"));

    // Same leaf rows, same visible titles (chips/badges aside). The only
    // structural difference is deliberate: per-scan wraps the top-level
    // requirements in a group whose label repeats the category header;
    // cross-account flattens that redundant wrapper.
    expect(
      crossAccountLeaves.map((t) => t.replace(/Fail$/, "")).sort(),
    ).toEqual(perScanLeaves.sort());
  });
});
