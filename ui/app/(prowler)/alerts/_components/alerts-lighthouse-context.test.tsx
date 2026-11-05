import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AlertRule } from "../_types";

import { AlertsLighthouseContext } from "./alerts-lighthouse-context";

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="alerts-context">{JSON.stringify(item)}</output>
  ),
}));

const editingAlert = {
  id: "alert-1",
  attributes: {
    name: "Critical S3 findings",
    enabled: true,
    trigger: "scan_completed",
  },
} as unknown as AlertRule;

describe("AlertsLighthouseContext", () => {
  it("publishes the alert rules summary as Lighthouse context", () => {
    render(<AlertsLighthouseContext totalCount={12} editingAlert={null} />);

    const context = screen.getByTestId("alerts-context");
    expect(context).toHaveTextContent('"kind":"alert"');
    expect(context).toHaveTextContent('"label":"12 alert rules"');
    expect(context).toHaveTextContent('"total":12');
  });

  it("publishes the edited rule as focused context", () => {
    render(
      <AlertsLighthouseContext totalCount={12} editingAlert={editingAlert} />,
    );

    const contexts = screen.getAllByTestId("alerts-context");
    expect(contexts).toHaveLength(2);
    expect(contexts[1]).toHaveTextContent('"source":"focused"');
    expect(contexts[1]).toHaveTextContent('"label":"Critical S3 findings"');
    expect(contexts[1]).toHaveTextContent('"trigger":"scan_completed"');
    expect(contexts[1]).toHaveTextContent('"enabled":true');
  });
});
