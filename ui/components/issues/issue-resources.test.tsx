import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IssueResources } from "./issue-resources";

const UID = "arn:aws:s3:::acme-customer-exports";

describe("IssueResources", () => {
  it("links each resource to the Resources page of its provider", () => {
    render(<IssueResources resources={[UID]} providerId="provider-1" />);

    expect(
      screen.getByRole("link", { name: `Open in Resources: ${UID}` }),
    ).toHaveAttribute(
      "href",
      `/resources?filter%5Buid%5D=${encodeURIComponent(UID)}&filter%5Bprovider_id__in%5D=provider-1`,
    );
  });

  it("lists sample resources without a link, since Resources has no sample data", () => {
    render(<IssueResources resources={[UID]} providerId="sample-provider" />);

    expect(screen.getByText(UID)).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
