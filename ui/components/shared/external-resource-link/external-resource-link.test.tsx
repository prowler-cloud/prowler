import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ExternalResourceLink } from "./external-resource-link";

describe("ExternalResourceLink", () => {
  it("renders an AWS Console link for AWS resources with a valid ARN", () => {
    const arn = "arn:aws:s3:::example-bucket";
    render(<ExternalResourceLink providerType="aws" resourceUid={arn} />);

    const link = screen.getByRole("link", {
      name: /open resource in aws console/i,
    });
    expect(link).toHaveAttribute(
      "href",
      `https://console.aws.amazon.com/go/view?arn=${encodeURIComponent(arn)}`,
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveTextContent("View in AWS Console");
  });

  it("renders a repository link for IaC resources", () => {
    render(
      <ExternalResourceLink
        providerType="iac"
        providerUid="https://github.com/example/repo"
        resourceName="main.tf"
        findingUid="check-id-main.tf-10:15"
        region="develop"
      />,
    );

    const link = screen.getByRole("link", {
      name: /open resource in the repository/i,
    });
    expect(link).toHaveAttribute(
      "href",
      "https://github.com/example/repo/blob/develop/main.tf#L10-L15",
    );
    expect(link).toHaveTextContent("View in Repository");
  });

  it("renders nothing for AWS resources without a valid ARN", () => {
    const { container } = render(
      <ExternalResourceLink providerType="aws" resourceUid="not-an-arn" />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for IaC resources missing repo url or filename", () => {
    const { container } = render(
      <ExternalResourceLink
        providerType="iac"
        providerUid=""
        resourceName="main.tf"
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for providers without external link support", () => {
    const { container } = render(
      <ExternalResourceLink
        providerType="azure"
        resourceUid="/subscriptions/abc/resourceGroups/rg"
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
