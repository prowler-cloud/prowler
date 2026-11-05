import { render, screen } from "@testing-library/react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { GitHubPersonalAccessTokenForm } from "./github-personal-access-token-form";

// Wraps the form in a react-hook-form context so the WizardInputField mounts
// without exploding. We are testing the surrounding links, not the input.
const Harness = ({ providerUid }: { providerUid?: string }) => {
  const form = useForm();
  return (
    <FormProvider {...form}>
      <GitHubPersonalAccessTokenForm
        control={form.control}
        providerUid={providerUid}
      />
    </FormProvider>
  );
};

const USER_URL =
  "https://github.com/settings/personal-access-tokens/new?name=Prowler+Security+Scanner&description=Fine-grained+PAT+for+Prowler+security+scanning&expires_in=90&administration=read&contents=read&vulnerability_alerts=read&emails=read";

const expectSafeExternalLink = (href: string) => (name: RegExp) => {
  const link = screen.getByRole("link", { name });
  expect(link).toHaveAttribute("href", href);
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", "noopener noreferrer");
};

describe("GitHubPersonalAccessTokenForm", () => {
  it("renders the personal-repositories link with the correct href and safe target attributes", () => {
    // Given
    render(<Harness />);

    // Then
    expectSafeExternalLink(USER_URL)(
      /create a pre-configured token for personal repositories/i,
    );
  });

  it("does not render the organization link when providerUid is missing so the user is not offered an identical-looking duplicate", () => {
    // Given
    render(<Harness />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /create a pre-configured token for organization/i,
      }),
    ).not.toBeInTheDocument();
  });

  it("renders the organization link with the identifier pinned as target_name when providerUid is provided", () => {
    // Given
    render(<Harness providerUid="prowler-cloud" />);

    // When
    const orgLink = screen.getByRole("link", {
      name: /create a pre-configured token for organization prowler-cloud/i,
    });

    // Then
    expect(orgLink).toHaveAttribute("target", "_blank");
    expect(orgLink).toHaveAttribute("rel", "noopener noreferrer");
    const orgUrl = new URL(orgLink.getAttribute("href") ?? "");
    expect(orgUrl.origin + orgUrl.pathname).toBe(
      "https://github.com/settings/personal-access-tokens/new",
    );
    expect(orgUrl.searchParams.get("target_name")).toBe("prowler-cloud");
    expect(orgUrl.searchParams.get("organization_administration")).toBe("read");
    expect(orgUrl.searchParams.get("members")).toBe("read");
    expect(orgUrl.searchParams.get("emails")).toBeNull();
  });

  it("ignores whitespace around providerUid so a stray user-typed space does not hide the organization link", () => {
    // Given
    render(<Harness providerUid="   " />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /create a pre-configured token for organization/i,
      }),
    ).not.toBeInTheDocument();
  });
});
