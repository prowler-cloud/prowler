import { render, screen } from "@testing-library/react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { CloudflareTokenCredentials } from "@/types";

import { CloudflareApiTokenCredentialsForm } from "./cloudflare-api-token-credentials-form";

// Wraps the form in a react-hook-form context so the WizardInputField mounts
// without exploding. We are testing the surrounding links, not the input.
const Harness = ({ providerUid }: { providerUid?: string }) => {
  const form = useForm<CloudflareTokenCredentials>();
  return (
    <FormProvider {...form}>
      <CloudflareApiTokenCredentialsForm
        control={form.control}
        providerUid={providerUid}
      />
    </FormProvider>
  );
};

const USER_URL =
  "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22read%22%7D%5D&accountId=%2A&zoneId=all&name=Prowler%20Security%20Scanner";

describe("CloudflareApiTokenCredentialsForm", () => {
  it("always renders the User API Token link with the correct href and safe target attributes", () => {
    // Given
    render(<Harness />);

    // When
    const link = screen.getByRole("link", {
      name: /create a pre-configured user api token/i,
    });

    // Then
    expect(link).toHaveAttribute("href", USER_URL);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("does not render the Account-Owned link when providerUid is missing so the user is not offered an ambiguous duplicate", () => {
    // Given
    render(<Harness />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /create a pre-configured account-owned api token/i,
      }),
    ).not.toBeInTheDocument();
  });

  it("renders the Account-Owned link routed through Cloudflare's dashboard `to=` param with the account id substituted when providerUid is provided", () => {
    // Given
    render(<Harness providerUid="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" />);

    // When
    const link = screen.getByRole("link", {
      name: /create a pre-configured account-owned api token/i,
    });

    // Then
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    const parsed = new URL(link.getAttribute("href") ?? "");
    expect(parsed.origin).toBe("https://dash.cloudflare.com");
    expect(parsed.pathname).toBe("/");
    expect(parsed.searchParams.get("to")).toBe(
      "/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/api-tokens",
    );
    expect(parsed.searchParams.get("name")).toBe("Prowler Security Scanner");
  });

  it("ignores whitespace around providerUid so a stray user-typed space does not hide the Account-Owned link", () => {
    // Given
    render(<Harness providerUid="   " />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /create a pre-configured account-owned api token/i,
      }),
    ).not.toBeInTheDocument();
  });
});
