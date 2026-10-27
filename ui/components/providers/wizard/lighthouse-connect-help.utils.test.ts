import { describe, expect, it } from "vitest";

import { getLighthouseScopeKey } from "@/lib/lighthouse/context/pages";

import {
  buildProviderWizardHelpContext,
  resolveConnectionMethod,
} from "./lighthouse-connect-help.utils";

const PROVIDERS_SCOPE_KEY = getLighthouseScopeKey("/providers");

describe("buildProviderWizardHelpContext", () => {
  it("describes the provider, step and method the user is on", () => {
    // When
    const context = buildProviderWizardHelpContext({
      providerType: "aws",
      providerUid: "123456789012",
      mode: "add",
      stepName: "connect",
      stepLabel: "Link a Provider",
      connectionMethod: "role",
      docsUrl: "https://goto.prowler.com/provider-aws",
    });

    // Then
    expect(context).toEqual({
      schemaVersion: 1,
      transport: "inline",
      items: [
        {
          kind: "provider",
          id: "provider-wizard",
          source: "focused",
          scopeKey: PROVIDERS_SCOPE_KEY,
          label: "AWS · Link a Provider",
          providerType: "aws",
          providerUid: "123456789012",
          wizardStep: "connect",
          wizardMode: "add",
          connectionMethod: "role",
          docsUrl: "https://goto.prowler.com/provider-aws",
        },
      ],
    });
  });

  it("asks for help choosing when no provider has been picked yet", () => {
    // When
    const context = buildProviderWizardHelpContext({
      providerType: null,
      providerUid: null,
      mode: "add",
      stepName: "connect",
      stepLabel: "Link a Provider",
      connectionMethod: null,
      docsUrl: "https://goto.prowler.com/providers",
    });

    // Then: unknown fields are left out instead of sent empty
    expect(context.items).toEqual([
      {
        kind: "provider",
        id: "provider-wizard",
        source: "focused",
        scopeKey: PROVIDERS_SCOPE_KEY,
        label: "New provider · Link a Provider",
        wizardStep: "connect",
        wizardMode: "add",
        docsUrl: "https://goto.prowler.com/providers",
      },
    ]);
  });
});

describe("resolveConnectionMethod", () => {
  it.each([
    {
      case: "an organization onboarding",
      input: { isOrganizationsFlow: true, providerType: "aws", via: null },
      expected: "organizations",
    },
    {
      case: "the method a connected account used",
      input: { isOrganizationsFlow: false, providerType: "gcp", via: "sa" },
      expected: "sa",
    },
    {
      case: "the AWS method picked but not submitted yet",
      input: {
        isOrganizationsFlow: false,
        providerType: "aws",
        via: null,
        awsDraftMethod: "credentials",
      },
      expected: "credentials",
    },
    {
      case: "the AWS default before any pick",
      input: { isOrganizationsFlow: false, providerType: "aws", via: null },
      expected: "role",
    },
    {
      case: "a provider whose method is still unknown",
      input: { isOrganizationsFlow: false, providerType: "azure", via: null },
      expected: null,
    },
  ])("resolves $case", ({ input, expected }) => {
    expect(resolveConnectionMethod(input)).toBe(expected);
  });
});
