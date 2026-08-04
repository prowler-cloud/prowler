import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { createSamlConfig, updateSamlConfig } from "./saml";

const buildFormData = ({
  additionalEmailDomains = [],
  id,
}: {
  additionalEmailDomains?: string[];
  id?: string;
}) => {
  const formData = new FormData();
  formData.set("email_domain", " Primary.Example.com ");
  formData.set("metadata_xml", " <EntityDescriptor /> ");
  if (id) formData.set("id", id);
  additionalEmailDomains.forEach((domain) =>
    formData.append("additional_email_domains", domain),
  );
  return formData;
};

const getRequestBody = () => {
  const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
  return JSON.parse(String(request.body));
};

describe("SAML configuration actions", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: { id: "saml-1", type: "saml-configurations" },
    });
  });

  it("sends every normalized additional domain when Cloud creates a configuration", async () => {
    // Given
    const formData = buildFormData({
      additionalEmailDomains: [
        " Subsidiary.Example.com ",
        "Division.Example.com",
      ],
    });

    // When
    await createSamlConfig(null, formData);

    // Then
    expect(getRequestBody()).toEqual({
      data: {
        type: "saml-configurations",
        attributes: {
          email_domain: "primary.example.com",
          additional_email_domains: [
            "subsidiary.example.com",
            "division.example.com",
          ],
          metadata_xml: "<EntityDescriptor />",
        },
      },
    });
  });

  it("sends an empty additional-domain list when Cloud removes every alias", async () => {
    // Given
    const formData = buildFormData({ id: "saml-1" });

    // When
    await updateSamlConfig(null, formData);

    // Then
    expect(getRequestBody().data.attributes.additional_email_domains).toEqual(
      [],
    );
  });

  it("omits additional domains in OSS while preserving the SAML configuration flow", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const formData = buildFormData({
      additionalEmailDomains: ["alias.example.com"],
      id: "saml-1",
    });

    // When
    await updateSamlConfig(null, formData);

    // Then
    expect(getRequestBody().data.attributes).toEqual({
      email_domain: "primary.example.com",
      metadata_xml: "<EntityDescriptor />",
    });
  });

  it("maps API validation failures to the additional-domains field", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({
      error: "Domain is already in use.",
      errors: [
        {
          detail: "Domain is already in use.",
          source: {
            pointer: "/data/attributes/additional_email_domains/0",
          },
        },
      ],
      status: 400,
    });
    const formData = buildFormData({
      additionalEmailDomains: ["alias.example.com"],
    });

    // When
    const result = await createSamlConfig(null, formData);

    // Then
    expect(result).toEqual({
      errors: { additional_email_domains: "Domain is already in use." },
    });
  });
});
