"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib/helper";

const samlConfigFormSchema = z.object({
  email_domain: z
    .string()
    .trim()
    .min(1, { message: "Email domain is required" }),
  metadata_xml: z
    .string()
    .trim()
    .min(1, { message: "Metadata XML is required" }),
});

export async function createSamlConfig(prevState: any, formData: FormData) {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = samlConfigFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        email_domain: formFieldErrors?.email_domain?.[0],
        metadata_xml: formFieldErrors?.metadata_xml?.[0],
      },
    };
  }

  const { email_domain, metadata_xml } = validatedData.data;

  const payload = {
    data: {
      type: "saml-configurations",
      attributes: {
        email_domain: email_domain.trim(),
        metadata_xml: metadata_xml.trim(),
      },
    },
  };

  try {
    const url = new URL(`${apiBaseUrl}/saml-config`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Failed to create SAML config: ${response.statusText}`);
    }

    await response.json();
    revalidatePath("/integrations");
    return { success: "SAML configuration created successfully!" };
  } catch (error) {
    console.error("Error creating SAML config:", error);
    return {
      errors: {
        general: "Error creating SAML configuration. Please try again.",
      },
    };
  }
}

export async function getSamlConfig() {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/saml-config`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch SAML config: ${response.statusText}`);
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    console.error("Error fetching SAML config:", error);
    return undefined;
  }
}
