"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { mutedFindingsConfigFormSchema } from "@/types/formSchemas";
import {
  DeleteMutedFindingsConfigActionState,
  MutedFindingsConfigActionState,
  ProcessorData,
} from "@/types/processors";

export const createMutedFindingsConfig = async (
  _prevState: MutedFindingsConfigActionState,
  formData: FormData,
): Promise<MutedFindingsConfigActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = mutedFindingsConfigFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;
    return {
      errors: {
        configuration: formFieldErrors?.configuration?.[0],
      },
    };
  }

  const { configuration } = validatedData.data;

  try {
    const url = new URL(`${apiBaseUrl}/processors`);

    const bodyData = {
      data: {
        type: "processors",
        attributes: {
          processor_type: "mutelist",
          configuration: configuration,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.errors?.[0]?.detail ||
            errorData?.message ||
            `Failed to create Mutelist configuration: ${response.statusText}`,
        );
      } catch {
        throw new Error(
          `Failed to create Mutelist configuration: ${response.statusText}`,
        );
      }
    }

    await response.json();
    return { success: "Mutelist configuration created successfully!" };
  } catch (error) {
    console.error("Error creating Mutelist config:", error);
    return {
      errors: {
        configuration:
          error instanceof Error
            ? error.message
            : "Error creating Mutelist configuration. Please try again.",
      },
    };
  }
};

export const updateMutedFindingsConfig = async (
  _prevState: MutedFindingsConfigActionState,
  formData: FormData,
): Promise<MutedFindingsConfigActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = mutedFindingsConfigFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;
    return {
      errors: {
        configuration: formFieldErrors?.configuration?.[0],
      },
    };
  }

  const { configuration, id } = validatedData.data;

  if (!id) {
    return {
      errors: {
        general: "Configuration ID is required for update",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/processors/${id}`);

    const bodyData = {
      data: {
        type: "processors",
        id,
        attributes: {
          configuration: configuration,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.errors?.[0]?.detail ||
            errorData?.message ||
            `Failed to update Mutelist configuration: ${response.statusText}`,
        );
      } catch {
        throw new Error(
          `Failed to update Mutelist configuration: ${response.statusText}`,
        );
      }
    }

    await response.json();
    return { success: "Mutelist configuration updated successfully!" };
  } catch (error) {
    console.error("Error updating Mutelist config:", error);
    return {
      errors: {
        configuration:
          error instanceof Error
            ? error.message
            : "Error updating Mutelist configuration. Please try again.",
      },
    };
  }
};

export const getMutedFindingsConfig = async (): Promise<
  ProcessorData | undefined
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/processors`);
  url.searchParams.append("filter[processor_type]", "mutelist");

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch Mutelist config: ${response.statusText}`,
      );
    }

    const data = await response.json();
    return data.data[0];
  } catch (error) {
    console.error("Error fetching Mutelist config:", error);
    return undefined;
  }
};

export const deleteMutedFindingsConfig = async (
  _prevState: DeleteMutedFindingsConfigActionState,
  formData: FormData,
): Promise<DeleteMutedFindingsConfigActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const processorId = formDataObject.id as string;

  if (!processorId) {
    return {
      errors: {
        general: "Configuration ID is required for deletion",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/processors/${processorId}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete Mutelist configuration: ${response.statusText}`,
      );
    }

    return { success: "Mutelist configuration deleted successfully!" };
  } catch (error) {
    console.error("Error deleting Mutelist config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting Mutelist configuration. Please try again.",
      },
    };
  }
};
