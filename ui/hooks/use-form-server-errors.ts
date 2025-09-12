import { UseFormReturn } from "react-hook-form";

import { useToast } from "@/components/ui";
import { ApiError } from "@/types";

/**
 * Generic hook for handling server errors in forms
 * Can be used across different types of forms, not just credential forms
 */
export const useFormServerErrors = <T extends Record<string, any>>(
  form: UseFormReturn<T>,
  customErrorMapping?: Record<string, string>,
) => {
  const { toast } = useToast();

  const handleServerErrors = (
    errors: ApiError[],
    errorMapping?: Record<string, string>,
  ) => {
    errors.forEach((error: ApiError) => {
      const errorMessage = error.detail;
      const fieldName = errorMapping?.[error.source.pointer];

      if (fieldName && fieldName in form.formState.defaultValues!) {
        form.setError(fieldName as any, {
          type: "server",
          message: errorMessage,
        });
      } else {
        // Handle unknown error pointers with toast
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: errorMessage,
        });
      }
    });
  };

  const handleServerResponse = (
    data: any,
    errorMapping?: Record<string, string>,
  ) => {
    // Check for both error (singular) and errors (plural) from server responses
    if (data?.error) {
      // Handle single error from server
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: data.error,
      });
      return false; // Indicates error occurred
    } else if (data?.errors && data.errors.length > 0) {
      handleServerErrors(data.errors, errorMapping || customErrorMapping);
      return false; // Indicates error occurred
    }
    return true; // Indicates success
  };

  return { handleServerResponse, handleServerErrors };
};
