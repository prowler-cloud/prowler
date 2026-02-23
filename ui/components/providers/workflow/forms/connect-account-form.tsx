"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronLeftIcon, ChevronRightIcon, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { addProvider } from "@/actions/providers/providers";
import { ProviderTitleDocs } from "@/components/providers/workflow/provider-title-docs";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { addProviderFormSchema, ApiError, ProviderType } from "@/types";

import { RadioGroupProvider } from "../../radio-group-provider";

export type FormValues = z.infer<typeof addProviderFormSchema>;

// Helper function for labels and placeholders
const getProviderFieldDetails = (providerType?: ProviderType) => {
  switch (providerType) {
    case "aws":
      return {
        label: "Account ID",
        placeholder: "e.g. 123456789012",
      };
    case "gcp":
      return {
        label: "Project ID",
        placeholder: "e.g. my-gcp-project",
      };
    case "azure":
      return {
        label: "Subscription ID",
        placeholder: "e.g. fc94207a-d396-4a14-a7fd-12ab34cd56ef",
      };
    case "kubernetes":
      return {
        label: "Kubernetes Context",
        placeholder: "e.g. my-cluster-context",
      };
    case "m365":
      return {
        label: "Domain ID",
        placeholder: "e.g. your-domain.onmicrosoft.com",
      };
    case "github":
      return {
        label: "Username/Organization",
        placeholder: "e.g. username or organization-name",
      };
    case "iac":
      return {
        label: "Repository URL",
        placeholder: "e.g. https://github.com/user/repo",
      };
    case "oraclecloud":
      return {
        label: "Tenancy OCID",
        placeholder: "e.g. ocid1.tenancy.oc1..aaaaaaa...",
      };
    case "mongodbatlas":
      return {
        label: "Organization ID",
        placeholder: "e.g. 5f43a8c4e1234567890abcde",
      };
    case "alibabacloud":
      return {
        label: "Account ID",
        placeholder: "e.g. 1234567890123456",
      };
    case "cloudflare":
      return {
        label: "Account ID",
        placeholder: "e.g. a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      };
    case "openstack":
      return {
        label: "Project ID",
        placeholder: "e.g. a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      };
    default:
      return {
        label: "Provider UID",
        placeholder: "Enter the provider UID",
      };
  }
};

export const ConnectAccountForm = () => {
  const { toast } = useToast();
  const [prevStep, setPrevStep] = useState(1);
  const router = useRouter();

  const formSchema = addProviderFormSchema;

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerType: undefined,
      providerUid: "",
      providerAlias: "",
    },
  });

  const providerType = form.watch("providerType");
  const providerFieldDetails = getProviderFieldDetails(providerType);

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    const formValues = { ...values };

    const formData = new FormData();
    Object.entries(formValues).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    try {
      const data = await addProvider(formData);

      if (data?.errors && data.errors.length > 0) {
        // Handle server-side validation errors
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;
          const pointer = error.source?.pointer;

          switch (pointer) {
            case "/data/attributes/provider":
              form.setError("providerType", {
                type: "server",
                message: errorMessage,
              });
              break;
            case "/data/attributes/uid":
            case "/data/attributes/__all__":
              form.setError("providerUid", {
                type: "server",
                message: errorMessage,
              });
              break;
            case "/data/attributes/alias":
              form.setError("providerAlias", {
                type: "server",
                message: errorMessage,
              });
              break;
            default:
              toast({
                variant: "destructive",
                title: "Oops! Something went wrong",
                description: errorMessage,
              });
          }
        });
        return;
      } else {
        // Go to the next step after successful submission
        const {
          id,
          attributes: { provider: providerType },
        } = data.data;

        router.push(`/providers/add-credentials?type=${providerType}&id=${id}`);
      }
    } catch (error: unknown) {
      console.error("Error during submission:", error);
      toast({
        variant: "destructive",
        title: "Submission Error",
        description:
          error instanceof Error
            ? error.message
            : "Something went wrong. Please try again.",
      });
    }
  };

  const handleBackStep = () => {
    setPrevStep((prev) => prev - 1);
    //Deselect the providerType if the user is going back to the first step
    if (prevStep === 2) {
      form.setValue("providerType", undefined as unknown as ProviderType);
    }
    // Reset the providerUid and providerAlias fields when going back
    form.setValue("providerUid", "");
    form.setValue("providerAlias", "");
  };

  useEffect(() => {
    if (providerType) {
      setPrevStep(2);
    }
  }, [providerType]);

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-4"
      >
        {/* Step 1: Provider selection */}
        {prevStep === 1 && (
          <RadioGroupProvider
            control={form.control}
            isInvalid={!!form.formState.errors.providerType}
            errorMessage={form.formState.errors.providerType?.message}
          />
        )}
        {/* Step 2: UID, alias, and credentials (if AWS) */}
        {prevStep === 2 && (
          <>
            <ProviderTitleDocs providerType={providerType} />
            <CustomInput
              control={form.control}
              name="providerUid"
              type="text"
              label={providerFieldDetails.label}
              labelPlacement="inside"
              placeholder={providerFieldDetails.placeholder}
              variant="bordered"
              isRequired
            />
            <CustomInput
              control={form.control}
              name="providerAlias"
              type="text"
              label="Provider alias (optional)"
              labelPlacement="inside"
              placeholder="Enter the provider alias"
              variant="bordered"
              isRequired={false}
            />
          </>
        )}
        {/* Navigation buttons */}
        <div className="flex w-full justify-end gap-4">
          {/* Show "Back" button only in Step 2 */}
          {prevStep === 2 && (
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={handleBackStep}
              disabled={isLoading}
            >
              {!isLoading && <ChevronLeftIcon size={24} />}
              Back
            </Button>
          )}
          {/* Show "Next" button in Step 2 */}
          {prevStep === 2 && (
            <Button
              type="submit"
              variant="default"
              size="lg"
              disabled={isLoading}
            >
              {isLoading ? (
                <Loader2 className="animate-spin" />
              ) : (
                <ChevronRightIcon size={24} />
              )}
              {isLoading ? "Loading" : "Next"}
            </Button>
          )}
        </div>
      </form>
    </Form>
  );
};
