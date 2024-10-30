"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronLeftIcon, ChevronRightIcon, SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

import { addProvider } from "../../../../actions/providers/providers";
import { addProviderFormSchema, ApiError } from "../../../../types";
import { RadioGroupProvider } from "../../radio-group-provider";
import { RadioGroupAWSViaCredentialsForm } from "./radio-group-aws-via-credentials-form";

export type FormValues = z.infer<typeof addProviderFormSchema>;

export const ConnectAccountForm = () => {
  const { toast } = useToast();
  const [prevStep, setPrevStep] = useState(1);

  const formSchema = addProviderFormSchema;

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerType: "",
      providerId: "",
      providerAlias: "",
      awsCredentialsType: "",
    },
  });
  const providerType = form.watch("providerType");
  const isLoading = form.formState.isSubmitting;

  const router = useRouter();

  const onSubmitClient = async (values: FormValues) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addProvider(formData);
    console.log(data);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        switch (error.source.pointer) {
          case "/data/attributes/provider":
            form.setError("providerType", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/uid":
          case "/data/attributes/__all__":
            form.setError("providerId", {
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
      setPrevStep(1);
    } else {
      router.push("/providers/add-credentials");
    }
  };

  const handleNextStep = () => {
    setPrevStep((prev) => prev + 1);
  };

  const handleBackStep = () => {
    setPrevStep((prev) => prev - 1);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        {prevStep === 1 && (
          <>
            {/* Select a provider */}
            <RadioGroupProvider
              control={form.control}
              isInvalid={!!form.formState.errors.providerType}
            />
            {/* Provider UID */}
            <CustomInput
              control={form.control}
              name="providerId"
              type="text"
              label="Provider UID"
              labelPlacement="inside"
              placeholder={"Enter the provider UID"}
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.providerId}
            />
            {/* Provider alias */}
            <CustomInput
              control={form.control}
              name="providerAlias"
              type="text"
              label="Provider alias (optional)"
              labelPlacement="inside"
              placeholder={"Enter the provider alias"}
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.providerAlias}
            />
          </>
        )}

        {prevStep === 2 && (
          <>
            {/* Select AWS credentials type */}
            <RadioGroupAWSViaCredentialsForm control={form.control} />
          </>
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          {prevStep === 2 && (
            <CustomButton
              type="button"
              ariaLabel="Back"
              className="w-1/2 bg-transparent"
              variant="faded"
              size="lg"
              radius="lg"
              onPress={handleBackStep}
              startContent={!isLoading && <ChevronLeftIcon size={24} />}
              isDisabled={isLoading}
            >
              <span>Back</span>
            </CustomButton>
          )}

          <CustomButton
            type="button"
            ariaLabel={
              prevStep === 1 && providerType === "aws" ? "Next" : "Save"
            }
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={
              !isLoading &&
              !(prevStep === 1 && providerType === "aws") && (
                <SaveIcon size={24} />
              )
            }
            endContent={
              !isLoading &&
              prevStep === 1 &&
              providerType === "aws" && <ChevronRightIcon size={24} />
            }
            onPress={() => {
              if (prevStep === 1 && providerType === "aws") {
                handleNextStep();
              } else {
                form.handleSubmit(onSubmitClient)();
              }
            }}
          >
            {isLoading ? (
              <>Loading</>
            ) : (
              <span>
                {prevStep === 1 && providerType === "aws" ? "Next" : "Save"}
              </span>
            )}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
