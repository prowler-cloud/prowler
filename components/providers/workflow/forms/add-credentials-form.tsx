"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

import { addProvider } from "../../../../actions/providers/providers";
import { addCredentialsFormSchema, ApiError } from "../../../../types";

export const AddCredentialsForm = ({
  providerType,
}: {
  providerType: string;
}) => {
  const formSchema = addCredentialsFormSchema(providerType);
  const { toast } = useToast();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
  });

  const isLoading = form.formState.isSubmitting;

  const router = useRouter();

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
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
    } else {
      router.push("/providers/test-connection");
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        {providerType === "aws" && (
          <>
            {/* AWS Access Key ID */}
            <CustomInput
              control={form.control}
              name="aws_access_key_id"
              type="text"
              label="AWS Access Key ID"
              labelPlacement="inside"
              placeholder={"Enter the AWS Access Key ID"}
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.aws_access_key_id}
            />
            {/* AWS Secret Access Key */}
            <CustomInput
              control={form.control}
              name="aws_secret_access_key"
              type="text"
              label="AWS Secret Access Key"
              labelPlacement="inside"
              placeholder={"Enter the AWS Secret Access Key"}
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.aws_secret_access_key}
            />
            {/* AWS Session Token */}
            <CustomInput
              control={form.control}
              name="aws_session_token"
              type="text"
              label="AWS Session Token"
              labelPlacement="inside"
              placeholder={"Enter the AWS Session Token"}
              variant="bordered"
              isRequired
              isInvalid={!!form.formState.errors.aws_session_token}
            />
          </>
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Save</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
