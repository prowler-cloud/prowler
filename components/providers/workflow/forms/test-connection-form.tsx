"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import Link from "next/link";
import { useState } from "react";
// import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { checkConnectionProvider } from "@/actions/providers/providers";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError, testConnectionFormSchema } from "@/types";

type FormValues = z.infer<typeof testConnectionFormSchema>;

export const TestConnectionForm = ({
  searchParams,
}: {
  searchParams: { id: string };
}) => {
  const { toast } = useToast();
  const providerId = searchParams.id;

  const formSchema = testConnectionFormSchema;
  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    console.log({ values }, "values from test connection form");
    const formData = new FormData();
    formData.append("providerId", values.providerId);

    const data = await checkConnectionProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;

        switch (errorMessage) {
          case "Not found.":
            setApiErrorMessage(errorMessage);
            break;
          default:
            toast({
              variant: "destructive",
              title: `Error ${error.status}`,
              description: errorMessage,
            });
        }
      });
    } else {
      console.log({ data: data.data.id }, "success");
      setApiErrorMessage(null);
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="text-left">
          <div className="text-2xl font-bold leading-9 text-default-foreground">
            Test connection
          </div>
          <div className="py-2 text-default-500">
            Please check the provider connection
          </div>
        </div>

        {apiErrorMessage && (
          <div className="mt-4 rounded-md bg-red-100 p-3 text-red-700">
            <p>{`Provider ID ${apiErrorMessage.toLowerCase()}. Please check and try again.`}</p>
          </div>
        )}

        <input type="hidden" name="providerId" value={providerId} />

        <div className="flex w-full justify-end sm:space-x-6">
          {apiErrorMessage ? (
            <Link
              href="/providers"
              className="mr-3 flex w-fit items-center justify-center space-x-2 rounded-lg border border-solid border-gray-200 px-4 py-2 hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              <Icon
                icon="icon-park-outline:close-small"
                className="h-5 w-5 text-gray-600 dark:text-gray-400"
              />
              <span>Back to providers</span>
            </Link>
          ) : (
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
              {isLoading ? <>Loading</> : <span>Connect account</span>}
            </CustomButton>
          )}
        </div>
      </form>
    </Form>
  );
};
