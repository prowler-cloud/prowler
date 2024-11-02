"use client";

import { zodResolver } from "@hookform/resolvers/zod";
// import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { checkConnectionProvider } from "@/actions/providers/providers";
import { SaveIcon } from "@/components/icons";
// import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { testConnectionFormSchema } from "@/types";

type FormValues = z.infer<typeof testConnectionFormSchema>;
export const TestConnectionForm = ({
  searchParams,
}: {
  searchParams: { id: string };
}) => {
  //   const { toast } = useToast();
  //   const router = useRouter();
  const providerId = searchParams.id;

  const formSchema = testConnectionFormSchema;

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
      console.log({ data }, "error");
    } else {
      console.log({ data }, "success");
    }
  };
  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmitClient)}>
        <div className="text-left">
          <div className="text-2xl font-bold leading-9 text-default-foreground">
            Test connection
          </div>
          <div className="py-2 text-default-500">
            Please test the connection to the provider.
          </div>
        </div>

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
            {isLoading ? <>Loading</> : <span>Connect account</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
