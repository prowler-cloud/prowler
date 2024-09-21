"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Button, CircularProgress } from "@nextui-org/react";
import React, { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { deleteProvider } from "@/actions";
import { useToast } from "@/components/ui";
import { Form } from "@/components/ui/form";

const formSchema = z.object({
  providerId: z.string(),
});

export const DeleteForm = ({
  providerId,
  setIsOpen,
}: {
  providerId: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
  });
  const { toast } = useToast();
  const isLoading = form.formState.isSubmitting;

  async function onSubmitClient(formData: FormData) {
    // client-side validation
    const data = await deleteProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      // show error
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Success!",
        description: "The provider was removed successfully.",
      });
    }
  }

  return (
    <Form {...form}>
      <form action={onSubmitClient}>
        <input type="hidden" name="id" value={providerId} />
        <div className="w-full flex justify-center sm:space-x-6">
          <Button
            size="lg"
            variant="bordered"
            disabled={isLoading}
            className="w-full hidden sm:block"
            type="button"
            onClick={() => setIsOpen(false)}
          >
            Cancel
          </Button>
          <Button
            size="lg"
            type="submit"
            disabled={isLoading}
            className="w-full bg-system-error hover:bg-system-error/90 text-white"
          >
            {isLoading ? (
              <>
                <CircularProgress aria-label="Loading..." size="sm" />
                Deleting
              </>
            ) : (
              <span>Delete</span>
            )}
          </Button>
        </div>
      </form>
    </Form>
  );
};
