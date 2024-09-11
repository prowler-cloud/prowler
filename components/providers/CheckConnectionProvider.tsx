"use client";

import { useRef } from "react";

import { checkConnectionProvider } from "@/actions";

import { CustomButtonClientAction } from "../ui/custom";
import { useToast } from "../ui/toast";

export const CheckConnectionProvider = ({ id }: { id: string }) => {
  const ref = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  async function clientAction(formData: FormData) {
    // reset the form
    ref.current?.reset();
    // client-side validation
    const data = await checkConnectionProvider(formData);
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
        title: "Checking",
        description: "The task was launched successfully",
      });
    }
  }

  return (
    <form ref={ref} action={clientAction} className="flex gap-x-2">
      <input type="hidden" name="id" value={id} />
      <CustomButtonClientAction buttonLabel="Check connection" />
    </form>
  );
};
