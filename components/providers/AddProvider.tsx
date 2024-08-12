"use client";

import { useRef } from "react";

import { addProvider } from "@/actions";

import { useToast } from "../ui/toast";
import { ButtonAddProvider } from "./ButtonAddProvider";

export const AddProvider = () => {
  const ref = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  async function clientAction(formData: FormData) {
    // reset the form
    ref.current?.reset();
    // client-side validation
    const data = await addProvider(formData);
    if (data?.errors) {
      data.errors.forEach((error: { detail: string }) => {
        const errorMessage = `${error.detail}`;
        // show error
        toast({
          variant: "destructive",
          title: "Ups! Something went wrong",
          description: errorMessage,
        });
      });
    } else {
      toast({
        title: "Success!",
        description: "The provider was added successfully.",
      });
    }
  }

  return (
    <form ref={ref} action={clientAction} className="flex gap-x-2">
      <input
        type="text"
        name="provider"
        placeholder="Provider"
        aria-label="Provider"
        className="py-2 px-3 rounded-sm"
      />
      <input
        type="text"
        name="id"
        placeholder="Provider ID"
        aria-label="Provider ID"
        className="py-2 px-3 rounded-sm"
      />
      <input
        type="text"
        name="alias"
        placeholder="Alias"
        aria-label="Alias"
        className="py-2 px-3 rounded-sm"
      />
      <ButtonAddProvider />
    </form>
  );
};
