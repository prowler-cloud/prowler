"use client";

import { Button, Input } from "@nextui-org/react";
import { useRef, useState } from "react";

import { addProvider } from "@/actions";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  useToast,
} from "@/components/ui";

import { ButtonAddProvider } from "./ButtonAddProvider";
import { CustomRadioProvider } from "./CustomRadioProvider";

export const AddProviderModal = () => {
  const [open, setOpen] = useState(false);

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
          title: "Oops! Something went wrong",
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
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button aria-label="Add Cloud Account" variant="ghost">
          Add Cloud Account
        </Button>
      </DialogTrigger>
      <DialogContent className="flex flex-col sm:max-w-md md:max-w-4xl">
        <DialogHeader className="mb-6 space-y-3">
          <DialogTitle className="text-2xl text-center">
            Add cloud account
          </DialogTitle>
          <DialogDescription className="text-md">
            You must manually deploy a new read-only IAM role for each account
            you want to add. The following links will provide detailed
            instructions how to do this:
          </DialogDescription>
        </DialogHeader>
        <form
          ref={ref}
          action={clientAction}
          onSubmit={() => setOpen(false)}
          className="grid sm:grid-cols-2 gap-6"
        >
          <div className="col-span-1">
            <CustomRadioProvider />
          </div>
          <div className="col-span-1 flex flex-col gap-y-2 my-auto">
            <Input
              type="text"
              name="id"
              label="Provider ID"
              labelPlacement="outside"
              placeholder="Provider ID"
              className="w-full rounded-sm"
              aria-label="Enter Provider ID"
            />
            <Input
              type="text"
              name="alias"
              label="Alias"
              labelPlacement="outside"
              placeholder="alias"
              className="w-full rounded-sm"
              aria-label="Enter Provider alias"
            />
          </div>
          <div className="col-span-2 flex justify-center mt-4">
            <ButtonAddProvider />
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
