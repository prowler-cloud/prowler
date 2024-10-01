"use client";

import { Button, Input } from "@nextui-org/react";
import { useRef, useState } from "react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui";

import { ButtonAddUser } from "./ButtonAddUser";
import { CustomSelectUser } from "./CustomSelectUser";

export const AddUserModal = () => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLFormElement>(null);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button aria-label="Add User" variant="ghost">
          Add User
        </Button>
      </DialogTrigger>
      <DialogContent
        aria-describedby={undefined}
        className="flex flex-col sm:max-w-md md:max-w-lg"
      >
        <DialogHeader className="mb-6 space-y-3">
          <DialogTitle className="text-center text-2xl">Add User</DialogTitle>
        </DialogHeader>
        <form ref={ref} onSubmit={() => setOpen(false)}>
          <div className="col-span-1 my-auto flex flex-col gap-y-2">
            <Input
              type="text"
              name="email"
              label="Email"
              labelPlacement="outside"
              placeholder="Email"
              aria-label="Enter Email"
              size="md"
              radius="md"
              isRequired
              fullWidth
              classNames={{
                base: "h-12 mb-4",
                inputWrapper: "h-full",
              }}
            />
            <CustomSelectUser />
          </div>
          <div className="col-span-2 mt-4 flex justify-center">
            <ButtonAddUser />
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
