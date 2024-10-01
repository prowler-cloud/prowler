"use client";

import { Input } from "@nextui-org/react";
import { useRef } from "react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui";
import { UserProps } from "@/types";

import { ButtonEditUser } from "./ButtonEditUser";
import { CustomSelectUser } from "./CustomSelectUser";

interface EditUserModalProps {
  isOpen: boolean;
  setIsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  userData: UserProps;
}

export const EditUserModal: React.FC<EditUserModalProps> = ({
  isOpen,
  setIsOpen,
  userData,
}) => {
  const ref = useRef<HTMLFormElement>(null);

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogContent
        aria-describedby={undefined}
        className="flex flex-col sm:max-w-md md:max-w-lg"
      >
        <DialogHeader className="mb-6 space-y-3">
          <DialogTitle className="text-center text-2xl">Edit User</DialogTitle>
        </DialogHeader>
        <form ref={ref} onSubmit={() => setIsOpen(false)}>
          <div className="col-span-1 my-auto flex flex-col gap-y-2">
            <Input
              type="name"
              name="name"
              label="Name"
              labelPlacement="outside"
              placeholder={userData?.name}
              aria-label="Enter Name"
              size="md"
              radius="md"
              isRequired
              fullWidth
              classNames={{
                base: "h-12 mb-4",
                inputWrapper: "h-full",
              }}
            />
            <Input
              type="text"
              name="email"
              label="Email"
              labelPlacement="outside"
              placeholder={userData?.email}
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
            <CustomSelectUser userData={userData} />
          </div>
          <div className="col-span-2 mt-4 flex justify-center">
            <ButtonEditUser />
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
