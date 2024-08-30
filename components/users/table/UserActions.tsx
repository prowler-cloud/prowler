"use client";

import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui";
import { EditUserModal } from "@/components/users";
import { UserProps } from "@/types";

interface UserActionsProps {
  userData: UserProps;
}

export const UserActions: React.FC<UserActionsProps> = ({ userData }) => {
  const [isEditOpen, setIsEditOpen] = useState(false);

  return (
    <>
      <div className="relative flex justify-end items-center gap-2">
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger>
            <VerticalDotsIcon
              size={28}
              className="text-default-400 p-0.5 hover:bg-gray-200 hover:rounded-full"
            />
          </DropdownMenuTrigger>
          <DropdownMenuContent className="bg-white">
            <DropdownMenuItem
              className="hover:bg-gray-200 hover:cursor-pointer"
              onClick={() => setIsEditOpen(true)}
            >
              Edit
            </DropdownMenuItem>
            <DropdownMenuItem className="hover:bg-gray-200 hover:cursor-pointer">
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      {isEditOpen && (
        <EditUserModal
          isOpen={isEditOpen}
          setIsOpen={setIsEditOpen}
          userData={userData}
        />
      )}
    </>
  );
};
