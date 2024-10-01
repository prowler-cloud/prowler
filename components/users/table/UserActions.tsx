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
      <div className="relative flex items-center justify-end gap-2">
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger>
            <VerticalDotsIcon
              size={28}
              className="p-0.5 text-default-400 hover:rounded-full hover:bg-gray-200"
            />
          </DropdownMenuTrigger>
          <DropdownMenuContent className="bg-white">
            <DropdownMenuItem
              className="hover:cursor-pointer hover:bg-gray-200"
              onClick={() => setIsEditOpen(true)}
            >
              Edit
            </DropdownMenuItem>
            <DropdownMenuItem className="hover:cursor-pointer hover:bg-gray-200">
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
