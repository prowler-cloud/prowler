"use client";

import { Avatar } from "@nextui-org/react";
import React from "react";

import { cn } from "@/utils/cn";

interface UserAvatarProps {
  userName: string;
  position: string;
  isCompact: boolean;
}
export const UserAvatar: React.FC<UserAvatarProps> = ({
  userName,
  position,
  isCompact = false,
}) => {
  return (
    <div className="flex items-center gap-3 px-3">
      <Avatar isBordered className="flex-none" size="sm" showFallback />
      <div
        className={cn("flex max-w-full flex-col", {
          hidden: isCompact,
        })}
      >
        <p className="truncate text-small font-medium text-default-600">
          {userName}
        </p>
        <p className="truncate text-tiny text-default-400">{position}</p>
      </div>
    </div>
  );
};
