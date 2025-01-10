"use client";

import { Avatar } from "@nextui-org/react";
import clsx from "clsx";
import React from "react";

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
        className={clsx("flex max-w-full flex-col", {
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
