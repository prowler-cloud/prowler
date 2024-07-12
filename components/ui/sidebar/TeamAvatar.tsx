"use client";

import type { AvatarProps } from "@nextui-org/react";
import { Avatar } from "@nextui-org/react";
import clsx from "clsx";
import React from "react";

export const TeamAvatar = React.forwardRef<HTMLSpanElement, AvatarProps>(
  ({ name, className, classNames = {}, ...props }, ref) => (
    <Avatar
      {...props}
      ref={ref}
      classNames={{
        ...classNames,
        base: clsx(
          "bg-transparent border border-divider",
          classNames?.base,
          className,
        ),
        name: clsx(
          "text-default-500 text-[0.6rem] font-semibold",
          classNames?.name,
        ),
      }}
      getInitials={(name) =>
        (name[0] || "") + (name[name.lastIndexOf(" ") + 1] || "").toUpperCase()
      }
      name={name}
      radius="md"
      size="sm"
    />
  ),
);

TeamAvatar.displayName = "TeamAvatar";
