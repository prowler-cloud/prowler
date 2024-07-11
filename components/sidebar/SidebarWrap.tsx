"use client";

import { Icon } from "@iconify/react";
import { Button, ScrollShadow, Spacer, Tooltip } from "@nextui-org/react";
import React from "react";
import { useMediaQuery } from "usehooks-ts";

import { cn } from "@/utils/cn";

import { AcmeIcon } from "../acme";
import { ThemeSwitch } from "../ThemeSwitch";
import Sidebar from "./Sidebar";
import { sectionItemsWithTeams } from "./SidebarItems";
import UserAvatar from "./UserAvatar";

export const SidebarWrap = () => {
  const [isCollapsed, setIsCollapsed] = React.useState(false);
  const isMobile = useMediaQuery("(max-width: 768px)");

  const isCompact = isCollapsed || isMobile;

  const onToggle = React.useCallback(() => {
    setIsCollapsed((prev) => !prev);
  }, []);

  return (
    <div
      className={cn(
        "relative flex h-screen w-72 flex-col !border-r-small border-divider p-6 transition-width",
        {
          "w-16 items-center px-2 py-6": isCompact,
        },
      )}
    >
      <div
        className={cn(
          "flex items-center gap-3 px-3",

          {
            "justify-center gap-0": isCompact,
          },
        )}
      >
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-foreground">
          <AcmeIcon className="text-background" />
        </div>
        <span
          className={cn("text-small font-bold uppercase opacity-100", {
            "w-0 opacity-0": isCompact,
          })}
        >
          Prowler
        </span>
      </div>
      <Spacer y={8} />

      <UserAvatar
        userName={"Pablo Lara"}
        position={"Software Engineer"}
        isCompact={isCompact}
      />

      <ScrollShadow className="-mr-6 h-full max-h-full py-6 pr-6">
        <Sidebar
          defaultSelectedKey="home"
          isCompact={isCompact}
          items={sectionItemsWithTeams}
        />
      </ScrollShadow>
      <Spacer y={2} />
      <div
        className={cn("mt-auto flex flex-col", {
          "items-center": isCompact,
        })}
      >
        <Tooltip
          content="Help & Feedback"
          isDisabled={!isCompact}
          placement="right"
        >
          <Button
            fullWidth
            className={cn(
              "justify-start truncate text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="solar:info-circle-line-duotone"
                  width={24}
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="solar:info-circle-line-duotone"
                width={24}
              />
            ) : (
              "Help & Information"
            )}
          </Button>
        </Tooltip>
        <Tooltip content="Log Out" isDisabled={!isCompact} placement="right">
          <Button
            className={cn(
              "justify-start text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none rotate-180 text-default-500"
                  icon="solar:minus-circle-line-duotone"
                  width={24}
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="rotate-180 text-default-500"
                icon="solar:minus-circle-line-duotone"
                width={24}
              />
            ) : (
              "Log Out"
            )}
          </Button>
        </Tooltip>
      </div>
      <div
        className={cn("mt-auto flex justify-end gap-3 items-baseline", {
          "flex-col items-center": isCompact,
        })}
      >
        <Tooltip
          content="Light | Dark mode"
          placement={isCompact ? "right" : "top"}
        >
          <div
            className={cn(
              "text-default-500 data-[hover=true]:text-foreground px-0",
              {
                "justify-center mt-3": isCompact,
              },
            )}
          >
            <ThemeSwitch />
          </div>
        </Tooltip>
        <Tooltip
          content="Open | Close sidebar"
          placement={isCompact ? "right" : "top"}
        >
          <Button
            className={cn(
              "text-default-500 data-[hover=true]:text-foreground px-0",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly
            size="sm"
            variant="light"
            onPress={onToggle}
          >
            <Icon
              className="text-default-500"
              height={24}
              icon="solar:sidebar-minimalistic-outline"
              width={24}
            />
          </Button>
        </Tooltip>
      </div>
    </div>
  );
};
