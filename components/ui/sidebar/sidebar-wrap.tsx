"use client";

import { Icon } from "@iconify/react";
import { Button, ScrollShadow, Spacer, Tooltip } from "@nextui-org/react";
import clsx from "clsx";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession } from "next-auth/react";
import React, { Suspense, useCallback } from "react";
import { useMediaQuery } from "usehooks-ts";

import { logOut } from "@/actions/auth";
import { useUIStore } from "@/store";

import {
  ProwlerExtended,
  ProwlerShort,
} from "../../icons/prowler/ProwlerIcons";
import { ThemeSwitch } from "../../ThemeSwitch";
import Sidebar from "./sidebar-tmp";
import { sectionItemsWithTeams } from "./sidebar-items";
import { UserAvatar } from "./user-avatar";

export const SidebarWrap = () => {
  const pathname = usePathname();
  const { data: session } = useSession();

  const isCollapsed = useUIStore((state) => state.isSideMenuOpen);
  const openSideMenu = useUIStore((state) => state.openSideMenu);
  const closeSideMenu = useUIStore((state) => state.closeSideMenu);

  const isMobile = useMediaQuery("(max-width: 768px)");
  const isCompact = isCollapsed || isMobile;

  const onToggle = useCallback(() => {
    if (!isCollapsed) openSideMenu();
    if (isCollapsed) closeSideMenu();
  }, [isCollapsed]);

  const currentPath = pathname === "/" ? "overview" : pathname.split("/")?.[1];

  return (
    <div
      className={clsx(
        "relative flex h-screen flex-col !border-r-small border-divider transition-width",
        {
          "w-72 p-6": !isCompact,
          "w-16 items-center px-2 py-6": isCompact,
        },
      )}
    >
      <div
        className={clsx("flex items-center justify-center gap-3 px-3", {
          "gap-0": isCompact,
        })}
      >
        <div
          className={clsx({
            hidden: !isCompact,
          })}
        >
          <ProwlerShort />
        </div>
        <div
          className={clsx({
            hidden: isCompact,
          })}
        >
          <ProwlerExtended />
        </div>
      </div>
      <Spacer y={8} />

      <Link href={"/profile"}>
        <Suspense fallback={<p>Loading...</p>}>
          <UserAvatar
            userName={session?.user.name ?? "Guest"}
            position={session?.user.companyName ?? "Company Name"}
            isCompact={isCompact}
          />
        </Suspense>
      </Link>

      <ScrollShadow hideScrollBar className="-mr-6 h-full max-h-full py-6 pr-6">
        <Sidebar
          defaultSelectedKey="overview"
          isCompact={isCompact}
          items={sectionItemsWithTeams}
          selectedKeys={[currentPath]}
        />
      </ScrollShadow>
      <Spacer y={2} />
      <div
        className={clsx("mt-auto flex flex-col", {
          "items-center": isCompact,
        })}
      >
        {/* <Tooltip
          content="Feedback & Support"
          isDisabled={!isCompact}
          placement="right"
        >
          <Button
            aria-label="Feedback & Support"
            fullWidth
            className={clsx(
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
                  icon="akar-icons:info"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="akar-icons:info"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Feedback & Support"
            )}
          </Button>
        </Tooltip> */}

        <Tooltip
          content="Documentation"
          isDisabled={!isCompact}
          placement="right"
        >
          <Link
            href="https://docs.prowler.com/projects/prowler-saas/en/latest/"
            target="_blank"
          >
            <Button
              aria-label="Documentation"
              className={clsx(
                "justify-start text-default-500 data-[hover=true]:text-foreground",
                {
                  "justify-center": isCompact,
                },
              )}
              isIconOnly={isCompact}
              startContent={
                isCompact ? null : (
                  <Icon
                    className="flex-none text-default-500"
                    icon="tabler:file-type-doc"
                    width={24}
                    aria-hidden="true"
                  />
                )
              }
              variant="light"
            >
              {isCompact ? (
                <Icon
                  className="text-default-500"
                  icon="tabler:file-type-doc"
                  width={24}
                  aria-hidden="true"
                />
              ) : (
                "Documentation"
              )}
            </Button>
          </Link>
        </Tooltip>

        {/* <Tooltip
          content="Product Updates"
          isDisabled={!isCompact}
          placement="right"
        >
          <Button
            aria-label="Product Updates"
            className={clsx(
              "justify-start text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="mdi:update"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="mdi:update"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Product Updates"
            )}
          </Button>
        </Tooltip> */}

        <Tooltip content="Log Out" isDisabled={!isCompact} placement="right">
          <Button
            aria-label="Log Out"
            onClick={() => logOut()}
            className={clsx(
              "justify-start text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="heroicons-outline:logout"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="heroicons-outline:logout"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Log Out"
            )}
          </Button>
        </Tooltip>
      </div>
      <div
        className={clsx("mt-auto flex justify-end gap-3", {
          "flex-col items-center": isCompact,
          "items-baseline": !isCompact,
        })}
      >
        <Tooltip
          content="Light | Dark mode"
          placement={isCompact ? "right" : "top"}
        >
          <div
            className={clsx(
              "px-0 text-default-500 data-[hover=true]:text-foreground",
              {
                "mt-3 justify-center": isCompact,
              },
            )}
          >
            <ThemeSwitch aria-label="Toggle theme" />
          </div>
        </Tooltip>
        <Tooltip
          content="Open | Close sidebar"
          placement={isCompact ? "right" : "top"}
        >
          <Button
            aria-label={isCompact ? "Open sidebar" : "Close sidebar"}
            className={clsx(
              "px-0 text-default-500 data-[hover=true]:text-foreground",
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
              aria-hidden="true"
            />
          </Button>
        </Tooltip>
      </div>
    </div>
  );
};
