"use client";

import { type FormEvent, type RefObject, useEffect, useRef } from "react";

import { Button } from "@/components/shadcn/button/button";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal/modal";

interface RegistryAccessDialogCommonProps {
  errorMessage?: string;
  onOpenChange: (open: boolean) => void;
  onSubmit: (key: string) => Promise<void>;
  open: boolean;
  pending: boolean;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
}

type ConnectRegistryAccessDialogProps = RegistryAccessDialogCommonProps & {
  mode: "connect";
  onDisconnect?: never;
};

type ManageRegistryAccessDialogProps = RegistryAccessDialogCommonProps & {
  mode: "manage";
  onDisconnect: () => Promise<void>;
};

type RegistryAccessDialogProps =
  | ConnectRegistryAccessDialogProps
  | ManageRegistryAccessDialogProps;

export function RegistryAccessDialog({
  errorMessage,
  mode,
  onDisconnect,
  onOpenChange,
  onSubmit,
  open,
  pending,
  returnFocusRef,
}: RegistryAccessDialogProps) {
  const formRef = useRef<HTMLFormElement>(null);
  const keyInputRef = useRef<HTMLInputElement>(null);
  const wasPendingRef = useRef(pending);
  const actionLabel = mode === "connect" ? "Connect" : "Replace key";

  // Re-enabling the form after a watched validation settles loses focus from
  // the disabled input; hand it back so a retry can start from the keyboard.
  useEffect(() => {
    if (wasPendingRef.current && !pending) keyInputRef.current?.focus();
    wasPendingRef.current = pending;
  }, [pending]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const key = new FormData(event.currentTarget).get("registry-key");
    if (typeof key !== "string" || key.trim().length === 0) return;

    formRef.current?.reset();
    await onSubmit(key);
  }

  return (
    <Modal
      description="Your Registry API key links this workspace to the Prowler artifact registry. It is validated asynchronously and never stored by this browser."
      onOpenAutoFocus={(event) => {
        event.preventDefault();
        keyInputRef.current?.focus();
      }}
      onCloseAutoFocus={(event) => {
        event.preventDefault();
        returnFocusRef.current?.focus();
      }}
      onOpenChange={onOpenChange}
      open={open}
      size="md"
      title={
        mode === "connect"
          ? "Connect Registry API key"
          : "Manage Registry access"
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={handleSubmit}
        ref={formRef}
      >
        <div className="flex flex-col gap-2">
          <label className="flex flex-col gap-2 text-sm" htmlFor="registry-key">
            <span>Registry key</span>
            <Input
              aria-describedby={errorMessage ? "registry-key-error" : undefined}
              autoComplete="new-password"
              disabled={pending}
              id="registry-key"
              name="registry-key"
              ref={keyInputRef}
              spellCheck={false}
              type="password"
            />
          </label>
          {errorMessage && (
            <p
              className="text-text-error-primary text-sm"
              id="registry-key-error"
              role="alert"
            >
              {errorMessage}
            </p>
          )}
          <Button asChild className="self-start" size="link-sm" variant="link">
            <a
              href="https://registry.prowler.com"
              rel="noopener noreferrer"
              target="_blank"
            >
              Where do I find my key?
            </a>
          </Button>
        </div>
        <DialogFooter
          className={mode === "manage" ? "sm:justify-between" : undefined}
        >
          {mode === "manage" && (
            <Button
              disabled={pending}
              onClick={onDisconnect}
              type="button"
              variant="destructive"
            >
              Disconnect
            </Button>
          )}
          <div className="flex flex-col-reverse gap-2 sm:flex-row">
            <Button
              disabled={pending}
              onClick={() => onOpenChange(false)}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button disabled={pending} type="submit">
              {pending ? "Connecting…" : actionLabel}
            </Button>
          </div>
        </DialogFooter>
      </form>
    </Modal>
  );
}
