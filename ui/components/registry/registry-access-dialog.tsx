"use client";

import { type FormEvent, type RefObject, useRef } from "react";

import { Button } from "@/components/shadcn/button/button";
import { DialogFooter } from "@/components/shadcn/dialog";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal/modal";
import { Spinner } from "@/components/shadcn/spinner/spinner";

interface RegistryAccessDialogCommonProps {
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
  const actionLabel = mode === "connect" ? "Connect" : "Replace Registry key";

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const key = new FormData(event.currentTarget).get("registry-key");
    if (typeof key !== "string" || key.trim().length === 0) return;

    formRef.current?.reset();
    await onSubmit(key);
  }

  return (
    <Modal
      description="Your Registry key is validated asynchronously and is never stored by this browser."
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
      size="sm"
      title={mode === "connect" ? "Connect Registry" : "Manage Registry access"}
    >
      {pending ? (
        <div className="flex items-center gap-3" role="status">
          <Spinner className="motion-reduce:animate-none" />
          <p className="font-medium">Validating your Registry key…</p>
        </div>
      ) : (
        <form
          className="flex flex-col gap-4"
          onSubmit={handleSubmit}
          ref={formRef}
        >
          <label className="flex flex-col gap-2 text-sm" htmlFor="registry-key">
            <span>Registry key</span>
            <Input
              autoComplete="new-password"
              id="registry-key"
              name="registry-key"
              ref={keyInputRef}
              spellCheck={false}
              type="password"
            />
          </label>
          <DialogFooter>
            {mode === "manage" && (
              <Button
                onClick={onDisconnect}
                type="button"
                variant="destructive"
              >
                Disconnect Registry
              </Button>
            )}
            <Button type="submit">{actionLabel}</Button>
          </DialogFooter>
        </form>
      )}
    </Modal>
  );
}
