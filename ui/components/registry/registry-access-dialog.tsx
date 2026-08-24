"use client";

import { useRef } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Input } from "@/components/shadcn/input/input";
import { Modal } from "@/components/shadcn/modal/modal";

interface RegistryAccessDialogCommonProps {
  onOpenChange: (open: boolean) => void;
  onSubmit: (key: string) => Promise<void>;
  open: boolean;
  pending: boolean;
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
}: RegistryAccessDialogProps) {
  const formRef = useRef<HTMLFormElement>(null);
  const keyInputRef = useRef<HTMLInputElement>(null);
  const actionLabel = mode === "connect" ? "Connect" : "Replace Registry key";

  async function handleSubmit(formData: FormData) {
    const key = formData.get("registry-key");
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
      onOpenChange={onOpenChange}
      open={open}
      size="sm"
      title={mode === "connect" ? "Connect Registry" : "Manage Registry access"}
    >
      <form action={handleSubmit} ref={formRef} className="space-y-4">
        <label className="space-y-2 text-sm" htmlFor="registry-key">
          <span>Registry key</span>
          <Input
            autoComplete="new-password"
            disabled={pending}
            id="registry-key"
            name="registry-key"
            ref={keyInputRef}
            spellCheck={false}
            type="password"
          />
        </label>
        <div className="flex flex-wrap justify-end gap-2">
          {mode === "manage" && (
            <Button
              disabled={pending}
              onClick={onDisconnect}
              type="button"
              variant="destructive"
            >
              Disconnect Registry
            </Button>
          )}
          <Button disabled={pending} type="submit">
            {pending ? "Validating Registry key" : actionLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
