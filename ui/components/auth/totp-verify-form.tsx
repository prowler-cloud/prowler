"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { signIn } from "next-auth/react";

interface TOTPVerifyFormProps {
  email: string;
  password: string;
  tenantId?: string;
  callbackUrl?: string;
}

export function TOTPVerifyForm({ email, password, tenantId, callbackUrl = "/" }: TOTPVerifyFormProps) {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [isPending, startTransition] = useTransition();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    startTransition(async () => {
      const result = await signIn("totp-credentials", {
        email,
        password,
        totpCode: code,
        tenantId: tenantId || "",
        redirect: false,
      });

      if (result?.error) {
        setError("Invalid authentication code. Please try again.");
      } else {
        router.push(callbackUrl);
        router.refresh();
      }
    });
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="text-center">
        <h2 className="text-xl font-semibold">Two-Factor Authentication</h2>
        <p className="text-sm text-gray-500 mt-1">
          Enter the 6-digit code from your authenticator app
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <input
          type="text"
          inputMode="numeric"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          placeholder="000000"
          className="text-center text-2xl tracking-widest border rounded-lg p-3 w-full"
          autoFocus
          autoComplete="one-time-code"
        />

        {error && (
          <p className="text-red-500 text-sm text-center">{error}</p>
        )}

        <button
          type="submit"
          disabled={code.length !== 6 || isPending}
          className="bg-[#00CDCD] text-white rounded-lg py-2 px-4 font-medium disabled:opacity-50"
        >
          {isPending ? "Verifying..." : "Verify"}
        </button>
      </form>
    </div>
  );
}
