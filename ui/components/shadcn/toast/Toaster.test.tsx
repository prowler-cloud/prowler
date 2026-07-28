import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Toaster } from "./Toaster";

const LONG_ERROR =
  "AWSAssumeRoleError[1012]: arn:aws:sts::106908755756:assumed-role/prowler-cloud-task-20241002104346361000000003/00f08a82c8ee4e07ba";

vi.mock("./use-toast", () => ({
  useToast: () => ({
    toasts: [
      {
        id: "long-error",
        title: "Connection test failed",
        description: LONG_ERROR,
        variant: "destructive",
        open: true,
      },
    ],
  }),
}));

describe("Toaster", () => {
  it("wraps long error messages inside the toast width", () => {
    render(<Toaster />);

    const description = screen.getByText(LONG_ERROR);

    expect(description).toHaveClass(
      "max-h-48",
      "overflow-x-hidden",
      "overflow-y-auto",
      "break-all",
      "whitespace-pre-wrap",
    );
    expect(description.parentElement).toHaveClass(
      "min-w-0",
      "max-w-full",
      "flex-1",
      "overflow-x-hidden",
    );
  });
});
