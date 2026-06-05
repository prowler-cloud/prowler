import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FileUploadDropzone } from "./file-upload-dropzone";

describe("FileUploadDropzone", () => {
  it("animates drag feedback and selected file content", async () => {
    // Given - A dropzone without a selected file
    const user = userEvent.setup();
    const onFileSelect = vi.fn();
    render(<FileUploadDropzone onFileSelect={onFileSelect} />);

    // When - The dropzone renders
    const dropzone = screen.getByText(/drag and drop/i).closest("label");
    const input = screen.getByLabelText(/drag and drop/i, {
      selector: "input",
    });

    // Then - Drag feedback and internal content have visible motion contracts
    expect(dropzone).toHaveClass(
      "transition-[background-color,border-color,box-shadow,transform]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(dropzone?.querySelector("svg")).toHaveClass(
      "transition-transform",
      "duration-150",
      "ease-out",
      "group-hover:-translate-y-0.5",
      "motion-reduce:transform-none",
    );

    await user.upload(
      input,
      new File(["prowler"], "evidence.json", { type: "application/json" }),
    );

    expect(onFileSelect).toHaveBeenCalledWith(expect.any(File));
  });
});
