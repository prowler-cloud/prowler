import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { Form } from "@/components/shadcn/form";

import { CustomInput } from "./custom-input";

interface TestFormValues {
  password: string;
  email: string;
}

const TestForm = ({
  password = false,
  isRequired,
}: {
  password?: boolean;
  isRequired?: boolean;
}) => {
  const form = useForm<TestFormValues>({
    defaultValues: { password: "", email: "" },
  });

  return (
    <Form {...form}>
      <CustomInput
        control={form.control}
        name={password ? "password" : "email"}
        label="Email"
        password={password}
        {...(isRequired !== undefined && { isRequired })}
      />
    </Form>
  );
};

describe("CustomInput", () => {
  describe("when used as a password field", () => {
    it("should mask the value by default", () => {
      // Given
      render(<TestForm password />);

      // Then
      expect(screen.getByLabelText(/^password/i)).toHaveAttribute(
        "type",
        "password",
      );
    });

    it("should reveal and re-mask the value with the visibility toggle", async () => {
      // Given
      const user = userEvent.setup();
      render(<TestForm password />);
      const input = screen.getByLabelText(/^password/i);
      await user.type(input, "hunter2");

      // When the user shows the password
      await user.click(screen.getByRole("button", { name: "Show password" }));

      // Then the value becomes readable and the toggle flips
      expect(input).toHaveAttribute("type", "text");
      expect(input).toHaveValue("hunter2");

      // When the user hides it again
      await user.click(screen.getByRole("button", { name: "Hide password" }));

      // Then
      expect(input).toHaveAttribute("type", "password");
    });
  });

  describe("when used as a regular field", () => {
    it("should keep the provided type and accept user input", async () => {
      // Given
      const user = userEvent.setup();
      render(<TestForm />);
      const input = screen.getByLabelText(/email/i);

      // When
      await user.type(input, "dev@prowler.com");

      // Then
      expect(input).toHaveAttribute("type", "text");
      expect(input).toHaveValue("dev@prowler.com");
      expect(
        screen.queryByRole("button", { name: /password/i }),
      ).not.toBeInTheDocument();
    });

    it("should hide the required indicator when isRequired is false", () => {
      // Given
      render(<TestForm isRequired={false} />);

      // Then
      expect(screen.queryByText("*")).not.toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).not.toBeRequired();
    });
  });
});
