import { render, screen } from "@testing-library/react";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "./Form";

interface TestValues {
  providerUid: string;
}

function TestFormWithError() {
  const form = useForm<TestValues>({
    defaultValues: {
      providerUid: "",
    },
  });

  useEffect(() => {
    form.setError("providerUid", {
      type: "manual",
      message: "Provider ID is required",
    });
  }, [form]);

  return (
    <Form {...form}>
      <FormField
        control={form.control}
        name="providerUid"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Provider UID</FormLabel>
            <FormControl>
              <input {...field} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    </Form>
  );
}

describe("Form", () => {
  it("should use the existing error text token for labels and messages", async () => {
    // Given
    render(<TestFormWithError />);

    // When
    const label = await screen.findByText("Provider UID");
    const message = await screen.findByText("Provider ID is required");

    // Then
    expect(label).toHaveClass("text-text-error-primary");
    expect(message).toHaveClass("text-text-error-primary");
  });
});
