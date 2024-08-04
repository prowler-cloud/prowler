"use client";

import { useRef } from "react";

import { deleteProvider } from "@/actions";

import { useToast } from "../ui/toast";
import { ButtonDeleteProvider } from "./ButtonDeleteProvider";

export const DeleteProvider = ({ id }: { id: string }) => {
  const ref = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  //   const [state, formAction] = useFormState(deleteProvider, initialState);

  async function clientAction(formData: FormData) {
    // reset the form
    ref.current?.reset();
    // client-side validation
    const result = await deleteProvider(formData);
    if (result?.error) {
      const error = result.error;
      //show error
      toast({
        title: `${error}`,
        description: "There was a problem with your request.",
      });
    } else {
      toast({
        title: "Success!",
        description: "The provider was removed successfully.",
      });
    }
  }
  return (
    <form ref={ref} action={clientAction} className="flex gap-x-2">
      <input type="hidden" name="id" value={id} />

      <ButtonDeleteProvider />
      {/* <p aria-live="polite" className="sr-only" role="status">
        {state?.message}
      </p> */}
    </form>
  );
};

// const [state, formAction] = useFormState(deleteTodo, initialState);

// return (
//   <form action={formAction}>
//     <input type="hidden" name="id" value={id} />
//     <input type="hidden" name="todo" value={todo} />
//     <DeleteButton />
// <p aria-live="polite" className="sr-only" role="status">
//   {state?.message}
// </p>
//   </form>
// );
