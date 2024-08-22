import { z } from "zod";

export const authFormSchema = z.object({
  username: z
    .string()
    .min(4, {
      message: "Username must be at least 4 characters.",
    })
    .max(20),
  password: z.string().min(6),
  email: z.string().email(),
});
