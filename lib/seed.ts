import bcryptjs from "bcryptjs";

export const initialData = {
  users: [
    {
      email: "admin@admin.com",
      name: "Admin User",
      password: bcryptjs.hashSync("123456", 10),
      role: "admin",
    },
    {
      email: "user@user.com",
      name: "Prowler User",
      password: bcryptjs.hashSync("123456", 10),
      role: "user",
    },
  ],
};
