import bcryptjs from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

export const userMockData = [
  {
    id: uuidv4(), // Generate a unique UUID.
    tenantId: "12646005-9067-4d2a-a098-8bb378604362",
    email: "admin@prowler.com",
    name: "Admin Prowler",
    companyName: "Prowler",
    password: bcryptjs.hashSync("123123", 10),
    role: "admin",
    image: null,
  },
  {
    id: uuidv4(), // Generate a unique UUID.
    tenantId: "12646005-9067-4d2a-a098-8bb378604362",
    email: "user@prowler.com",
    name: "User Prowler",
    companyName: "Prowler",
    password: bcryptjs.hashSync("123123", 10),
    role: "user",
    image: null,
  },
];
