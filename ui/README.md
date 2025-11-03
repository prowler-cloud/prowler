# Description

This repository hosts the UI component for Prowler, providing a user-friendly web interface to interact seamlessly with Prowler's features.


## 🚀 Production deployment
### Docker deployment
#### Clone the repository
```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```
#### Build the Docker image
```bash
docker build -t prowler-cloud/ui . --target prod
```
#### Run the Docker container
```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment
#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Build the project

```bash
npm run build
```

#### Run the production server

```bash
npm start
```

## 🧪 Development deployment
### Docker deployment
#### Clone the repository
```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```
#### Build the Docker image
```bash
docker build -t prowler-cloud/ui . --target dev
```
#### Run the Docker container
```bash
docker run -p 3000:3000 prowler-cloud/ui
```

### Local deployment
#### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/ui.git

# SSH
git clone git@github.com:prowler-cloud/ui.git

```

#### Install dependencies

You can use one of them `npm`, `yarn`, `pnpm`, `bun`, Example using `npm`:

```bash
npm install
```

#### Run the development server

```bash
npm run dev
```

## Setup pnpm (optional)

If you are using `pnpm`, you need to add the following code to your `.npmrc` file:

```bash
public-hoist-pattern[]=*@nextui-org/*
```

After modifying the `.npmrc` file, you need to run `pnpm install` again to ensure that the dependencies are installed correctly.

## Environment Variables

### NEXT_PUBLIC_ALLOW_TENANT_CREATION

Controls whether new tenants can be created through the sign-up page.

- **Type**: String (`"true"` or `"false"`)
- **Default**: `"true"` (tenant creation enabled by default)
- **Description**: When set to `"false"`, the "Sign up" link is hidden from the login screen and tenant creation is disabled. Users with invitation tokens can still sign up even when tenant creation is disabled.

**Example:**
```bash
# Disable tenant creation
NEXT_PUBLIC_ALLOW_TENANT_CREATION=false

# Enable tenant creation (default)
NEXT_PUBLIC_ALLOW_TENANT_CREATION=true
```

> **Note**: This feature is useful in production environments where you want to restrict who can create new tenants, preventing unauthorized tenant creation while still allowing invited users to join.

## Technologies Used

- [Next.js 14](https://nextjs.org/docs/getting-started)
- [NextUI v2](https://nextui.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Tailwind Variants](https://tailwind-variants.org)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)
