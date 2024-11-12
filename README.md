# Next.js & NextUI Template

This is a template for creating applications using Next.js 14 (app directory) and NextUI (v2).

[Try it on CodeSandbox](https://githubbox.com/nextui-org/next-app-template)

## Technologies Used

- [Next.js 14](https://nextjs.org/docs/getting-started)
- [NextUI v2](https://nextui.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Tailwind Variants](https://tailwind-variants.org)
- [TypeScript](https://www.typescriptlang.org/)
- [Framer Motion](https://www.framer.com/motion/)
- [next-themes](https://github.com/pacocoursey/next-themes)

## Use the template with create-next-app

To create a new project based on this template using `create-next-app`, run the following command:

```bash
npx create-next-app -e https://github.com/nextui-org/next-app-template
```

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

## License

Licensed under the [MIT license](https://github.com/nextui-org/next-app-template/blob/main/LICENSE).
