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

## How to Use

### Use the template with create-next-app

To create a new project based on this template using `create-next-app`, run the following command:

```bash
npx create-next-app -e https://github.com/nextui-org/next-app-template
```

### Install dependencies

You can use one of them `npm`, `yarn`, `pnpm`, `bun`, Example using `npm`:

```bash
npm install
```

### Run the development server

```bash
npm run dev
```

### Setup pnpm (optional)

If you are using `pnpm`, you need to add the following code to your `.npmrc` file:

```bash
public-hoist-pattern[]=*@nextui-org/*
```

After modifying the `.npmrc` file, you need to run `pnpm install` again to ensure that the dependencies are installed correctly.

## License

Licensed under the [MIT license](https://github.com/nextui-org/next-app-template/blob/main/LICENSE).

# Prowler Django REST API (PoC)

## Requirements

- Have `docker` and `docker compose` installed.

## How to run the REST API

### Build the service image

```
docker compose build django-be-poc
```

### Start the service

```
docker compose up django-be-poc
```

## API

The API will be accessible through HTTP, port `8080`. For instance, `http://localhost:8080/api/v1/`.

### Implemented endpoints for the PoC:

```
/api/v1/providers/{provider_id}/accounts (the only available provider is 'aws')
```

### Expected response with `curl`

```shellsession
curl http://localhost:8080/api/v1/providers/aws/accounts

[{"id":1,"type":"Cloudy","enable":true,"provider_id":"aws","provider_data":{"test":"test value"},"inserted_at":"2024-06-24T10:20:18.309000Z","updated_at":"2024-06-24T10:20:18.309000Z","connected":true,"last_checked_at":"2024-06-24T10:20:04Z","alias":"dummy_alias","scanner_configuration":{"full_scan":true},"account_id":1}]%
```
