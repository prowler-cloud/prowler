# Prowler Documentation

This repository contains the Prowler Open Source documentation powered by [Mintlify](https://mintlify.com).

## Documentation Structure

- **Getting Started**: Overview, installation, and basic usage guides
- **User Guide**: Comprehensive guides for Prowler App, CLI, providers, and compliance
- **Developer Guide**: Technical documentation for developers contributing to Prowler

## Local Development

Install the [Mintlify CLI](https://www.npmjs.com/package/mint) to preview documentation changes locally:

```bash
npm i -g mint
```

Run the following command at the root of your documentation (where `mint.json` is located):

```bash
mint dev
```

View your local preview at `http://localhost:3000`.

## Publishing Changes

Changes pushed to the main branch are automatically deployed to production through Mintlify's GitHub integration.

## Documentation Guidelines

When contributing to the documentation, please follow the Prowler documentation style guide located in the `.claude` directory.

## Troubleshooting

- If your dev environment isn't running: Run `mint update` to ensure you have the most recent version of the CLI.
- If a page loads as a 404: Make sure you are running in a folder with a valid `mint.json` file and that the page path is correctly listed in the navigation.

## Resources

- [Prowler GitHub Repository](https://github.com/prowler-cloud/prowler)
- [Prowler Documentation](https://docs.prowler.com/)
- [Mintlify Documentation](https://mintlify.com/docs)
- [Mintlify Community](https://mintlify.com/community)
