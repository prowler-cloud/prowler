
# Create a new Provider for Prowler

Here you can find how to create a new Provider in Prowler to give support for making all security checks needed and make your cloud safer!

## Introduction

Providers are the foundation on which Prowler is built, a simple definition for a cloud provider could be "third-party company that offers a platform where any IT resource you need is available at any time upon request". The most well-known cloud providers are Amazon Web Service, Azure from Microsoft and Google Cloud which are already supported by Prowler.

To create a new provider that is not supported now by Prowler and add your security checks must create a new folder where store all related with it (services, checks, etc.). It must be store in route `prowler/providers/<new_provider_name>/`.

Inside that folder, you MUST create the following files and folders:

- A `lib` folder: to store all extra functions.
- A `services` folder: to store all [services](./services.md) to audit.
- An empty `__init__.py`: to make Python treat this service folder as a package.
- A `<new_provider_name>_provider.py`, containing all the provider's logic necessary to get authenticated in the provider, configurations and extra data useful for final report.
- A `models.py`, containing all the models necessary for the new provider.

## Provider

The Prowler's provider structure is the following and the way to use it is just in the generic service of each provider passing as a parameter of constructor to initialize all necessary session values.

### Base Class

All the providers in Prowler inherits from the same [base class](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py). It is an [abstract base class](https://docs.python.org/3/library/abc.html) that defines the interface for all provider classes in the auditing system.

### Provider Class

Due to the complexity and differencies of each provider use the rest of the providers as a template for the implementation.

- [AWS](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- [GCP](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- [Azure](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- [Kubernetes](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)

Remember that this class must be used to get credentials and the configuration.
