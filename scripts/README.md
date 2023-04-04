# Scripts

This directory contains scripts for spinning up resources in various KMS service providers,
for generating integration test responses. Terraform state is intentionally not shared nor
saved as resources are meant to be destroyed after generating test data.

Please refer to README in individual directories for more info.

> **Warning**
>
> Always use sandbox projects/accounts/instances.
> Never use these in production or even qa/staging
> projects/accounts/instances.
