# Test Data Generators

This directory contains GRPC replay data generators, used for integration testing.
This is intentionally does not make use of `go generate` as it requires non-trivial setup.

## Recreating test data

> **Warning**
>
> Always use sandbox projects. Never use these in production or even qa/staging projects.

- Create a new GCP project. Recreating test data will create KMS resources
which have immutable references and can never be destroyed(key material which incurs billing can be destroyed, but not the keyring and key names). If you want to keep KMS/keyrings tidy, create a new project just for this.
- Setup and Authenticate to Google Cloud via gcloud. If using a Service account, assign following roles.
    - [`roles/cloudkms.admin`](https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.admin)
    - [`roles/cloudkms.cryptoOperator`](https://cloud.google.com/kms/docs/reference/permissions-and-roles#cloudkms.cryptoOperator)

- If not already done, enable billing on the project.
- If not already done, enable KMS APIs.
    ```console
    gcloud services enable cloudkms.googleapis.com
    ```
- Initialize terraform
    ```console
    terraform -chdir=scripts/gcp init
    ```
- Create required KMS Keyring and keys. This keyring **must ony** be used for integration testing. Keyring name is automatically generated.
    > **Warning**
    >
    > This will incur some billing, though it should be less than 0.1$.
    > as long as you destroy it soon after recording grpc responses.

    ```console
    terraform -chdir=scripts/gcp apply -var="project=<your-sandbox-project-id>"
    ```
- Save GRPC responses which can be used for integration tests
    ```console
    go run scripts/gcp/testdata.go \
        -config scripts/gcp/keys.json \
        -output gcpkms/internal/testdata/
    ```
- Destroy **all** keys in the created keyring.
    ```console
    terraform -chdir=scripts/gcp destroy -var="project=<your-sandbox-project-id>"
    ```
