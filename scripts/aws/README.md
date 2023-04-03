# Test Data Generators

This directory contains HTTP replay data generators, used for integration testing.
This is intentionally does not use of `go generate` as it requires non-trivial setup.

## Creating AWS Resources (Without localstack)

> **Warning**
>
> Always use sandbox accounts. Never use these in production or even qa/staging accounts.

You will need [aws-vault]. As `testdata.go` does no handle aws profiles to avoid pulling
in additional dependencies as well as to avoiding calls to STS which does not work well with http replayer. But it does support `AWS_ACCESS_KEY_ID`,`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. With `aws-vault` configured, `aws-vault exec` can be used.

> **Warning**
>
> This will incur some billing, though it should be around ~5$ as long as you run terraform destroy afterwards. You can use localstack to avoid it.

- Create KMS Keys
    ```console
    aws-vault exec <aws-profile> -- terraform -chdir=scripts/aws apply
    ```

- Save request and responses for HTTP replayer.
    ```console
    aws-vault exec <aws-profile> -- go \
        run scripts/aws/testdata.go \
            -config keys.json \
            -output aws/internal/testdata
    ```
- Verify that there are no sensitive info or additional headers which are not ignored.
- Destroy Keys
    ```console
    aws-vault exec <aws-profile> -- terraform -chdir=scripts/aws destroy
    ```

## Creating AWS Resources (With localstack)

- Run [localstack] (if not running already)
    ```console
    docker compose --file scripts/aws/docker-compose.yml up --wait --wait-timeout=60
    ```
- Create KMS Keys
    ```console
    AWS_ACCESS_KEY_ID=test \
        AWS_SECRET_ACCESSS_KEY=test \
        AWS_REGION=us-east-1 \
        terraform \
        -chdir=scripts/aws apply \
        -var="kms_endpoint=http://127.0.0.1:4566/"
    ```

- Save request and responses for HTTP replayer.
    ```console
    go run scripts/aws/testdata.go \
        -config keys.json \
        -output aws/internal/testdata
    ```
- Destroy Keys
    ```console
        AWS_ACCESS_KEY_ID=test \
        AWS_SECRET_ACCESSS_KEY=test \
        AWS_REGION=us-east-1 \
        terraform \
        -chdir=scripts/aws \
        destroy
    ```


[aws-vault]: https://github.com/99designs/aws-vault
[localstack]: https://docs.localstack.cloud/user-guide/integrations/terraform/
