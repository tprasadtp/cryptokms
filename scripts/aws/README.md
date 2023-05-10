# Test Data Generators

This directory contains HTTP replay data generators, used for integration testing.
This is intentionally does not make use of `go generate` as it requires non-trivial setup.

## Creating AWS Resources

> **Warning**
>
> Always use sandbox accounts. Never use these in production or even qa/staging accounts.

You will need [aws-vault]. As `testdata.go` does no handle aws profiles to avoid pulling
in additional dependencies as well as to avoiding calls to STS which does not work well with http replayer. But it does support `AWS_ACCESS_KEY_ID`,`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. With `aws-vault` configured, `aws-vault exec` can be used.

> **Warning**
>
> This will incur some billing, though it should be around ~5$ as long as you run terraform destroy afterwards. You can use local-kms to avoid it.

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

## Creating AWS Resources (With local-kms)

> **Warning**
>
> localstack is not supported, as it **does not** support [asymmetric encryption](localstack_asymmetric)

- Run [local-kms] (if not running already)
    ```console
    docker compose --file scripts/aws/docker-compose.yml up -d
    ```
- Create KMS Keys
    ```console
    terraform \
        -chdir=scripts/aws apply \
        -var="kms_endpoint=http://localhost:8088/" \
        -var="access_key=test" \
        -var="secret_key=test" \
        -var="region=us-east-1"
    ```

- Save request and responses for HTTP replayer.
    ```console
    go run scripts/aws/testdata.go \
        -output awskms/internal/testdata/ \
        -config scripts/aws/keys.json \
        -access-key-id=test \
        -secret-access-key=test \
        -region=us-east-1 \
        -kms-endpoint="http://localhost:8088/"
    ```
- Destroy Keys
    ```console
    terraform \
        -chdir=scripts/aws destroy \
        -var="kms_endpoint=http://localhost:8088/" \
        -var="access_key=test" \
        -var="secret_key=test" \
        -var="region=us-east-1"
    ```


[aws-vault]: https://github.com/99designs/aws-vault
[local-kms]: https://github.com/nsmithuk/local-kms
