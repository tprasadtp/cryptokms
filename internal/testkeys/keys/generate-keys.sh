#!/bin/bash

set -e

function log() {
    local msg="$*"
    printf "==> %s \n" "$msg"
}

BASE_DIR="$(dirname "$0")"

while [[ ${1} != "" ]]; do
    case ${1} in
    --generate-private-keys | --regenerate-private-keys | -p | --private | --gen-private)
        log "Enable generating/regenerating private keys"
        GENERATE_PRIVATE_KEYS="1"
        ;;
    *)
        log "Unknown flag: $1"
        exit 1
    esac
    shift
done

if [[ $GENERATE_PRIVATE_KEYS == "1" ]]; then
    for size in 1024 2048 3072 4096; do
        log "Generating RSA $size Private Key"
        openssl genpkey \
            -quiet \
            -outform PEM \
            -algorithm RSA \
            -pkeyopt "rsa_keygen_bits:${size}" \
            -out "${BASE_DIR}/rsa_${size}.key"
    done

    for curve in 256 384 521; do
        log "Generating EC $curve Private Key"
        openssl genpkey \
            -quiet \
            -outform PEM \
            -algorithm EC \
            -pkeyopt "ec_paramgen_curve:P-${curve}" \
            -pkeyopt "ec_param_enc:named_curve" \
            -out "${BASE_DIR}/ecdsa_p${curve}.key"
    done
fi

for size in 1024 2048 3072 4096; do
    log "Generating RSA $size Public Key"
    openssl rsa \
        -in "${BASE_DIR}/rsa_${size}.key" \
        -outform PEM \
        -pubout -out "${BASE_DIR}/rsa_${size}.pub"
done

for curve in 256 384 521; do
    log "Generating EC $curve Public Key"
    openssl ec \
        -in "${BASE_DIR}/ecdsa_p${curve}.key" \
        -outform PEM \
        -pubout -out "${BASE_DIR}/ecdsa_p${curve}.pub"
done
