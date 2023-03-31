terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

// Provider
provider "aws" {
}

// Types of keys
locals {
  signing_key_algorithms = [
    "RSA_4096",
    "RSA_3072",
    "RSA_2048",
    "ECC_NIST_P521",
    "ECC_NIST_P384",
    "ECC_NIST_P256",
  ]
  encryption_key_algorithms = [
    "RSA_4096",
    # "RSA_3072",
    # "RSA_2048",
    # "ECC_NIST_P521",
    # "ECC_NIST_P384",
  ]
}

// Create signing keys
resource "aws_kms_key" "signer" {
  for_each                 = toset(local.signing_key_algorithms)
  customer_master_key_spec = each.value
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
  description              = format("Singer - %s tprasadtp/cryptokms intergration test", each.value)
  tags = {
    "provisioner" : "terraform"
    "project" : "tprasadtp/cryptokms"
    "autoclean" : "true"
    "io.github.tprasadtp.metadata.spinner.project" : "tprasadtp/cryptokms"
    "io.github.tprasadtp.metadata.spinner.autoclean" : "true"
  }
}

resource "aws_kms_key" "decrypter" {
  for_each                 = toset(local.encryption_key_algorithms)
  customer_master_key_spec = each.value
  key_usage                = "ENCRYPT_DECRYPT"
  deletion_window_in_days  = 7
  description              = format("Decrypter - %s tprasadtp/cryptokms intergration test", each.value)
  tags = {
    "provisioner" : "terraform"
    "project" : "tprasadtp/cryptokms"
    "autoclean" : "true"
    "io.github.tprasadtp.metadata.spinner.project" : "tprasadtp/cryptokms"
    "io.github.tprasadtp.metadata.spinner.autoclean" : "true"
  }
}

// Output key ARN, spec and usage to a json file.
resource "local_file" "output_json" {
  filename = "${path.module}/keys.json"
  content = jsonencode(
    {
      "Keys" : concat(
        [
          for k in aws_kms_key.signer : {
            "KeyID" : k.arn
            "KeyUsage" : k.key_usage
            "KeyAlgorithm" : k.customer_master_key_spec
          }
        ],
        [
          for k in aws_kms_key.decrypter : {
            "KeyID" : k.arn
            "KeyUsage" : k.key_usage
            "KeyAlgorithm" : k.customer_master_key_spec
          }
        ]
      )
    }
  )
}
