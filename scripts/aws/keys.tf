terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

variable "kms_endpoint" {
  type        = string
  description = "AWS KMS endpoint. If not specified uses default AWS KMS endpoint."
  default     = null
  nullable    = true
}

variable "access_key" {
  type        = string
  description = "AWS Access Key ID"
  default     = null
  nullable    = true
}

variable "secret_key" {
  type        = string
  description = "AWS Secret Access Key"
  default     = null
  nullable    = true
}

variable "region" {
  type        = string
  description = "AWS Region"
  default     = "us-east-1"
}



// Provider
provider "aws" {
  access_key = var.access_key
  secret_key = var.secret_key
  region = var.region
  // Skip validations when api endpoint is specified.
  skip_credentials_validation = var.kms_endpoint != "" ? true : null
  skip_requesting_account_id = var.kms_endpoint != "" ? true : null
  skip_metadata_api_check = var.kms_endpoint != "" ? true : null
  endpoints {
    kms = var.kms_endpoint
  }
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
    "RSA_3072",
    "RSA_2048",
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
