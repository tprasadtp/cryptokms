terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.59.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4.3"
    }
  }
}

// Locals
locals {
  signing_key_algorithms = [
    "EC_SIGN_P256_SHA256",
    "EC_SIGN_P384_SHA384",
    "RSA_SIGN_PKCS1_2048_SHA256",
    "RSA_SIGN_PKCS1_3072_SHA256",
    "RSA_SIGN_PKCS1_4096_SHA256",
    "RSA_SIGN_PKCS1_4096_SHA512",
  ]
  encryption_key_algorithms = [
    "RSA_DECRYPT_OAEP_2048_SHA1",
    "RSA_DECRYPT_OAEP_3072_SHA1",
    "RSA_DECRYPT_OAEP_4096_SHA1",
    "RSA_DECRYPT_OAEP_2048_SHA256",
    "RSA_DECRYPT_OAEP_3072_SHA256",
    "RSA_DECRYPT_OAEP_4096_SHA256",
    "RSA_DECRYPT_OAEP_4096_SHA512",
  ]
}

variable "project" {
  type        = string
  description = "GCP project ID"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]{1}$", var.project))
    error_message = "Project ID must be must be between 6 and 30 characters and can have lowercase letters, digits, or hyphens.It must start with a lowercase letter and end with a letter or number."
  }
}

// Provider
provider "google" {
  project = var.project
}

// Random keyring name
resource "random_id" "keyring_name" {
  prefix      = "itest-"
  byte_length = 4
}

// Resources
resource "google_kms_key_ring" "keyring" {
  name     = random_id.keyring_name.hex
  location = "global"
}

// Create signing keys
resource "google_kms_crypto_key" "signer" {
  for_each = toset(local.signing_key_algorithms)
  name     = format("%s", replace(lower(each.value), "_", "-"))
  key_ring = google_kms_key_ring.keyring.id
  purpose  = "ASYMMETRIC_SIGN"
  version_template {
    algorithm = each.value
  }
}

// Create decryption keys
resource "google_kms_crypto_key" "decrypter" {
  for_each = toset(local.encryption_key_algorithms)
  name     = format("%s", replace(lower(each.value), "_", "-"))
  key_ring = google_kms_key_ring.keyring.id
  purpose  = "ASYMMETRIC_DECRYPT"
  version_template {
    algorithm = each.value
  }
}

// Output key ID, algorithm and purpose to a json file.
resource "local_file" "output_json" {
  filename = "${path.module}/keys.json"
  content = jsonencode(
    {
      "ProjectName": var.project
      "KeyringName" : google_kms_key_ring.keyring.name
      "KeyringLocation" : google_kms_key_ring.keyring.location
      "Keys" : concat(
        [
          for k in google_kms_crypto_key.signer : {
            "KeyID" : k.id
            "KeyUsage" : k.purpose
            "KeyAlgorithm" : k.version_template[0].algorithm
          }
        ],
        [
          for k in google_kms_crypto_key.decrypter : {
            "KeyID" : k.id
            "KeyUsage" : k.purpose
            "KeyAlgorithm" : k.version_template[0].algorithm
          }
        ],
      )
    }
  )
}
