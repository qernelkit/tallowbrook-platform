# Customer managed keys. Signing and MAC keys are declared here directly; the
# data-encryption keys go through modules/kms-key so they share one policy shape.

locals {
  # One signing key per billing document family. Credit notes will join when
  # billing starts issuing them as PDFs.
  document_signing_key_specs = {
    invoices = "ECC_NIST_P384"
  }
}

data "aws_iam_policy_document" "ledger_signing_key" {
  statement {
    sid       = "AccountRoot"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "LedgerBatchSigner"
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ledger_batch_signer.arn]
    }
  }
}

resource "aws_iam_role" "ledger_batch_signer" {
  name               = "ledger-batch-signer"
  assume_role_policy = data.aws_iam_policy_document.eks_pod_identity.json
}

data "aws_iam_policy_document" "eks_pod_identity" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "ledger_signing" {
  description              = "Ledger journal batch signatures"
  customer_master_key_spec = "RSA_4096"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.ledger_signing_key.json
}

resource "aws_kms_key" "api_token_signing" {
  description              = "Access tokens issued by the public API"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
}

resource "aws_kms_key" "release_attestation" {
  description              = "Release manifests and build attestations"
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
}

resource "aws_kms_key" "webhook_mac" {
  description              = "Partner webhook request tags"
  customer_master_key_spec = "HMAC_256"
  key_usage                = "GENERATE_VERIFY_MAC"
  deletion_window_in_days  = 30
}

resource "aws_kms_key" "document_signing" {
  for_each = local.document_signing_key_specs

  description              = "Billing ${each.key} PDFs"
  customer_master_key_spec = each.value
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
}

resource "aws_kms_alias" "ledger_signing" {
  name          = "alias/tb-ledger-signing"
  target_key_id = aws_kms_key.ledger_signing.key_id
}

resource "aws_kms_alias" "api_token_signing" {
  name          = "alias/tb-api-token-signing"
  target_key_id = aws_kms_key.api_token_signing.key_id
}

resource "aws_kms_alias" "release_attestation" {
  name          = "alias/tb-release-attestation"
  target_key_id = aws_kms_key.release_attestation.key_id
}

resource "aws_kms_alias" "webhook_mac" {
  name          = "alias/tb-webhook-mac"
  target_key_id = aws_kms_key.webhook_mac.key_id
}

resource "aws_kms_alias" "document_signing" {
  for_each = aws_kms_key.document_signing

  name          = "alias/tb-${each.key}-signing"
  target_key_id = each.value.key_id
}

module "export_data_key" {
  source         = "./modules/kms-key"
  alias          = "tb-exports"
  description    = "Partner export bundles and their data keys"
  user_role_arns = [aws_iam_role.export_worker.arn]
}

module "reporting_db_key" {
  source      = "./modules/kms-key"
  alias       = "tb-reporting-db"
  description = "Reporting database storage"
}

module "vault_unseal_key" {
  source      = "./modules/kms-key"
  alias       = "tb-vault-unseal"
  description = "Vault auto-unseal"
}

module "ebs_key" {
  source      = "./modules/kms-key"
  alias       = "tb-ebs-default"
  description = "Default key for new EBS volumes"
}

module "backups_key" {
  source      = "./modules/kms-key"
  alias       = "tb-db-backups"
  description = "Database backup bucket"
}

module "enclave_seed_key" {
  source      = "./modules/kms-key"
  alias       = "tb-enclave-seed"
  description = "Wraps the signing seed released to the Nitro Enclave"
}

resource "aws_iam_role" "export_worker" {
  name               = "export-worker"
  assume_role_policy = data.aws_iam_policy_document.eks_pod_identity.json
}

data "aws_caller_identity" "current" {}
