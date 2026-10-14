# Payment PIN keys live in a CloudHSM cluster behind a KMS custom key store,
# so the card services call KMS while the key material stays in our HSMs.

resource "aws_cloudhsm_v2_cluster" "payments" {
  hsm_type   = "hsm2m.medium"
  mode       = "FIPS"
  subnet_ids = slice(aws_subnet.private[*].id, 0, 2)

  tags = { Name = "payments-pin" }
}

resource "aws_cloudhsm_v2_hsm" "payments" {
  count = 2

  cluster_id = aws_cloudhsm_v2_cluster.payments.cluster_id
  subnet_id  = aws_subnet.private[count.index].id
}

# Issuing certificate of the cluster's trust anchor, uploaded when the cluster
# was initialised (runbook: payments HSM bring-up).
data "aws_ssm_parameter" "payments_trust_anchor" {
  name = "/platform/payments-hsm/customer-ca"
}

resource "aws_kms_custom_key_store" "payments_hsm" {
  custom_key_store_name    = "payments-hsm"
  cloud_hsm_cluster_id     = aws_cloudhsm_v2_cluster.payments.cluster_id
  key_store_password       = var.kmsuser_password
  trust_anchor_certificate = data.aws_ssm_parameter.payments_trust_anchor.value

  depends_on = [aws_cloudhsm_v2_hsm.payments]
}

resource "aws_kms_key" "pin_master" {
  description             = "Payment PIN block master key"
  custom_key_store_id     = aws_kms_custom_key_store.payments_hsm.id
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "pin_master" {
  name          = "alias/tb-pin-master"
  target_key_id = aws_kms_key.pin_master.key_id
}
