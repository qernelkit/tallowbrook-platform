# Site-to-site VPN to the ORD depot firewall.

resource "aws_customer_gateway" "depot_ord" {
  bgp_asn    = 65040
  ip_address = var.depot_ord_public_ip
  type       = "ipsec.1"

  tags = { Name = "depot-ord" }
}

resource "aws_vpn_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "platform-${var.environment}" }
}

resource "aws_vpn_gateway_route_propagation" "private" {
  vpn_gateway_id = aws_vpn_gateway.main.id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpn_connection" "depot_ord" {
  customer_gateway_id = aws_customer_gateway.depot_ord.id
  vpn_gateway_id      = aws_vpn_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = true

  tunnel1_preshared_key                = "dSpcl1Ck6RCjORSb02qLOyT81K218MiZ"
  tunnel1_phase1_encryption_algorithms = ["AES256-GCM-16"]
  tunnel1_phase1_dh_group_numbers      = [20]

  tunnel2_preshared_key = "pvexZUCI77FhlOOIi.9ipIJgcIAJTqEG"

  tags = { Name = "depot-ord" }
}

resource "aws_vpn_connection_route" "depot_ord" {
  vpn_connection_id      = aws_vpn_connection.depot_ord.id
  destination_cidr_block = var.depot_ord_cidr
}
