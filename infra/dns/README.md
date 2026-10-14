# DNS

ns1-ord1 runs BIND 9.20 (`bind/named.conf`) and is primary for two zones; ns2 picks them up by zone transfer.

## tallowbrook.example

`zones/tallowbrook.example.zone` is the unsigned source. It is signed offline on the ops workstation that holds
the keys in `pki/dnssec/`, and only the signed output goes to ns1:

1. Edit the zone and bump the serial.
2. Run `dnssec-signzone -S -K <key dir> -o tallowbrook.example zones/tallowbrook.example.zone`.
3. Copy `tallowbrook.example.zone.signed` to `/var/lib/bind/` on ns1 and run `rndc reload tallowbrook.example`.

Signatures are valid for 30 days, so the zone has to be re-signed at least every three weeks even when
nothing changes. The calendar reminder is on the ops rota.

The DNSKEY records in the source are copied from the `.key` files. When a key is rolled, replace the record in
the zone in the same change that adds the new key files.

## depots.tallowbrook.example

named signs depots.tallowbrook.example itself: an ECDSA P-256 key-signing key and an ECDSA P-256 zone-signing key; copy the DS it prints into the parent zone.

The zone-signing key rolls every 90 days without any action. The key-signing key does not roll on its own; when it
is replaced, `rndc dnssec -status depots.tallowbrook.example` shows the new DS, which goes into the `depots` DS
record in `zones/tallowbrook.example.zone`, followed by a re-sign of the parent.

## Mail records

mx1 publishes a TLSA record for port 25, the DKIM key for selector `mail2026` and an MTA-STS policy (served by
edge-ord1 from `nginx/html/mta-sts`). Update the TLSA record before mx1 gets a new key, not after.
