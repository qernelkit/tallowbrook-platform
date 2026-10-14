# pki

Certificates, keys and keystores for the staging stack. Services mount this tree at
`/etc/tallowbrook/pki` (Linux) or `C:/ProgramData/Tallowbrook/pki` (Windows).

Each certificate is one PEM block that starts with `-----BEGIN CERTIFICATE-----` and ends with the matching END line.
Private keys for production live in the HSM partition; the files in this tree serve the staging stack.

Layout: `ca/` issuing hierarchy, `services/` server and client certificates, `keystores/` Java and
PKCS#12 stores, `ssh/` host keys and the user CA, `signing/` release and firmware signing, `dnssec/`
zone keys, `vpn/` and `wireguard/` tunnel material.
