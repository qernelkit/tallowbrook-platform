# Ops toolbox: every CLI the scripts in infra/scripts need, at pinned versions.
#   docker build -t registry.tallowbrook.example/platform/ops-toolbox:2026.10 -f infra/scripts/toolbox/Dockerfile infra/scripts

FROM golang:1.25.3-alpine3.22 AS kubeseal
RUN go install github.com/bitnami-labs/sealed-secrets/cmd/kubeseal@v0.32.2

FROM hashicorp/vault:1.20.4 AS vault

FROM alpine:3.22

RUN apk add --no-cache \
      bash=5.2.37-r0 \
      coreutils=9.7-r1 \
      xxd=9.1.1566-r0 \
      openssl=3.5.9-r0 \
      openssh-client-default=10.0_p1-r10 \
      gnupg=2.4.9-r0 \
      age=1.2.1-r10 \
      sops=3.9.4-r11 \
      borgbackup=1.4.3-r0 \
      cryptsetup=2.7.5-r1 \
      tpm2-tools=5.7-r1 \
      opensc=0.26.0-r0 \
      yubikey-manager=5.6.1-r0 \
      krb5=1.21.3-r0 \
      aws-cli=2.27.25-r0 \
      kubectl=1.33.1-r5 \
      github-cli=2.72.0-r6 \
      postgresql17-client=17.11-r0

RUN apk add --no-cache aria2 curl jq

COPY --from=kubeseal /go/bin/kubeseal /usr/local/bin/kubeseal
COPY --from=vault /bin/vault /usr/local/bin/vault

WORKDIR /opt/ops
COPY . .

ENTRYPOINT ["/bin/bash"]
