# TLS policy

Every listener the platform team runs has a named policy in the infrastructure
code. This page explains the choices and the exceptions.

## Public listeners

Public listeners negotiate TLS 1.3 and offer hybrid ML-KEM key exchange to clients that support it.

Clients that cannot do TLS 1.3 still connect over TLS 1.2 with forward-secret
suites only. The edge probe in CI checks every public hostname each hour and
pages the on-call engineer if a listener stops offering the hybrid exchange.

## Carrier and partner listeners

The carrier listener still accepts TLS 1.0 for two EDI partners; see the exception register for end dates.

Partners on the API Gateway domain and the partner portal get TLS 1.2 or
later. New partners are never added to the carrier listener; they onboard
through the partner API.

## Inside the cluster

Service-to-service traffic goes through the mesh with mutual TLS, and the mesh
default floor is TLS 1.3. The ledger service additionally pins its clients to
mesh-issued certificates.

## Exceptions

Exceptions are time-boxed and recorded in the exception register with an owner
and an end date. The platform team reviews the register monthly. Ask in
#platform-eng before you promise a partner anything.
