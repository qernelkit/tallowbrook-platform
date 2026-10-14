# Platform docs

Notes from the platform engineering team for everyone who deploys to, or is on
call for, the Tallowbrook platform.

## Security

- [Encryption at rest](security/encryption-at-rest.md): what protects stored
  data in each system, and who owns the keys.
- [TLS policy](security/tls-policy.md): listener policies, exceptions and how
  to request a change.

## Runbooks

- [Rotating signing keys](runbooks/rotate-signing-keys.md): container image,
  release and token signing keys.

## Onboarding

- [Local development](onboarding/local-development.md): getting the stack
  running on a laptop.

Questions go to #platform-eng. Changes to these pages go through a pull request
like any other change; tag the platform team for review.
