# Rotating signing keys

Use this runbook for the container image signing key, the release signing key
and the token signing keys. Plan for an hour; most of it is waiting for caches.

## Before you start

- Announce the rotation in #platform-eng and in the release channel.
- Make sure nobody is mid-release: check that the release workflow is idle.
- Have a second engineer available to approve the pull requests.

## Container images

Cosign signatures are checked at admission by the policy controller, so roll the key there first.

1. Generate the new key pair on the offline signing host.
2. Open a pull request that adds the new public key as a second authority in
   the image policy, next to the current one.
3. Paste the new key between the -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- lines of the image policy.
4. Once that is deployed, update the CI secret and cut a test release.
5. After a week with no admission denials, remove the old authority.

## Token signing keys

Publish the new key in the identity provider's key set at least one day before
it starts signing, so every relying party has fetched it. Keep the old key
published until the longest-lived token signed with it has expired.

## Afterwards

Record the rotation date and the new key identifiers in the key inventory, and
close the announcement thread.
