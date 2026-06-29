# Security Policy

## Supported versions

Security fixes are provided for the latest released version. PACT is pre-alpha,
so public APIs, deployment templates, and carrier details may still
change when a security issue requires it.

## Reporting a vulnerability

Do not report vulnerabilities in a public issue. Use GitHub's private
security-advisory reporting for this repository.

Please include:

- affected version or commit
- affected component, such as CLI, registry API, browser workspace, carrier, or
  deployment template
- reproduction steps
- expected and observed impact
- whether private content, keys, nonces, device material, or registry secrets
  can be exposed
- suggested mitigation, if you have one

You should receive an acknowledgement within seven days. Disclosure timing will
be coordinated after the issue has been assessed and a fix is available.

## Security boundaries

PACT is designed so registries store signed claims and public evidence, not raw
private content. Please report any path that publishes or returns:

- plaintext content for a private claim
- private nonces
- identity private keys or decrypted identity material
- raw browser or hardware fingerprint source material
- prompts, probe text, provider responses, or private evidence packages
- registry CA private keys or deployment secrets

Baseline unauthenticated profiles must still have a signed private
device-binding token. Higher trust labels, such as hosted account, domain
verification, documented rights, or third-party attestation, require additional
registry evidence and must not be self-asserted by the claimant.

## Out of scope

PACT does not claim to determine whether content is real, AI-generated, legally
owned, or legally licensed. Reports about those limitations are useful only when
the product presents them incorrectly or a verifier overstates what was checked.
