# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial package skeleton.
- RFC 8785 canonical JSON and binary/text content normalization.
- CAWG-compatible policies with validated PACT permission extensions.
- Registry-scoped P-256 claimant identities with RFC 7638 key identifiers.
- OS credential-store and encrypted PKCS#8 identity persistence.
- PACT Manifest v1 commitments, ES256 signatures, strict parsing, and layered
  verification reports.
- Visible, invisible, and combined text carriers with zero-width locators.
- HTML and XML carrier embedding and extraction for ``pact.text.v1``
  manifests.
- Initial C2PA integration for supported embedded image formats.
- C2PA PDF embedded-file-stream writing and extraction for prebuilt manifest
  stores.
- C2PA ZIP-based document embedding and extraction for formats such as DOCX.
- Hybrid C2PA document signing helpers that reuse the official CAI signer path
  for PDF, DOCX, and detached legacy-document workflows.
- C2PA inspection helpers and external-manifest reference bootstrap metadata
  for formats that still need a non-embedded workflow.
- Append-only registry-core services with replay challenges, proof-of-work
  validation, profile registration, claim registration, key rotation,
  revocation, disputes, domain verification, certificate issuance, and Merkle
  batch hashing.
- FastAPI registry API, public HTML claim/profile proof pages, loopback-local
  web mode, and a ``pact`` CLI entrypoint for identity, signing, verification,
  inspection, and service startup.
