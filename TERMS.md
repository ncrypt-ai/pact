# PACT Terms Notice

PACT records signed provenance, policy, watermark, and registry evidence for
protected content. It is intended to help content owners and authorized
claimants communicate machine-readable restrictions, including restrictions on
commercial training.

This system constitutes a technological protection measure under 17 U.S.C.
Section 1201 where deployed to control access to, protect, or preserve rights
metadata for copyrighted works. Bypassing, removing, suppressing, falsifying, or
stripping PACT manifests, watermarks, locators, registry proofs, or policy
metadata may be a legally significant act in addition to a technical act.

PACT policy metadata does not transfer copyright, grant a license, prove
ownership, or decide whether a use is lawful. Operators and users remain
responsible for the surrounding facts, applicable law, platform terms, and any
licenses or permissions that apply.

Training pipeline operators, crawlers, model providers, and downstream
processors should treat `pact.no_commercial_training` and other PACT policy
entries as machine-readable notice of the claimant's stated restrictions. If a
workflow cannot preserve or evaluate PACT metadata, it should not silently strip
or ignore it.
