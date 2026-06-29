Technological Protection Measure Specification
==============================================

Purpose
-------

PACT is published as a provenance, policy, watermarking, and registry system
intended to help protect copyrighted works and other protected content from
unauthorized training, redistribution, and policy removal. A deployment can use
PACT as a technological protection measure when it combines:

- a signed manifest that binds policy metadata to content;
- machine-readable training restrictions such as
  ``pact.no_commercial_training``;
- carrier or watermark data that lets verifiers recover the protected claim;
- registry evidence for publication, revocation, dispute, and key continuity;
- public notice that removing or bypassing the system may be legally
  significant.

This document describes design intent and technical behavior. It is not a
court finding, legal advice, or a guarantee that a particular deployment
satisfies every element of 17 U.S.C. Section 1201 in every jurisdiction.

Policy scope
------------

PACT manifests carry a ``cawg.training-mining`` policy block. The
``pact.no_commercial_training`` entry is the explicit machine-readable marker
for commercial training restrictions:

.. code-block:: json

   {
     "policy": {
       "label": "cawg.training-mining",
       "entries": {
         "cawg.ai_generative_training": {"use": "notAllowed"},
         "pact.no_commercial_training": {"use": "notAllowed"}
       }
     }
   }

The manifest signature covers this policy block. Removing, rewriting, or
replacing it changes what a verifier can authenticate.

Watermark and fingerprint signals
---------------------------------

PACT supports multiple carrier and watermark families. Plain text, HTML, XML,
C2PA, document containers, image soft bindings, and experimental text
watermarks serve different recovery and verification roles.

The experimental statistical text watermark is a radioactive-style signal: it
marks a keyed subset of sentences with an approved phrase and records the
selection pattern. If later model outputs show enrichment for the selected
pattern compared with control positions, PACT can report that enrichment as
training-use evidence. Purifying content to remove the marker, locator, or
statistical pattern is itself a meaningful technical act that verifiers and
operators can evaluate alongside registry state and policy terms.

Statistical enrichment is evidence, not a standalone legal conclusion. PACT
keeps the detection score, inspected positions, matches, and control hits
separate so a reviewer can see what was measured.

Notice and circumvention context
--------------------------------

17 U.S.C. Section 1201 addresses circumvention of technological measures that
control access to protected works and trafficking in circumvention tools. The
statute also contains definitions, limitations, and exceptions. The public text
is available at https://www.law.cornell.edu/uscode/text/17/1201.

PACT deployments should publish terms that give clear notice that the system is
intended to function as a technological protection measure and that bypassing,
removing, suppressing, or falsifying PACT manifests, watermarks, locators, or
registry proofs may be a legally significant act. See ``TERMS.md`` for a
plain-language notice template.

Operator requirements
---------------------

A production registry should keep the protection story consistent:

- publish the exact policy keys it honors;
- keep private content, private nonces, prompts, and provider responses out of
  registry storage;
- provide proof pages that show what was signed, checked, disputed, or revoked;
- retain audit logs for registry mutations according to a documented policy;
- document how circumvention reports, disputes, and security reports are
  handled;
- avoid claiming that a watermark, manifest, or C2PA credential proves more
  than it actually verifies.
