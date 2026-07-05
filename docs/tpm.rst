Technological Protection Measure Specification
==============================================

Purpose
-------

PACT can be deployed as a technological protection measure (TPM) for
copyrighted works. A deployment that combines signed manifests with
machine-readable restrictions, carrier or watermark signals, and a public
registry creates a system that lets verifiers, crawlers, and pipeline operators
identify protected content and the policies attached to it.

This document describes design intent and technical behavior. It is not legal
advice, a court finding, or a guarantee that any specific deployment satisfies
every element of 17 U.S.C. Section 1201 in every jurisdiction. Operators should
have counsel review the deployment, policy language, and applicable law before
relying on PACT in a legal process.

What makes a deployment a TPM
------------------------------

A PACT deployment functions as a TPM when it combines all of:

**Signed policy binding.** The manifest's ``policy`` block is covered by the
claimant's ES256 signature. Removing, rewriting, or replacing it changes what
any verifier can authenticate. The signature algorithm and canonicalization
(RFC 8785) make this tamper-evident.

**Machine-readable training restrictions.** The ``pact.no_commercial_training``
policy entry is an explicit, machine-readable commercial-training restriction,
distinct from the broader ``cawg.ai_generative_training`` key. Pipelines that
process training data can detect and honor this restriction without interpreting
prose.

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

**Carrier and watermark signals.** One or more of the carrier formats described
in :doc:`carriers <carriers>` attach the manifest and a locator to the content
so the claim can be recovered even when the manifest is distributed separately
from the original file. Statistical text watermarks add a recoverable keyed
signal that persists through some transformations.

**Registry evidence.** A public registry records the claim, its current
revocation and dispute state, and the claimant's trust tier. Public proof pages
at ``/pact/claims/{claim_id}`` let anyone verify that a specific claim exists,
has not been revoked, and has not been successfully disputed.

**Public notice.** Plain-text carrier embeddings include a PACT notice in the
visible proof block. Operators should additionally publish terms giving clear
notice that the system is a TPM and that bypassing, removing, or falsifying
manifests, watermarks, locators, or registry proofs may be a legally significant
act. See ``TERMS.md`` for a plain-language notice template.

Statistical watermarks as evidence
------------------------------------

The statistical text watermark records a keyed selection of sentence positions
in the protected content. When provider outputs later show enrichment for the
selected pattern compared to unselected control positions, PACT reports that
enrichment alongside confidence intervals and corrected p-values.

This is evidence, not a legal conclusion. The report shows what was measured —
the positions, the matches, the control hit rate — so a reviewer can evaluate
the enrichment rather than accepting a black-box score. A claimant who purifies
the content to remove the statistical marker or the locator takes a deliberate
technical action that is itself relevant evidence in a review.

Operator requirements for a consistent protection story
--------------------------------------------------------

A production registry that presents itself as a TPM should:

- Publish the exact policy keys it honors and how they are enforced
- Keep private content, private nonces, prompts, and provider responses out of
  registry storage (enforced by ``audit_signed_manifest_publication``)
- Provide public proof pages showing what was signed, checked, disputed, or
  revoked
- Retain registry mutation logs according to a documented retention policy
- Document how circumvention reports, disputes, and security reports are handled
- Never claim that a watermark, manifest, or C2PA credential proves more than
  it actually verified

Applicable statute
------------------

17 U.S.C. Section 1201 addresses circumvention of technological measures and
trafficking in circumvention tools. It also contains definitions, limitations,
and exceptions. The public text is available at
https://www.law.cornell.edu/uscode/text/17/1201.

PACT deployments should not treat the ``TERMS.md`` template as a substitute for
legal review. The question of whether a particular deployment satisfies the
statute in a particular jurisdiction depends on the work, the rights involved,
the technical implementation, the notice given, and the knowledge of the
party accused of circumvention.
