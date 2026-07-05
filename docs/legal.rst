Legal and Policy Notes
======================

PACT records signed claims and policy metadata. It does not determine who owns
a work, whether a license is valid, whether training occurred, or whether a
particular use is legal. PACT output is provenance and evidence metadata that
can support a review — not a legal conclusion.

PACT has not received formal legal review, a court endorsement, or regulatory
approval. Operators and users should have counsel review the exact workflow,
policy language, and jurisdiction before relying on PACT in a legal proceeding.

What a policy entry means
--------------------------

A PACT policy entry is the claimant's machine-readable instruction or assertion.
An entry that says generative training is not allowed is useful for routing,
logging, and enforcement pipelines — but it is not a court finding, a platform
decision, or a contract.

Applications that display policy results should provide context: who signed the
claim, what content was verified (if any), whether the nonce is public or
private, what registry evidence exists, and whether the claim is disputed,
revoked, or only partially verified. A policy entry without that context does
not give a viewer enough information to draw conclusions.

Manifest removal and copyright management information
------------------------------------------------------

Removing a PACT manifest is not only a technical act. In the United States, the
Digital Millennium Copyright Act contains rules for copyright management
information (CMI). 17 U.S.C. Section 1202 prohibits, among other things,
knowingly removing or altering CMI without authority when the person knows, or
has reasonable grounds to know, that doing so will induce, enable, facilitate,
or conceal infringement. Civil remedies are available under 17 U.S.C.
Section 1203.

- 17 U.S.C. § 1202: https://www.law.cornell.edu/uscode/text/17/1202
- 17 U.S.C. § 1203: https://www.law.cornell.edu/uscode/text/17/1203

A PACT manifest is designed to carry information that can identify a work,
identify a claimant, point to a registry record, and express terms or conditions
for use. That kind of metadata may qualify as CMI. If someone strips the
manifest or locator and then uses the work in a way that violates the manifest's
rights-related terms, the removal may be evidence that they attempted to evade
rights and provenance information.

This does not mean every policy violation is copyright infringement, or that
every removed manifest creates liability. The legal analysis depends on the
work, the rights involved, the user's authority, the policy language, the
subsequent use, and the knowledge required by the statute. The practical point
remains: applications and operators should treat manifest removal as a serious
rights-management signal, especially when followed by conduct the manifest
prohibited.

Technological protection measure notice
---------------------------------------

PACT is documented as a system that can be deployed as a technological
protection measure when operators preserve signed manifests, policy metadata,
watermarks, locators, and registry proofs. The technical specification is in
:doc:`tpm`, and a plain-language notice template is in ``TERMS.md``.

17 U.S.C. Section 1201 addresses circumvention of technological measures and
trafficking in circumvention tools. Operators should not treat the notice
template as a substitute for legal review of the deployment.

C2PA context
------------

PACT supports C2PA because many real files and tools use it for content
credentials. A C2PA credential can help carry metadata through an image, PDF,
or document workflow — but it does not by itself prove authorship, ownership,
originality, or legal permission. Those conclusions require registry evidence,
claimant context, and often human review.

For broader context on C2PA's guarantees and limits:

- https://lowentropy.net/posts/c2pa/
- https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html

These are useful references, not endorsements of every conclusion. They are
reminders that provenance systems require careful threat modeling and honest
language about what was and was not verified.

Private claims and registry disclosure
---------------------------------------

Claimants who do not want the registry to enable public content verification
should sign with a private nonce (omitting the public nonce from the manifest)
and share that nonce only with intended verifiers. The registry stores only
the salted commitment; without the nonce, no one can confirm or deny whether
a given piece of content matches the commitment.

Private content, private nonces, prompts, probe text, provider responses, and
private evidence packages must not be sent to the registry. The privacy audit
(``pact privacy audit``) checks a signed manifest against local material before
publication and reports any fields that should not appear in the manifest.

Operator responsibilities
--------------------------

Registry operators are responsible for local law, data retention policy, abuse
handling, and user-facing terms. A production registry should document, at
minimum:

- Who operates the registry and how to contact them
- What public profile and claim data is retained and for how long
- How disputes, revocations, and takedown requests are handled
- How security issues are reported (see ``SECURITY.md``)
- Whether uploads to inspection endpoints are logged, and for how long
- What rate limits and abuse controls are active
- How registry CA keys, the OPRF server secret, and database backups are
  protected and rotated
